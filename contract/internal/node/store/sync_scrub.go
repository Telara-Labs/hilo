package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"

	qk "github.com/Telara-Labs/telara-memory/contract/internal/node/quarantinekeys"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// scrubSyncCopies runs with the main writer held. Acquisition of the sibling
// writer is nonblocking, so a sync transaction waiting for the main writer
// cannot deadlock it. Busy means pending, never clean. The sidecar commit and
// its checkpoint precede the main scrub receipt. A crash at any point retries
// from the durable signed controls and tombs, without relying on a live worker.
func (s *Store) scrubSyncCopies(ctx context.Context, d *databaseState) (bool, error) {
	path := filepath.Join(s.opts.Dir, SyncDatabaseName)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return true, nil
	} else if err != nil {
		return false, failure("storage_error")
	}
	if err := privateFile(path); err != nil {
		return false, err
	}
	if err := securePathFiles(path); err != nil {
		return false, err
	}
	db, err := sql.Open("sqlite", SQLiteURI(path, "mode=rw"))
	if err != nil {
		return false, failure("storage_error")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return false, failure("storage_error")
	}
	defer conn.Close()
	for _, stmt := range []string{"PRAGMA busy_timeout=0", "PRAGMA secure_delete=ON", "PRAGMA temp_store=MEMORY"} {
		if _, err = conn.ExecContext(ctx, stmt); err != nil {
			return false, failure("storage_error")
		}
	}
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return false, nil
	}
	committed := false
	defer func() {
		if !committed {
			conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		}
	}()
	// An unrelated partial/unknown sidecar is never accepted as proof of scrub.
	var tables int
	if err = conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('outbox','operation','data_quarantine')").Scan(&tables); err != nil || tables != 3 {
		return false, failure("incompatible_database")
	}
	if _, err = conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS quarantine_fence(kind TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(kind,value)); CREATE TABLE IF NOT EXISTS quarantine_scrub(destination TEXT PRIMARY KEY);`); err != nil {
		return false, failure("storage_error")
	}
	fences := map[qk.Key]bool{}
	add := func(kind, value string) {
		if kind == qk.ID && !record.IsHex64(value) {
			return
		}
		if value != "" {
			fences[qk.Key{Kind: kind, Value: value}] = true
		}
	}
	for id, causes := range d.eval.Causes {
		if len(causes) > 0 {
			add(qk.ID, id)
		}
	}
	for id, causes := range d.eval.HoldCauses {
		if len(causes) > 0 {
			add(qk.ID, id)
		}
	}
	// A selector remains a fence even if its matching record never arrived.
	for _, x := range d.records {
		if x.sigStatus != sig.StatusVerified {
			continue
		}
		if b, ok := x.rec.Body.(*record.ErasureBody); ok {
			for _, v := range b.Selectors.IDs {
				add(qk.ID, v)
			}
			for _, v := range b.Selectors.LIDs {
				add(qk.LID, v)
			}
			for _, v := range b.Selectors.Sessions {
				add(qk.Session, v)
			}
			for _, v := range b.Selectors.Sources {
				add(qk.Source, v)
			}
			for _, v := range b.Selectors.Tasks {
				add(qk.Task, v.TaskID)
			}
			for _, v := range b.Selectors.Events {
				add(qk.Event, v.EventID)
			}
		}
	}
	rows, err := conn.QueryContext(ctx, "SELECT kind,value FROM quarantine_fence")
	if err != nil {
		return false, failure("storage_error")
	}
	for rows.Next() {
		var k qk.Key
		if rows.Scan(&k.Kind, &k.Value) != nil {
			rows.Close()
			return false, failure("storage_error")
		}
		fences[k] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, failure("storage_error")
	}
	type copyRow struct {
		dest           string
		hseq           int64
		id, source, op string
		keys           qk.Keys
		valid, drop    bool
	}
	var copies []copyRow
	rows, err = conn.QueryContext(ctx, "SELECT destination,hseq,envelope FROM data_quarantine")
	if err != nil {
		return false, failure("storage_error")
	}
	for rows.Next() {
		var c copyRow
		var raw []byte
		var env record.Envelope
		if rows.Scan(&c.dest, &c.hseq, &raw) != nil {
			rows.Close()
			return false, failure("storage_error")
		}
		if json.Unmarshal(raw, &env) == nil {
			c.keys, c.valid = qk.Parse(env)
		}
		c.id = env.ID
		copies = append(copies, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, failure("storage_error")
	}
	rows, err = conn.QueryContext(ctx, "SELECT destination,record_id,source_id,op_id,header,body,sigs FROM outbox WHERE header IS NOT NULL OR body IS NOT NULL OR sigs IS NOT NULL")
	if err != nil {
		return false, failure("storage_error")
	}
	for rows.Next() {
		var c copyRow
		var header, body, raw []byte
		var sigs []record.Signature
		if rows.Scan(&c.dest, &c.id, &c.source, &c.op, &header, &body, &raw) != nil {
			rows.Close()
			return false, failure("storage_error")
		}
		if json.Unmarshal(raw, &sigs) == nil {
			c.keys, c.valid = qk.Parse(nodesync.Envelope(header, body, sigs, c.id))
		}
		copies = append(copies, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, failure("storage_error")
	}
	for changed := true; changed; {
		changed = false
		for i := range copies {
			c := &copies[i]
			if c.drop {
				continue
			}
			drop := !c.valid || fences[qk.Key{Kind: qk.ID, Value: c.source}]
			for _, k := range c.keys.Own {
				drop = drop || fences[k]
			}
			for _, id := range c.keys.Deps {
				drop = drop || fences[qk.Key{Kind: qk.ID, Value: id}]
			}
			for _, id := range c.keys.Recalled {
				if fences[qk.Key{Kind: qk.ID, Value: id}] {
					drop = true
					add(qk.Session, c.keys.Session)
				}
			}
			if drop {
				c.drop = true
				add(qk.ID, c.id)
				changed = true
			}
		}
	}
	for k := range fences {
		if _, err = conn.ExecContext(ctx, "INSERT OR IGNORE INTO quarantine_fence VALUES(?,?)", k.Kind, k.Value); err != nil {
			return false, failure("storage_error")
		}
	}
	for _, c := range copies {
		if !c.drop {
			continue
		}
		if c.op != "" {
			// An operation is an immutable signed request. Cancel the whole request;
			// unaffected siblings can be freshly exported on the next round.
			if _, err = conn.ExecContext(ctx, "UPDATE operation SET state='cancelled',reason='erasure',raw=x'' WHERE op_id=?", c.op); err != nil {
				return false, failure("storage_error")
			}
			if _, err = conn.ExecContext(ctx, "UPDATE outbox SET state='cancelled',header=NULL,body=NULL,sigs=NULL WHERE op_id=?", c.op); err != nil {
				return false, failure("storage_error")
			}
		} else {
			if _, err = conn.ExecContext(ctx, "DELETE FROM data_quarantine WHERE destination=? AND hseq=?", c.dest, c.hseq); err != nil {
				return false, failure("storage_error")
			}
		}
		if _, err = conn.ExecContext(ctx, "INSERT OR IGNORE INTO quarantine_scrub VALUES(?)", c.dest); err != nil {
			return false, failure("storage_error")
		}
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return false, failure("storage_error")
	}
	committed = true
	var busy, log, done int
	if err = conn.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done); err != nil {
		return false, failure("storage_error")
	}
	if busy != 0 || log != 0 || done != 0 {
		return false, nil
	}
	// Keep markers; they contain no payload and the worker also checkpoints
	// before its next ACK. The durable main job alone determines this receipt.
	return true, nil
}
