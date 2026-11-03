package syncnode

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Telara-Labs/hilo/contract/internal/node/store"
)

// Sidecar states reported by InspectStatus.
const (
	SidecarAbsent  = "absent"  // no sync database exists
	SidecarPresent = "present" // the sync database was read
)

// InspectStatus reports what Status reports without writing anything. It
// never creates the sync database or its -wal and -shm files, applies its
// schema, inserts a cursor row, takes a write lock or checkpoints. A missing database, or tables a writer
// has not created yet, read as the empty state a writer would start from.
// The second result names the sidecar state.
func InspectStatus(ctx context.Context, dir string) (StatusReport, string, error) {
	out := StatusReport{Rules: []Rule{}, Outbox: map[string]int64{}}
	p, err := LoadProfile(dir)
	if Disabled(err) {
		return out, SidecarAbsent, nil
	}
	if err != nil {
		return out, "", err
	}
	out.Configured, out.Enabled, out.Enrolled = true, p.Enabled, p.Enrolled()
	if raw, err := store.ReadSyncProfile(dir); err == nil {
		var retired struct {
			Retired []string `json:"retired"`
		}
		if json.Unmarshal(raw, &retired) == nil && len(retired.Retired) > 0 {
			out.CredentialCleanup = "pending"
		}
		clear(raw)
	}
	path := filepath.Join(dir, store.SyncDatabaseName)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if p.Enrolled() {
			out.Origin, out.Tenant, out.User, out.Config = p.Origin, p.Tenant, p.User, p.Config
			out.Repos, out.GrantExpiresAt = append([]string(nil), p.Grant.Repos...), p.Grant.ExpiresAtUnix
		}
		return out, SidecarAbsent, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return out, "", errStateInvalid
	}
	// A read-only connection to a WAL database still creates the -wal and
	// -shm files when they are absent. Without a WAL there is no live writer
	// state outside the main file, so it is read as immutable and nothing is
	// created. With both present a writer's index already exists and is only
	// read. A WAL without its index cannot be read without creating one.
	query := "mode=ro"
	_, walErr := os.Lstat(path + "-wal")
	_, shmErr := os.Lstat(path + "-shm")
	switch {
	case os.IsNotExist(walErr) && os.IsNotExist(shmErr):
		query = "mode=ro&immutable=1"
	case walErr != nil || shmErr != nil:
		return out, "", errStateInvalid
	}
	db, err := sql.Open("sqlite", store.SQLiteURI(path, query))
	if err != nil {
		return out, "", errStateInvalid
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	c, err := db.Conn(ctx)
	if err != nil {
		return out, "", errStateInvalid
	}
	defer c.Close()
	if _, err = c.ExecContext(ctx, "PRAGMA query_only=1"); err != nil {
		return out, "", errStateInvalid
	}
	// One read transaction gives a consistent snapshot.
	if _, err = c.ExecContext(ctx, "BEGIN"); err != nil {
		return out, "", errStateInvalid
	}
	defer c.ExecContext(context.Background(), "ROLLBACK")
	present := map[string]bool{}
	rows, err := c.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return out, "", errStateInvalid
	}
	for rows.Next() {
		var name string
		if rows.Scan(&name) != nil {
			rows.Close()
			return out, "", errStateInvalid
		}
		present[name] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, "", errStateInvalid
	}
	if present["selection_rule"] {
		if out.Rules, err = readRules(ctx, c); err != nil {
			return out, "", err
		}
	}
	if !p.Enrolled() {
		return out, SidecarPresent, nil
	}
	out.Origin, out.Tenant, out.User, out.Config = p.Origin, p.Tenant, p.User, p.Config
	out.Repos, out.GrantExpiresAt = append([]string(nil), p.Grant.Repos...), p.Grant.ExpiresAtUnix
	dest := destination(p.Scope())
	if present["sync_state"] {
		err = c.QueryRowContext(ctx, "SELECT ctl_cursor,data_cursor,acked_ctl,acked_data,barrier_hseq,barrier_reason,last_error,last_round FROM sync_state WHERE destination=?", dest).Scan(&out.CtlCursor, &out.DataCursor, &out.AckedCtl, &out.AckedData, &out.BarrierHSeq, &out.BarrierReason, &out.LastError, &out.LastRound)
		if err != nil && err != sql.ErrNoRows {
			return out, "", errStateInvalid
		}
	}
	if present["outbox"] {
		rows, err := c.QueryContext(ctx, "SELECT state,count(*) FROM outbox WHERE destination=? GROUP BY state", dest)
		if err != nil {
			return out, "", errStateInvalid
		}
		for rows.Next() {
			var state string
			var n int64
			if rows.Scan(&state, &n) != nil {
				rows.Close()
				return out, "", errStateInvalid
			}
			out.Outbox[state] = n
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, "", errStateInvalid
		}
	}
	for table, dst := range map[string]*int64{"delivery_receipt": &out.Receipts, "data_quarantine": &out.Quarantined} {
		if present[table] && c.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE destination=?", dest).Scan(dst) != nil {
			return out, "", errStateInvalid
		}
	}
	return out, SidecarPresent, nil
}
