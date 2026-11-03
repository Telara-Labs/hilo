package store

import (
	"bytes"
	"context"
	"database/sql"
	"github.com/Telara-Labs/hilo/contract/record"
	"os"
	"testing"
)

func TestPhysicalScrubActualBytesAndBusyReader(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	token := "erasure_canary_8cd94f620acc713e"
	a := seedFreshCheckpoint(w, token)
	reader, e := sql.Open("sqlite", w.s.path)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	reader.SetMaxOpenConns(1)
	tx, e := reader.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	var text string
	if e = tx.QueryRowContext(ctx, "SELECT text FROM passage WHERE id=?", a.AdvisoryID).Scan(&text); e != nil || !bytes.Contains([]byte(text), []byte(token)) {
		t.Fatal("reader fixture", e)
	}
	erase := w.control(1, record.KindErasure, a.AdvisoryID)
	w.append(erase)
	pending, e := w.s.Scrub(ctx, erase.AdvisoryID)
	if e != nil || pending.State != "pending" {
		t.Fatal("busy reader reported clean", pending, e)
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	w.s.Close()
	s, e := Open(ctx, w.o)
	if e != nil {
		t.Fatal(e)
	}
	w.s = s
	var state string
	if e = s.conn.QueryRowContext(ctx, "SELECT state FROM scrub_job WHERE control=?", erase.AdvisoryID).Scan(&state); e != nil || state != "pending" {
		t.Fatal("scrub job lost after restart", state, e)
	}
	done, e := s.Scrub(ctx, erase.AdvisoryID)
	if e != nil || done.State != "complete" {
		t.Fatal("scrub not complete", done, e)
	}
	var count int
	if e = s.conn.QueryRowContext(ctx, "SELECT count(*) FROM search WHERE search MATCH ?", token).Scan(&count); e != nil || count != 0 {
		t.Fatal("fts still contains erased text", count, e)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, e := os.ReadFile(s.path + suffix)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(b, []byte(token)) {
			t.Fatal("erased canary remains", suffix)
		}
	}
}
