package store

import (
	"bytes"
	"context"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
	"os"
	"sync"
	"testing"
)

// seedPending creates a large signed real-SQLite fixture in one transaction.
// The candidate exercised below still goes through the public admission API.
func (w *world) seedPending(inputs []SignedRecord) {
	w.t.Helper()
	ctx := context.Background()
	err := w.s.write(ctx, func() error {
		d, e := w.s.load(ctx)
		if e != nil {
			return e
		}
		var added []*stored
		for _, in := range inputs {
			r, signatures, e := parse(in)
			if e != nil {
				return e
			}
			res := sig.VerifyRecord(r, signatures, d.kr.State(), sig.Context{Route: record.RouteLocal})
			if res.Status != sig.StatusVerified {
				return failure("invalid_fixture")
			}
			x := &stored{rec: r, sigs: signatures, owner: w.o.PinnedGenesisID, seq: d.nextSeq, generation: d.generation + 1}
			material(x)
			d.nextSeq++
			d.records = append(d.records, x)
			d.byID[r.ID] = x
			added = append(added, x)
		}
		if e = d.rebuild(w.o); e != nil {
			return e
		}
		delta, e := w.s.effectDelta(ctx, d)
		if e != nil {
			return e
		}
		if len(delta) != 0 {
			return failure("invalid_fixture")
		}
		for _, x := range added {
			if e = w.s.insertRecord(ctx, x); e != nil {
				return e
			}
		}
		d.generation++
		if _, e = w.s.conn.ExecContext(ctx, "UPDATE meta SET next_seq=?,generation=? WHERE singleton=1", d.nextSeq, d.generation); e != nil {
			return failure("storage_error")
		}
		return w.s.persistState(ctx, d)
	})
	if err != nil {
		w.t.Fatal(err)
	}
}
func TestLateBulkClosureRefusesBeforeAnyCandidateWrite(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	x := record.H("absent-X")
	y := w.task(10000, "late_budget_candidate_canary_72f4d", x)
	w.append(w.control(1, record.KindErasure, x))
	var inputs []SignedRecord
	for n := 0; n < 1500; n++ {
		inputs = append(inputs, w.task(n+1, "pending", y.AdvisoryID))
	}
	w.seedPending(inputs)
	before := w.snapshot()
	var effects int
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect").Scan(&effects)
	if effects != 0 {
		t.Fatal("absent fence charged")
	}
	_, err := w.s.Append(ctx, y)
	if Code(err) != "bulk_confirmation_required" {
		t.Fatal("late bulk accepted", err)
	}
	after := w.snapshot()
	if after.Generation != before.Generation || len(after.Entries) != len(before.Entries) {
		t.Fatal("partial mutation")
	}
	for _, e := range after.Entries {
		if e.ID == y.AdvisoryID {
			t.Fatal("refused header persisted")
		}
		if e.State == "ancestry-pending" && len(e.BodyJCS) != 0 {
			t.Fatal("pending body exposed")
		}
	}
	for _, suffix := range []string{"", "-wal"} {
		b, e := os.ReadFile(w.s.path + suffix)
		if e == nil && bytes.Contains(b, []byte("late_budget_candidate_canary_72f4d")) {
			t.Fatal("refused candidate bytes reached disk")
		}
	}
	w.s.Close()
	s, e := Open(ctx, w.o)
	if e != nil {
		t.Fatal(e)
	}
	w.s = s
	if len(w.snapshot().Entries) != len(before.Entries) {
		t.Fatal("restart changed budget state")
	}
	if _, e = s.Append(ctx, y); Code(e) != "bulk_confirmation_required" {
		t.Fatal("restart reset guard", e)
	}
}
func TestLifetimeBudgetConcurrentWritersAndDuplicateNoRefund(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	var inputs []SignedRecord
	var ids []string
	for n := 1; n <= 1001; n++ {
		r := w.task(n, "bulk-fixture")
		inputs = append(inputs, r)
		ids = append(ids, r.AdvisoryID)
	}
	w.seedPending(inputs)
	c := w.control(1, record.KindErasure, ids[:999]...)
	first := w.append(c)
	dup := w.append(c)
	if !dup.Duplicate || dup.Sequence != first.Sequence {
		t.Fatal("control dedup")
	}
	other, e := Open(ctx, w.o)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	cs := []SignedRecord{w.control(2, record.KindErasure, ids[999]), w.control(3, record.KindErasure, ids[1000])}
	stores := []*Store{w.s, other}
	var wg sync.WaitGroup
	codes := make([]string, 2)
	for i := range stores {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _, e := stores[i].Append(ctx, cs[i]); codes[i] = Code(e) }(i)
	}
	wg.Wait()
	if !((codes[0] == "" && codes[1] == "bulk_confirmation_required") || (codes[1] == "" && codes[0] == "bulk_confirmation_required")) {
		t.Fatal("near-limit serialization", codes)
	}
	var n int
	if w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect").Scan(&n) != nil || n != 1000 {
		t.Fatal("incorrect durable budget", n)
	}
	if e = w.s.Reindex(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = w.s.Append(ctx, w.control(4, record.KindErasure, ids[0])); Code(e) != "bulk_confirmation_required" {
		t.Fatal("distinct control or reindex refunded", e)
	}
}
