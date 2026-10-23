package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"testing"
)

func TestLateOccurrenceBulkBarrierIsDurableMetadataOnly(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	event := w.event("privacy_barrier_shared_copy")
	original := w.chunk(event)
	header := original
	header.BodyJCS = nil
	w.append(header)
	erase := w.control(1, record.KindErasure, original.AdvisoryID)
	w.append(erase)
	var copies []SignedRecord
	for n := 0; n < 1001; n++ {
		copies = append(copies, w.chunk(event))
	}
	w.seedPending(copies)
	before := w.snapshot()
	var oldSeq, oldBudget, oldBodyRows, oldEvents int
	if w.s.conn.QueryRowContext(ctx, "SELECT next_seq FROM meta").Scan(&oldSeq) != nil {
		t.Fatal("meta")
	}
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect").Scan(&oldBudget)
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_body").Scan(&oldBodyRows)
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM item_event WHERE id=?", original.AdvisoryID).Scan(&oldEvents)
	_, e := w.s.Append(ctx, original)
	var fixed *Error
	if !errors.As(e, &fixed) || fixed.Code != "bulk_confirmation_required" || !fixed.OwnerBlocked {
		t.Fatal("missing committed barrier refusal", e)
	}
	var seq, budget, bodies, events int
	var gen int64
	w.s.conn.QueryRowContext(ctx, "SELECT next_seq,generation FROM meta").Scan(&seq, &gen)
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect").Scan(&budget)
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_body").Scan(&bodies)
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM item_event WHERE id=?", original.AdvisoryID).Scan(&events)
	if seq != oldSeq || budget != oldBudget || bodies != oldBodyRows || events != oldEvents || gen != before.Generation+1 {
		t.Fatal("barrier persisted candidate or partial deletion", seq, budget, bodies, events, gen)
	}
	if _, e = w.s.Snapshot(ctx, ReadRequest{}); Code(e) != "bulk_confirmation_required" {
		t.Fatal("barrier leaked snapshot", e)
	}
	if e = w.s.PublishProjection(ctx, JobToken{copies[0].AdvisoryID, find(before, copies[0].AdvisoryID).Generation}, Projection{Model: "m1", Vector: make([]byte, 256)}); Code(e) != "bulk_confirmation_required" {
		t.Fatal("barrier leaked vector", e)
	}
	if _, e = w.s.Append(ctx, w.task(9000, "newblockedbody")); Code(e) != "bulk_confirmation_required" {
		t.Fatal("barrier admitted ordinary record", e)
	}
	ban, e := w.s.Suppressed(ctx, SourceOccurrence{Owner: w.o.PinnedGenesisID, SessionKey: w.sessionKey()})
	if e != nil || !ban.Suppressed || !ban.OwnerBlocked {
		t.Fatal("barrier allowed capture", ban, e)
	}
	scrub, e := w.s.Scrub(ctx, erase.AdvisoryID)
	if e != nil || scrub.State != "blocked" {
		t.Fatal("barrier falsely scrubbed", scrub, e)
	}
	// Required key authority changes remain possible and cannot clear the barrier.
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{26}, 32))
	add := w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(next.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: w.o.PinnedGenesisID, Parents: []string{w.genesis.AdvisoryID}}, w.key, w.key, next)
	if _, e = w.s.Append(ctx, add); e != nil {
		t.Fatal("barrier blocked key authority", e)
	}
	w.s.Close()
	s, e := Open(ctx, w.o)
	if e != nil {
		t.Fatal(e)
	}
	w.s = s
	if _, e = s.Snapshot(ctx, ReadRequest{}); Code(e) != "bulk_confirmation_required" {
		t.Fatal("restart cleared barrier", e)
	}
	if e = s.Reindex(ctx); Code(e) != "bulk_confirmation_required" {
		t.Fatal("reindex cleared barrier", e)
	}

}
func TestNewOversizedControlRefusesWithoutPrivacyBarrier(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	var inputs []SignedRecord
	var ids []string
	for n := 1; n <= 1001; n++ {
		r := w.task(n, "live bulk input")
		inputs = append(inputs, r)
		ids = append(ids, r.AdvisoryID)
	}
	w.seedPending(inputs)
	before := w.snapshot()
	control := w.control(1, record.KindErasure, ids...)
	if _, e := w.s.Append(ctx, control); Code(e) != "bulk_confirmation_required" {
		t.Fatal("oversized control accepted", e)
	}
	after := w.snapshot()
	if len(after.Entries) != len(before.Entries) || after.Generation != before.Generation {
		t.Fatal("new refused control mutated state")
	}
	var n int
	if w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&n) != nil || n != 0 {
		t.Fatal("unaccepted control caused owner barrier")
	}
}
