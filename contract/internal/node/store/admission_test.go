package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"testing"
)

type world struct {
	t       *testing.T
	s       *Store
	o       Options
	key     ed25519.PrivateKey
	genesis SignedRecord
	at      int64
}

func newWorld(t *testing.T) *world {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	o := testOptions(t)
	o.PinnedGenesisID = sig.KeyID(key.Public().(ed25519.PublicKey))
	s, e := Open(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	w := &world{t: t, s: s, o: o, key: key, at: 1761150000000}
	op, e := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(key.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: o.PinnedGenesisID}, key.Public().(ed25519.PublicKey), testMachine, w.at, key)
	if e != nil {
		t.Fatal(e)
	}
	w.genesis = wire(op.Rec, op.Sigs)
	w.append(w.genesis)
	t.Cleanup(func() { w.s.Close() })
	return w
}
func wire(r *record.Record, signatures []record.Signature) SignedRecord {
	return SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: signatures, AdvisoryID: r.ID}
}
func (w *world) signed(h record.Header, b any) SignedRecord {
	w.t.Helper()
	w.at++
	h.Author = record.Author{MachineID: testMachine, KeyID: sig.KeyID(w.key.Public().(ed25519.PublicKey))}
	h.At = w.at
	h.Red = record.Redact{Profile: record.ProfileLocal}
	r, e := record.Build(h, b, bytes.Repeat([]byte{7}, 32))
	if e != nil {
		w.t.Fatal(e)
	}
	sg, e := sig.SignRecord(w.key, r.ID)
	if e != nil {
		w.t.Fatal(e)
	}
	return wire(r, []record.Signature{sg})
}
func (w *world) task(n int, text string, deps ...string) SignedRecord {
	task := fmt.Sprintf("22222222-2222-4222-8222-%012x", n)
	return w.signed(record.Header{Type: record.KindTask, LID: record.TaskLID(w.o.PinnedGenesisID, task), Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: record.H("op", fmt.Sprint(n)), Links: record.Links{DerivedFrom: deps}}, &record.TaskBody{Name: "task", Goal: text, Status: "active"})
}
func (w *world) control(n int, k record.Kind, ids ...string) SignedRecord {
	h := record.Header{Type: k, Prov: record.ProvUser}
	h.LID, _ = record.ControlLID(k, sig.KeyID(w.key.Public().(ed25519.PublicKey)), record.H("nonce", fmt.Sprint(n))[:32])
	if k == record.KindErasure {
		return w.signed(h, &record.ErasureBody{Selectors: record.Selectors{IDs: ids}, Reason: "user_request"})
	}
	return w.signed(h, &record.RetractionBody{IDs: ids, Reason: "redaction_repair"})
}
func (w *world) append(r SignedRecord) AdmissionResult {
	w.t.Helper()
	a, e := w.s.Append(context.Background(), r)
	if e != nil {
		w.t.Fatal(e)
	}
	return a
}
func (w *world) snapshot() Snapshot {
	w.t.Helper()
	v, e := w.s.Snapshot(context.Background(), ReadRequest{})
	if e != nil {
		w.t.Fatal(e)
	}
	return v
}
func find(v Snapshot, id string) Entry {
	for _, x := range v.Entries {
		if x.ID == id {
			return x
		}
	}
	return Entry{}
}
func TestAdmissionDurableDuplicatePendingAndFTS(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	parent := w.task(1, "uniquezebraparent")
	child := w.task(2, "uniquezebrachild", parent.AdvisoryID)
	a := w.append(child)
	v := find(w.snapshot(), a.ID)
	if v.State != "ancestry-pending" || len(v.BodyJCS) != 0 {
		t.Fatal("pending body exposed", v.State)
	}
	var n int
	if w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM search WHERE search MATCH 'uniquezebrachild'").Scan(&n) != nil || n != 0 {
		t.Fatal("pending searchable")
	}
	w.append(parent)
	v = find(w.snapshot(), a.ID)
	if v.State != "live" || len(v.BodyJCS) == 0 || v.TaskStatus != "active" {
		t.Fatal("dependency not resolved", v)
	}
	duplicate := w.append(child)
	if !duplicate.Duplicate || duplicate.Sequence != a.Sequence {
		t.Fatal("duplicate sequence changed")
	}
	if w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM search WHERE search MATCH 'uniquezebrachild'").Scan(&n) != nil || n != 0 {
		t.Fatal("ordinary Append minted positive completeness")
	}
	w.s.Close()
	s, e := Open(ctx, w.o)
	if e != nil {
		t.Fatal(e)
	}
	w.s = s
	after := w.snapshot()
	if len(after.Entries) != 3 || find(after, a.ID).State != "live" {
		t.Fatal("restart lost truth")
	}
	if e = w.s.Reindex(ctx); e != nil {
		t.Fatal(e)
	}
	if find(w.snapshot(), a.ID).Sequence != a.Sequence {
		t.Fatal("reindex erased admission")
	}
}
func TestControlClosureLateArrivalAndWorkerFence(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	a := w.task(1, "oneuniquebody")
	b := w.task(2, "twouniquebody", a.AdvisoryID)
	c := w.task(3, "threeuniquebody", b.AdvisoryID)
	cb := w.append(c)
	bb := w.append(b)
	erase := w.control(1, record.KindErasure, a.AdvisoryID)
	w.append(erase)
	for _, id := range []string{b.AdvisoryID, c.AdvisoryID} {
		e := find(w.snapshot(), id)
		if e.State != "invalidated" || len(e.BodyJCS) != 0 {
			t.Fatal("late closure incomplete", e)
		}
	}
	w.append(a)
	if len(find(w.snapshot(), a.AdvisoryID).BodyJCS) != 0 {
		t.Fatal("late tombed body stored")
	}
	for _, tok := range []JobToken{{b.AdvisoryID, bb.Generation}, {c.AdvisoryID, cb.Generation}} {
		if Code(w.s.PublishProjection(ctx, tok, Projection{Model: "m1", Vector: make([]byte, 256)})) != "stale_projection" {
			t.Fatal("worker resurrected erased row")
		}
	}
	var n int
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_body b JOIN record r ON r.id=b.id WHERE r.state='invalidated'").Scan(&n)
	if n != 0 {
		t.Fatal("invalidated bodies remain")
	}
	w.append(erase)
	w.s.Close()
	s, e := Open(ctx, w.o)
	if e != nil {
		t.Fatal(e)
	}
	w.s = s
	if len(find(w.snapshot(), a.AdvisoryID).BodyJCS) != 0 {
		t.Fatal("restart resurrected")
	}
}
