package syncnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// foreignDerived is another device's chunk holding text that declares it
// copies content from deps, as hosted would relay it as data.
func foreignDerived(t *testing.T, sk, text, anchor string, at int64, deps ...string) (record.Envelope, string) {
	t.Helper()
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{78}, 32))
	pub := other.Public().(ed25519.PublicKey)
	machine := "99999999-9999-4999-8999-999999999999"
	id, err := record.EventID(sk, "assistant_final", record.Anchor{NativeItemID: anchor})
	if err != nil {
		t.Fatal(err)
	}
	e := record.Event{ID: id, Seq: 1, Kind: "assistant_final", Prov: "transcript", Text: &record.Text{Body: text}}
	h := record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.ChunkLID(sk, machine, id), At: at, Author: record.Author{MachineID: machine, KeyID: sig.KeyID(pub)}, Red: record.Redact{Profile: record.ProfileLocal}, Links: record.Links{DerivedFrom: deps}}
	r, err := record.Build(h, &record.ChunkBody{Events: []record.Event{e}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := sig.SignRecord(other, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return envelopeOf(r, []record.Signature{s}), r.ID
}

// ackWatch fails any ACK covering hc while canary is still on disk.
func ackWatch(t *testing.T, w *world, canary string) (set func(int64), failures func() []string) {
	var mu sync.Mutex
	var hc int64
	var out []string
	w.hosted.mu.Lock()
	w.hosted.onAck = func(_ string, ack transport.Ack) {
		mu.Lock()
		defer mu.Unlock()
		if hc == 0 || ack.CtlEnforcedThrough < hc {
			return
		}
		if err := canaryIn(w.dir, canary); err != nil {
			out = append(out, fmt.Sprintf("ack %d covers the erasure while %v", ack.CtlEnforcedThrough, err))
		}
	}
	w.hosted.mu.Unlock()
	return func(v int64) {
			mu.Lock()
			hc = v
			mu.Unlock()
		}, func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), out...)
		}
}

// A quarantined hosted chunk Q declares in links.derived_from that it copies
// local record R. An erasure naming only R's id invalidates Q too: Q is a
// managed copy of erased content, so the enforced ACK may cover the erasure
// only once Q's body is gone from every file. Q's own id then becomes a fence,
// so a later descendant of Q is never stored either.
func TestIDOnlyErasurePurgesQuarantinedDerivative(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	p := w.enroll()
	wk := w.worker()
	sk := x2SessionKey(t)
	root := w.task(1, repoA, "active")

	const canary = "quarantined_derivative_canary_6f2a"
	q, qid := foreignDerived(t, sk, canary, "derived-q", w.at, root.ID)
	planted := q.Body.Bytes
	w.hosted.addData(q)
	if err := wk.Round(ctx); err != nil {
		t.Fatal("quarantine round", err)
	}
	if n := count(t, wk, "SELECT count(*) FROM data_quarantine"); n != 1 {
		t.Fatalf("derivative not quarantined: %d", n)
	}
	if canaryIn(w.dir, planted) == nil {
		t.Fatal("fixture did not plant the quarantined copy")
	}
	set, failures := ackWatch(t, w, planted)
	hc := w.hosted.addControl(w.control(2, record.KindErasure, root.ID))
	set(hc)
	if err := wk.Round(ctx); err != nil {
		t.Fatal("erasure round", err)
	}
	if f := failures(); len(f) > 0 {
		t.Fatal(f)
	}
	if c := cursorsOf(t, wk, p); c.Ctl != hc {
		t.Fatalf("erasure not enforced: %+v", c)
	}
	if n := count(t, wk, "SELECT count(*) FROM data_quarantine"); n != 0 {
		t.Fatalf("quarantined derivative of an erased record kept: %d", n)
	}
	if n := count(t, wk, "SELECT count(*) FROM quarantine_fence WHERE kind='id' AND value=?", qid); n != 1 {
		t.Fatal("dropped derivative is not a fence for its own descendants")
	}
	assertNoCanary(t, w.dir, planted)

	// A later descendant of Q, never seen before, is dropped on arrival.
	const later = "descendant_of_dropped_canary_0b83"
	d, _ := foreignDerived(t, sk, later, "derived-d", w.at, qid)
	dh := w.hosted.addData(d)
	if err := wk.Round(ctx); err != nil {
		t.Fatal("descendant round", err)
	}
	if c := cursorsOf(t, wk, p); c.Data != dh {
		t.Fatalf("data cursor %+v, want %d", c, dh)
	}
	if n := count(t, wk, "SELECT count(*) FROM data_quarantine"); n != 0 {
		t.Fatalf("descendant of a dropped derivative stored: %d", n)
	}
	assertNoCanary(t, w.dir, d.Body.Bytes)
}

// An erasure is enforced in ENFORCE, and the same round's PULL(data) then
// delivers the erased envelope: hosted relays it late, or a stale or replayed
// page carries it. Nothing may be stored after cleanup that the ACK's claim
// covers, so PULL(data) consults the durable fences before storing anything,
// and the ACK that covers the erasure finds the bytes nowhere on disk. A later
// replay of the same envelope is refused the same way.
func TestErasedEnvelopeArrivingAfterEnforceIsNeverStored(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	p := w.enroll()
	wk := w.worker()
	sk := x2SessionKey(t)

	const canary = "late_erased_envelope_canary_a51c"
	f, fid := foreignChunk(t, sk, canary, w.at)
	planted := f.Body.Bytes
	set, failures := ackWatch(t, w, planted)
	hc := w.hosted.addControl(w.control(1, record.KindErasure, fid))
	set(hc)
	dh := w.hosted.addData(f)
	if err := wk.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if fl := failures(); len(fl) > 0 {
		t.Fatal(fl)
	}
	c := cursorsOf(t, wk, p)
	if c.Ctl != hc || c.Data != dh {
		t.Fatalf("cursors %+v, want ctl=%d data=%d", c, hc, dh)
	}
	if n := count(t, wk, "SELECT count(*) FROM data_quarantine"); n != 0 {
		t.Fatalf("erased envelope stored after enforcement: %d", n)
	}
	assertNoCanary(t, w.dir, planted)

	// Replayed at a later hseq, the envelope is refused again, after restart.
	_ = wk.state.Close()
	wk = w.worker()
	rh := w.hosted.addData(f)
	if err := wk.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if c := cursorsOf(t, wk, p); c.Data != rh {
		t.Fatalf("replay cursor %+v, want %d", c, rh)
	}
	if n := count(t, wk, "SELECT count(*) FROM data_quarantine"); n != 0 {
		t.Fatalf("replayed erased envelope stored: %d", n)
	}
	if fl := failures(); len(fl) > 0 {
		t.Fatal(fl)
	}
	assertNoCanary(t, w.dir, planted)
}
