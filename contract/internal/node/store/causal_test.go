package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/view"
	"os"
	"testing"
)

func (w *world) op(b record.KeyOpBody, author ed25519.PrivateKey, signers ...ed25519.PrivateKey) SignedRecord {
	w.t.Helper()
	w.at++
	op, e := sig.BuildKeyOp(b, author.Public().(ed25519.PublicKey), testMachine, w.at, signers...)
	if e != nil {
		w.t.Fatal(e)
	}
	return wire(op.Rec, op.Sigs)
}
func (w *world) sessionKey() string {
	k, e := record.SessionKey("claude-code", "local", record.NativeGlobal, "22222222-2222-4222-8222-222222222222", "")
	if e != nil {
		w.t.Fatal(e)
	}
	return k
}
func (w *world) event(text string, parents ...string) record.Event {
	sk := w.sessionKey()
	id, e := record.EventID(sk, "assistant_final", record.Anchor{NativeItemID: "event-one"})
	if e != nil {
		w.t.Fatal(e)
	}
	ev, e := record.ReviseEvent(record.Event{ID: id, Seq: 0, Kind: "assistant_final", Prov: "transcript", Text: &record.Text{Body: text}}, parents, bytes.Repeat([]byte{7}, 32))
	if e != nil {
		w.t.Fatal(e)
	}
	return ev
}
func (w *world) chunk(e record.Event) SignedRecord {
	sk := w.sessionKey()
	return w.signed(record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.ChunkLID(sk, testMachine, e.ID)}, &record.ChunkBody{Events: []record.Event{e}})
}
func (w *world) session(chunks []string, supersedes ...string) SignedRecord {
	sk := w.sessionKey()
	return w.signed(record.Header{Type: record.KindSession, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.SessionLID(sk, testMachine, 0), Links: record.Links{Supersedes: supersedes}}, &record.SessionBody{NativeID: "22222222-2222-4222-8222-222222222222", NativeIDKind: record.NativeGlobal, MachineOS: "darwin", Chunks: chunks, SettledThrough: 0})
}
func (w *world) sessionView() *view.Session {
	w.t.Helper()
	var result *view.Session
	e := w.s.write(context.Background(), func() error {
		d, e := w.s.load(context.Background())
		if e != nil {
			return e
		}
		f := d.facts[w.sessionKey()]
		if f.V == 0 {
			f.V = 2
		}
		result, e = view.SessionView(d.observed(), nil, nil, w.sessionKey(), f)
		return e
	})
	if e != nil {
		w.t.Fatal(e)
	}
	return result
}
func TestProtectedFactsRestartRetractionAndOccurrenceBan(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	a1 := w.event("oldprotectedtext")
	a2 := w.event("oldprotectedtext")
	if a1.Revision == a2.Revision {
		t.Fatal("fixture salt reused")
	}
	c1, c2 := w.chunk(a1), w.chunk(a2)
	w.append(c1)
	w.append(c2)
	s1 := w.session([]string{c1.AdvisoryID, c2.AdvisoryID})
	w.append(s1)
	if !w.sessionView().CoverageAt(0) {
		t.Fatal("equal captures not covered")
	}
	var n int
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM witness").Scan(&n)
	if n == 0 {
		t.Fatal("equality not persisted")
	}
	b := w.event("newprotectedtext", a1.Revision)
	cb := w.chunk(b)
	w.append(cb)
	s2 := w.session([]string{cb.AdvisoryID}, s1.AdvisoryID)
	w.append(s2)
	w.append(w.control(1, record.KindRetraction, c1.AdvisoryID))
	if !w.sessionView().CoverageAt(0) {
		t.Fatal("known erased predecessor unresolved")
	}
	w.s.Close()
	s, e := Open(ctx, w.o)
	if e != nil {
		t.Fatal(e)
	}
	w.s = s
	if !w.sessionView().CoverageAt(0) {
		t.Fatal("restart lost causal witnesses")
	}
	if e = s.Reindex(ctx); e != nil {
		t.Fatal(e)
	}
	if !w.sessionView().CoverageAt(0) {
		t.Fatal("reindex lost causal witnesses")
	}
	erasure := w.control(2, record.KindErasure, cb.AdvisoryID)
	w.append(erasure)
	for _, id := range []string{c1.AdvisoryID, c2.AdvisoryID, cb.AdvisoryID} {
		if x := find(w.snapshot(), id); len(x.BodyJCS) != 0 || x.State != "invalidated" {
			t.Fatal("capture escaped occurrence erase")
		}
	}
	ban, e := s.Suppressed(ctx, SourceOccurrence{Owner: w.o.PinnedGenesisID, SessionKey: w.sessionKey(), EventIDs: []string{a1.ID}})
	if e != nil || !ban.Suppressed {
		t.Fatal("recapture not suppressed", e)
	}
	fresh := w.chunk(w.event("oldprotectedtext"))
	w.append(fresh)
	if len(find(w.snapshot(), fresh.AdvisoryID).BodyJCS) != 0 {
		t.Fatal("new capture resurrected")
	}
	done, err := s.Scrub(ctx, erasure.AdvisoryID)
	if err != nil || done.State != "complete" {
		t.Fatal("event salt scrub not complete", done, err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		raw, err := os.ReadFile(s.path + suffix)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, salt := range []string{a1.Salt, a2.Salt, b.Salt} {
			if bytes.Contains(raw, []byte(salt)) {
				t.Fatal("event salt retained after managed occurrence erase", suffix)
			}
		}
	}

}
func TestBodylessSourceAuthorityRecomputedFromHeldKeyOperation(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	a := w.key
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	c := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, 32))
	genesis := w.o.PinnedGenesisID
	enroll := w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(b.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{w.genesis.AdvisoryID}}, a, a, b)
	w.append(enroll)
	parent := w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(c.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{enroll.AdvisoryID}}, a, a, c)
	revoke := w.op(record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: sig.KeyRefOf(b.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{parent.AdvisoryID}, Reason: "compromised"}, a, a)
	w.append(revoke)
	w.key = b
	ev := w.event("oldB")
	chunk := w.chunk(ev)
	w.append(chunk)
	w.key = a
	snap := w.session([]string{chunk.AdvisoryID})
	w.append(snap)
	w.append(w.control(1, record.KindRetraction, chunk.AdvisoryID))
	if len(find(w.snapshot(), chunk.AdvisoryID).BodyJCS) != 0 {
		t.Fatal("source still has body")
	}
	w.append(parent)
	var admitted bool
	e := w.s.write(ctx, func() error {
		d, e := w.s.load(ctx)
		if e != nil {
			return e
		}
		for _, o := range d.observed() {
			if o.Record.ID == chunk.AdvisoryID {
				admitted = o.Admissible
			}
		}
		return nil
	})
	if e != nil || admitted {
		t.Fatal("bodyless source retained invalid current authority", e)
	}
	w.s.Close()
	s, e := Open(ctx, w.o)
	if e != nil {
		t.Fatal(e)
	}
	w.s = s
	e = s.write(ctx, func() error {
		d, e := s.load(ctx)
		if e != nil {
			return e
		}
		if d.byID[chunk.AdvisoryID].sigStatus == sig.StatusVerified {
			return failure("bad_provenance")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestActiveFirstControlRetiredBacklogAndBudgetIdentity(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	a := w.key
	x := w.task(1, "oldbody")
	w.append(x)
	erase := w.control(1, record.KindErasure, x.AdvisoryID)
	accepted := w.append(erase)
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	rot := w.op(record.KeyOpBody{Op: record.OpDeviceRotate, Subject: sig.KeyRefOf(b.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: w.o.PinnedGenesisID, Previous: sig.KeyID(a.Public().(ed25519.PublicKey)), Parents: []string{w.genesis.AdvisoryID}}, a, a, b)
	w.append(rot)
	w.append(w.task(2, "ordinary retired backlog"))
	if _, e := w.s.Append(ctx, w.control(2, record.KindErasure, x.AdvisoryID)); Code(e) != "unauthorized_control" {
		t.Fatal("retired control accepted", e)
	}
	duplicate := w.append(erase)
	if duplicate.Sequence != accepted.Sequence {
		t.Fatal("control provenance changed")
	}
	w.key = b
	w.append(w.control(3, record.KindErasure, x.AdvisoryID))
	var effects, authors int
	w.s.conn.QueryRowContext(ctx, "SELECT count(*),count(DISTINCT author) FROM erasure_effect").Scan(&effects, &authors)
	if effects != 2 || authors != 1 {
		t.Fatal("rotation reset stable accounting", effects, authors)
	}
	if len(find(w.snapshot(), x.AdvisoryID).BodyJCS) != 0 {
		t.Fatal("rotation revived erased body")
	}
}
