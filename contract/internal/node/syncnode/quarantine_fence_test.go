package syncnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
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

// Late recall evidence must fence already quarantined and later session
// descendants, including when main-store invalidation already drops the
// recalling chunk before the quarantine's own fence lookup.
func TestQuarantineRecallClosureAllArrivalOrders(t *testing.T) {
	orders := [][]string{
		{"recall", "later", "erase"}, {"recall", "erase", "later"},
		{"later", "recall", "erase"}, {"later", "erase", "recall"},
		{"erase", "recall", "later"}, {"erase", "later", "recall"},
	}
	for _, order := range orders {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			ctx := context.Background()
			w := newWorld(t)
			w.enroll()
			wk := w.worker()
			root := w.task(1, repoA, "active")
			sk := x2SessionKey(t)
			recall, _ := foreignDerived(t, sk, "recall_copy_canary_6081", "recall-exposure", w.at)
			r, err := nodesync.OpenEnvelope(recall)
			if err != nil {
				t.Fatal(err)
			}
			body := r.Body.(*record.ChunkBody)
			body.Salt = ""
			body.Events[0].Salt, body.Events[0].Revision = "", ""
			body.Events[0].Recalled = []string{root.Header.LID + "@" + root.ID}
			r, err = record.Build(r.Header, r.Body)
			if err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{78}, 32))
			sg, err := sig.SignRecord(key, r.ID)
			if err != nil {
				t.Fatal(err)
			}
			recall = envelopeOf(r, []record.Signature{sg})
			later, _ := foreignDerived(t, sk, "later_semantic_canary_4bb1", "later-semantic", w.at+1)
			for _, step := range order {
				switch step {
				case "recall":
					w.hosted.addData(recall)
				case "later":
					w.hosted.addData(later)
				case "erase":
					w.hosted.addControl(w.control(2, record.KindErasure, root.ID))
				}
				if err := wk.Round(ctx); err != nil {
					t.Fatal(step, err)
				}
			}
			if n := count(t, wk, "SELECT count(*) FROM data_quarantine"); n != 0 {
				t.Fatalf("semantic descendant retained after recall evidence and erasure: %d", n)
			}
			if n := count(t, wk, "SELECT count(*) FROM quarantine_fence WHERE kind='session' AND value=?", sk); n != 1 {
				t.Fatal("recalled invalidated root did not persist a session fence")
			}
			assertNoCanary(t, w.dir, recall.Body.Bytes)
			assertNoCanary(t, w.dir, later.Body.Bytes)
		})
	}
}

// A local erasure of an unseen hosted record leaves no Snapshot entry. Its
// durable tomb still fences that record, copied descendants and recall roots.
func TestLocalUnseenErasureFencesHostedQuarantine(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.enroll()
	wk := w.worker()
	sk := x2SessionKey(t)
	late, id := foreignDerived(t, sk, "local_unseen_erasure_canary_71bb", "unseen", w.at)
	ctl, _, err := signedOf(w.control(1, record.KindErasure, id))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.st.ApplyControl(ctx, ctl); err != nil {
		t.Fatal(err)
	}
	invalid, err := w.st.QuarantineInvalidated(ctx, []string{id})
	if err != nil || !invalid {
		t.Fatal("absent target tomb not visible", invalid, err)
	}
	w.hosted.addData(late)
	if err := wk.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(t, wk, "SELECT count(*) FROM data_quarantine"); n != 0 {
		t.Fatal("local unseen erasure did not fence late copy", n)
	}
	assertNoCanary(t, w.dir, late.Body.Bytes)
}

// Owner-local erasure must clean the sync sidecar even with sync disabled and
// no worker or hosted control available. A pinned reader keeps physical state
// pending across a store reopen; once released, the exact same job completes
// with no planted copy in either database/WAL. Unrelated quarantine survives.
func TestLocalErasureScrubsSidecarWithoutHostedRound(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	p := w.enroll()
	wk := w.worker()
	sk := x2SessionKey(t)
	root := w.task(1, repoA, "active")
	victim, _ := foreignDerived(t, sk, "local_sidecar_erasure_canary_31ad", "local-sidecar", w.at, root.ID)
	keep, _ := foreignDerived(t, sk, "unrelated_quarantine_59c1", "unrelated", w.at)
	w.hosted.addData(victim)
	w.hosted.addData(keep)
	if err := wk.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(t, wk, "SELECT count(*) FROM data_quarantine"); n != 2 {
		t.Fatal("fixture", n)
	}
	w.selectRepo(wk, repoA)
	ob := newOutbox(wk.state, w.st, p.Scope())
	if n, err := wk.export(ctx, p, ob); err != nil || n != 1 {
		t.Fatal("queue fixture", n, err)
	}
	var queuedBody []byte
	if err := wk.state.db.QueryRowContext(ctx, "SELECT body FROM outbox WHERE source_id=?", root.ID).Scan(&queuedBody); err != nil {
		t.Fatal(err)
	}
	if err := SetEnabled(w.dir, false); err != nil {
		t.Fatal(err)
	}
	release := pinReader(t, filepath.Join(w.dir, store.SyncDatabaseName), "SELECT count(*) FROM data_quarantine")
	ctl, _, err := signedOf(w.control(2, record.KindErasure, root.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.st.ApplyControl(ctx, ctl); err != nil {
		t.Fatal(err)
	}
	r, err := w.st.Scrub(ctx, ctl.AdvisoryID)
	if err != nil || r.State == "complete" {
		t.Fatal("pinned sidecar gave clean receipt", r, err)
	}
	if n := count(t, wk, "SELECT count(*) FROM data_quarantine"); n != 1 {
		t.Fatal("targeted quarantine cleanup", n)
	}
	if err := w.st.Close(); err != nil {
		t.Fatal(err)
	}
	w.st, err = store.Open(ctx, store.Options{Dir: w.dir, PinnedGenesisID: p.Genesis, LocalMachineID: p.Device})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.st.Close() })
	r, err = w.st.Scrub(ctx, ctl.AdvisoryID)
	if err != nil || r.State == "complete" {
		t.Fatal("restart forgot pinned sidecar", r, err)
	}
	release()
	r, err = w.st.Scrub(ctx, ctl.AdvisoryID)
	if err != nil || r.State != "complete" {
		t.Fatal("released sidecar did not clean", r, err)
	}
	assertNoCanary(t, w.dir, victim.Body.Bytes)
	assertNoCanary(t, w.dir, string(queuedBody))
	if n := count(t, wk, "SELECT count(*) FROM outbox WHERE source_id=? AND (header IS NOT NULL OR body IS NOT NULL OR sigs IS NOT NULL)", root.ID); n != 0 {
		t.Fatal("outbox copy retained", n)
	}
	if n := count(t, wk, "SELECT count(*) FROM operation WHERE length(raw)>0"); n != 0 {
		t.Fatal("immutable operation copy retained", n)
	}
	if n := count(t, wk, "SELECT count(*) FROM data_quarantine"); n != 1 {
		t.Fatal("unrelated copy lost", n)
	}
}

func TestLocalScrubDoesNotDeadlockSidecarWriter(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.enroll()
	wk := w.worker()
	root := w.task(1, repoA, "active")
	ctl, _, err := signedOf(w.control(2, record.KindErasure, root.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.st.ApplyControl(ctx, ctl); err != nil {
		t.Fatal(err)
	}
	err = wk.state.tx(ctx, func(q querier) error {
		finished := make(chan error, 1)
		go func() {
			r, e := w.st.Scrub(ctx, ctl.AdvisoryID)
			if e == nil && r.State == "complete" {
				e = fmt.Errorf("busy sidecar returned complete")
			}
			finished <- e
		}()
		select {
		case e := <-finished:
			return e
		case <-time.After(3 * time.Second):
			return fmt.Errorf("main/sidecar writer lock inversion")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := w.st.Scrub(ctx, ctl.AdvisoryID)
	if err != nil || r.State != "complete" {
		t.Fatal("free sidecar did not complete", r, err)
	}
}

type scrubPausedSigner struct {
	inner   RecordSigner
	entered chan struct{}
	release chan struct{}
}

func (s scrubPausedSigner) KeyID() string { return s.inner.KeyID() }
func (s scrubPausedSigner) SignRecordID(id string) (record.Signature, error) {
	close(s.entered)
	<-s.release
	return s.inner.SignRecordID(id)
}

// A metadata export prepared before local erasure must not persist its sealed
// copy after a successful physical scrub, even if it resumes much later.
func TestLocalScrubFencesStalePreparedExport(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	p := w.enroll()
	wk := w.worker()
	root := w.task(1, repoA, "active")
	w.selectRepo(wk, repoA)
	paused := scrubPausedSigner{inner: w.keys, entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	resume := func() { releaseOnce.Do(func() { close(paused.release) }) }
	defer resume()
	wk.cfg.Signer = paused
	done := make(chan error, 1)
	go func() { _, err := wk.export(ctx, p, newOutbox(wk.state, w.st, p.Scope())); done <- err }()
	select {
	case <-paused.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("export did not reach signing")
	}
	ctl, _, err := signedOf(w.control(2, record.KindErasure, root.ID))
	if err != nil {
		resume()
		t.Fatal(err)
	}
	if _, err = w.st.ApplyControl(ctx, ctl); err != nil {
		resume()
		t.Fatal(err)
	}
	r, err := w.st.Scrub(ctx, ctl.AdvisoryID)
	if err != nil || r.State != "complete" {
		resume()
		t.Fatal("scrub", r, err)
	}
	resume()
	select {
	case err := <-done:
		if !errors.Is(err, nodesync.ErrCancelled) {
			t.Fatal("stale export persisted", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stale export did not finish")
	}
	if n := count(t, wk, "SELECT count(*) FROM outbox WHERE body IS NOT NULL"); n != 0 {
		t.Fatal("stale body retained", n)
	}
	if n := count(t, wk, "SELECT count(*) FROM operation WHERE length(raw)>0"); n != 0 {
		t.Fatal("stale immutable operation retained", n)
	}
}
