package syncnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/capture"
	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
	"github.com/Telara-Labs/hilo/contract/transport"
)

const (
	machineB = "55555555-5555-4555-8555-555555555555"
	machineC = "66666666-6666-4666-8666-666666666666"
)

// joinWorld enrolls another device of a's genesis with its own data directory,
// real store and vault, served by a's hosted log. Its device_add is co-signed
// by a and admitted on both stores.
func joinWorld(t *testing.T, a *world, seed byte, machine string) *world {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	pub := key.Public().(ed25519.PublicKey)
	a.at++
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(pub, record.RoleDevice, machine), Genesis: a.genesis, Parents: []string{a.keyring[len(a.keyring)-1].AdvisoryID}}, a.key.Public().(ed25519.PublicKey), a.machine, a.at, key, a.key)
	if err != nil {
		t.Fatal(err)
	}
	a.append(op.Rec, op.Sigs)
	add := store.SignedRecord{HeaderJCS: op.Rec.HeaderJCS, BodyJCS: op.Rec.BodyJCS, Sigs: op.Sigs, AdvisoryID: op.Rec.ID}
	a.keyring = append(a.keyring, add)
	b := &world{t: t, dir: filepath.Join(base, "data"), key: key, genesis: a.genesis, machine: machine, at: a.at, vault: newMemVault(), hosted: a.hosted}
	b.st, err = store.Open(context.Background(), store.Options{Dir: b.dir, PinnedGenesisID: b.genesis, LocalMachineID: machine})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.st.Close() })
	b.keyring = append([]store.SignedRecord(nil), a.keyring...)
	for _, r := range b.keyring {
		if _, err := b.st.Append(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := capture.PreloadKeys(make([]byte, 32), key)
	if err != nil {
		t.Fatal(err)
	}
	b.keys = &keys
	a.hosted.addDevice(machine, pub)
	return b
}

// restart closes the worker database and the store, as a node stop does, and
// reopens both from the same data directory.
func (w *world) restart(wk *Worker) *Worker {
	w.t.Helper()
	_ = wk.state.Close()
	w.st.Close()
	st, err := store.Open(context.Background(), store.Options{Dir: w.dir, PinnedGenesisID: w.genesis, LocalMachineID: w.machine})
	if err != nil {
		w.t.Fatal(err)
	}
	w.st = st
	return w.worker()
}

func x2SessionKey(t *testing.T) string {
	t.Helper()
	k, err := record.SessionKey("claude-code", "local", record.NativeGlobal, "77777777-7777-4777-8777-777777777777", "")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// chunk appends to w's own store a transcript chunk holding one event with
// text, returning the record and the event id.
func (w *world) chunk(sk, text, anchor string) (*record.Record, []record.Signature, string) {
	w.t.Helper()
	id, err := record.EventID(sk, "assistant_final", record.Anchor{NativeItemID: anchor})
	if err != nil {
		w.t.Fatal(err)
	}
	e := record.Event{ID: id, Seq: 1, Kind: "assistant_final", Prov: "transcript", Text: &record.Text{Body: text}}
	r, s := w.signed(record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.ChunkLID(sk, w.machine, id)}, &record.ChunkBody{Events: []record.Event{e}})
	w.append(r, s)
	return r, s, id
}

// erasureBy signs a complete-coverage erasure as one device. It states only
// the selectors that device knows; nothing is completed from a store.
func erasureBy(t *testing.T, key ed25519.PrivateKey, machine, nonce string, at int64, sel record.Selectors) record.Envelope {
	t.Helper()
	keyID := sig.KeyID(key.Public().(ed25519.PublicKey))
	h := record.Header{Type: record.KindErasure, Prov: record.ProvUser, At: at, Author: record.Author{MachineID: machine, KeyID: keyID}, Red: record.Redact{Profile: record.ProfileLocal}}
	var err error
	if h.LID, err = record.ControlLID(record.KindErasure, keyID, record.H("nonce", nonce)[:32]); err != nil {
		t.Fatal(err)
	}
	r, err := record.Build(h, &record.ErasureBody{EventCoverage: "complete", Selectors: sel, Reason: "user_request"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := sig.SignRecord(key, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return envelopeOf(r, []record.Signature{s})
}

func entryState(t *testing.T, st *store.Store, id string) (string, bool) {
	t.Helper()
	snap, err := st.Snapshot(context.Background(), store.ReadRequest{IDs: []string{id}})
	if err != nil {
		t.Fatalf("snapshot %s: %v", id[:8], err)
	}
	for _, e := range snap.Entries {
		if e.ID == id {
			return e.State, len(e.BodyJCS) > 0
		}
	}
	return "", false
}

func inKeyring(t *testing.T, st *store.Store, id string) bool {
	t.Helper()
	kr, err := st.Keyring(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range kr {
		if r.AdvisoryID == id {
			return true
		}
	}
	return false
}

func ownerBlocked(st *store.Store) bool {
	_, err := st.Snapshot(context.Background(), store.ReadRequest{})
	var e *store.Error
	return errors.As(err, &e) && e.OwnerBlocked
}

func erasurePending(t *testing.T, dir string) int64 {
	t.Helper()
	d, err := store.Inspect(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return d.Scrub.ErasurePending
}

func assertNoCanary(t *testing.T, dir, canary string) {
	t.Helper()
	if err := canaryIn(dir, canary); err != nil {
		t.Fatal(err)
	}
}

// canaryIn reports the first file under dir, database, WAL and sidecar
// included, whose bytes hold canary.
func canaryIn(dir, canary string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(canary)) {
			return fmt.Errorf("%s holds the erased text", filepath.Base(path))
		}
		return nil
	})
}

// X2: two devices of one genesis and one hosted log with page size one.
//
// Device B never saw A's chunk; A's signed event erasure reaches B through the
// log and bans the chunk when it arrives late. On A, B's id-only erasure c1
// leaves event coverage missing, so A's owner is blocked and its ACK stays
// below c1 across restarts while device_add of a new device C and C's
// supplement c2 arrive on later pages. Only the committed supplement completes
// c1, and the ACK covering it is sent after that commit. After C is revoked,
// its later control is refused and holds the cursor.
func TestX2CrossDeviceErasureSignersPagesAndRestart(t *testing.T) {
	ctx := context.Background()
	a := newWorld(t)
	b := joinWorld(t, a, 9, machineB)
	h := a.hosted
	h.pageLimit = 1
	a.enroll()
	pb := b.enroll()
	pa := Profile{}
	if p, err := LoadProfile(a.dir); err != nil {
		t.Fatal(err)
	} else {
		pa = p
	}
	wa, wb := a.worker(), b.worker()
	sk := x2SessionKey(t)
	genesisOwner := a.genesis

	// Every ACK any device sends must not run ahead of that device's durable
	// cursor, and an ACK covering a control must find its enforcement committed.
	var checkMu sync.Mutex
	var ackFailures []string
	nodes := map[string]struct {
		w  *world
		wk **Worker
		p  Profile
	}{testMachine: {a, &wa, pa}, machineB: {b, &wb, pb}}
	var enforcedAt map[int64]func() string
	h.onAck = func(machine string, ack transport.Ack) {
		checkMu.Lock()
		defer checkMu.Unlock()
		n := nodes[machine]
		c, err := (*n.wk).state.cursors(ctx, destination(n.p.Scope()))
		if err != nil || ack.CtlEnforcedThrough > c.Ctl || ack.DataAppliedThrough > c.Data {
			ackFailures = append(ackFailures, fmt.Sprintf("%s ack %+v ahead of durable %+v (%v)", machine[:4], ack, c, err))
		}
		if machine != testMachine {
			return
		}
		for hseq, check := range enforcedAt {
			if ack.CtlEnforcedThrough >= hseq {
				if msg := check(); msg != "" {
					ackFailures = append(ackFailures, fmt.Sprintf("ack %d before enforcement of %d committed: %s", ack.CtlEnforcedThrough, hseq, msg))
				}
			}
		}
	}
	round := func(wk *Worker, want error) {
		t.Helper()
		if err := wk.Round(ctx); !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Fatalf("round: %v, want %v", err, want)
		}
		checkMu.Lock()
		defer checkMu.Unlock()
		if len(ackFailures) > 0 {
			t.Fatal(strings.Join(ackFailures, "; "))
		}
	}
	lastAck := func(machine string) transport.Ack {
		t.Helper()
		acks := h.acksOf(machine)
		if len(acks) == 0 {
			t.Fatalf("%s sent no ack", machine[:4])
		}
		return acks[len(acks)-1]
	}

	// Phase 1: B never saw A's chunk. A erases it with a signed event
	// selector; B enforces the control from the log, and the chunk A had
	// already bundled arrives at B later and is banned on admission.
	const canary1 = "x2_never_seen_by_b_canary_5c0d"
	k1, _, e1 := a.chunk(sk, canary1, "x2-one")
	staged, err := a.st.SelectBundle(ctx, []string{k1.ID})
	if err != nil || len(staged.Data) != 1 {
		t.Fatalf("stage chunk for late transfer: %d %v", len(staged.Data), err)
	}
	a.at++
	x1 := erasureBy(t, a.key, a.machine, "x2-x1", a.at, record.Selectors{IDs: []string{k1.ID}, Events: []record.EventSelector{{Owner: genesisOwner, SessionKey: sk, EventID: e1}}})
	x1rec, err := decodeEnvelope(x1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.st.ApplyControl(ctx, store.SignedRecord{HeaderJCS: x1rec.HeaderJCS, BodyJCS: x1rec.BodyJCS, Sigs: x1.Sigs, AdvisoryID: x1.ID}); err != nil {
		t.Fatal("local erasure on A", err)
	}
	hx1 := h.addControl(x1)
	round(wb, nil)
	if c := cursorsOf(t, wb, pb); c.Ctl != hx1 {
		t.Fatalf("B did not enforce A's control: %+v", c)
	}
	if ack := lastAck(machineB); ack.CtlEnforcedThrough != hx1 {
		t.Fatalf("B ack %+v", ack)
	}
	// B's own capture of the same event occurrence is banned on admission.
	recaptured, _, again := b.chunk(sk, canary1+" on b", "x2-one")
	if again != e1 {
		t.Fatal("fixture did not recapture the same event")
	}
	if state, body := entryState(t, b.st, recaptured.ID); state != "invalidated" || body {
		t.Fatalf("B captured an event A erased: %s body=%v", state, body)
	}
	keyring, err := a.st.Keyring(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.st.ImportBundle(ctx, store.BundleImport{LocalKeyID: sig.KeyID(b.key.Public().(ed25519.PublicKey)), Keyring: keyring, Data: staged.Data}); err != nil {
		t.Fatal("late arrival at B", err)
	}
	if state, body := entryState(t, b.st, k1.ID); state != "invalidated" || body {
		t.Fatalf("late chunk escaped A's erasure on B: %s body=%v", state, body)
	}
	if res, err := b.st.Scrub(ctx, x1.ID); err != nil || res.State != "complete" {
		t.Fatalf("B scrub %+v %v", res, err)
	}
	assertNoCanary(t, b.dir, canary1)
	round(wb, nil)
	if fenced, err := b.st.RestorePending(ctx); err != nil || fenced {
		t.Fatalf("B restore fence not released by a complete round: %v %v", fenced, err)
	}

	// Phase 2, page 1: B knows only the id of A's chunk k2 and erases it by
	// id. On A the chunk's event is not covered, so the owner is blocked.
	const canary2 = "x2_missing_membership_canary_a91e"
	k2, _, e2 := a.chunk(sk, canary2, "x2-two")
	b.at = a.at + 10
	c1 := erasureBy(t, b.key, b.machine, "x2-c1", b.at, record.Selectors{IDs: []string{k2.ID}})
	hc1 := h.addControl(c1)
	heldBelowC1 := func(stage string) {
		t.Helper()
		c := cursorsOf(t, wa, pa)
		if c.Ctl != hx1 || c.BarrierHSeq != hc1 || c.BarrierReason != "coverage_pending" {
			t.Fatalf("%s: A cursors %+v", stage, c)
		}
		for _, ack := range h.acksOf(testMachine) {
			if ack.CtlEnforcedThrough >= hc1 {
				t.Fatalf("%s: A acknowledged c1 with coverage missing: %+v", stage, ack)
			}
		}
		if !ownerBlocked(a.st) || erasurePending(t, a.dir) != 1 {
			t.Fatalf("%s: missing membership did not block A's owner", stage)
		}
		if res, err := a.st.Scrub(ctx, c1.ID); err != nil || res.State != "blocked" {
			t.Fatalf("%s: early clean scrub %+v %v", stage, res, err)
		}
	}
	round(wa, ErrControlBlocked)
	heldBelowC1("page 1")
	// The fan-out shows B enforced c1 (it holds no member of k2) while A has not.
	round(wb, nil)
	if ack := lastAck(machineB); ack.CtlEnforcedThrough != hc1 {
		t.Fatalf("B fan-out ack %+v", ack)
	}
	wa = a.restart(wa)
	round(wa, ErrControlBlocked)
	heldBelowC1("page 1 after restart")

	// Page 2: a key_op enrolls device C, co-signed by A.
	cKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, 32))
	cPub := cKey.Public().(ed25519.PublicKey)
	a.at = b.at + 1
	cAdd, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(cPub, record.RoleDevice, machineC), Genesis: a.genesis, Parents: []string{a.keyring[len(a.keyring)-1].AdvisoryID}}, a.key.Public().(ed25519.PublicKey), a.machine, a.at, cKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	hk := h.addControl(envelopeOf(cAdd.Rec, cAdd.Sigs))
	// While c1 is coverage-pending the enrollment is staged: it stays an exact
	// pending envelope usable only to verify a supplement, and A's durable
	// keyring does not hold it, across restart.
	stagedOnly := func(stage string) {
		t.Helper()
		if n := count(t, wa, "SELECT count(*) FROM ctl_pending WHERE hseq=? AND reason='staged'", hk); n != 1 {
			t.Fatalf("%s: device_add not staged: %d", stage, n)
		}
		if inKeyring(t, a.st, cAdd.Rec.ID) {
			t.Fatalf("%s: device_add applied durably while c1 is coverage-pending", stage)
		}
	}
	wa = a.restart(wa)
	round(wa, ErrControlBlocked)
	heldBelowC1("page 2")
	if n := count(t, wa, "SELECT count(*) FROM ctl_pending WHERE hseq IN (?,?)", hc1, hk); n != 2 {
		t.Fatalf("page 2: c1 and the key_op not both held pending: %d", n)
	}
	stagedOnly("page 2")
	wa = a.restart(wa)
	round(wa, ErrControlBlocked)
	heldBelowC1("page 2 after restart")
	stagedOnly("page 2 after restart")
	wa = a.restart(wa)

	// Page 3: newly enrolled C supplies the signed event coverage. The ACK
	// that covers c1 must find the purge and the completed coverage committed,
	// and the erased bytes already gone from every file.
	c2 := erasureBy(t, cKey, machineC, "x2-c2", a.at+1, record.Selectors{Events: []record.EventSelector{{Owner: genesisOwner, SessionKey: sk, EventID: e2}}})
	hc2 := h.addControl(c2)
	checkMu.Lock()
	enforcedAt = map[int64]func() string{hc1: func() string {
		d, err := store.Inspect(ctx, a.dir)
		if err != nil || d.Scrub.ErasurePending != 0 {
			return fmt.Sprintf("%d erasures pending (%v)", d.Scrub.ErasurePending, err)
		}
		snap, err := a.st.Snapshot(ctx, store.ReadRequest{IDs: []string{k2.ID}})
		if err != nil || len(snap.Entries) != 1 || snap.Entries[0].State != "invalidated" || len(snap.Entries[0].BodyJCS) != 0 {
			return fmt.Sprintf("k2 not purged (%v)", err)
		}
		if err := canaryIn(a.dir, canary2); err != nil {
			return err.Error()
		}
		return ""
	}}
	checkMu.Unlock()
	round(wa, nil)
	if c := cursorsOf(t, wa, pa); c.Ctl != hc2 || c.BarrierHSeq != 0 {
		t.Fatalf("supplement did not complete the contiguous prefix: %+v", c)
	}
	if !inKeyring(t, a.st, cAdd.Rec.ID) {
		t.Fatal("staged device_add not applied after c1 completed")
	}
	if ack := lastAck(testMachine); ack.CtlEnforcedThrough != hc2 {
		t.Fatalf("A final ack %+v", ack)
	}
	assertNoCanary(t, a.dir, canary2)
	round(wb, nil)
	if ack := lastAck(machineB); ack.CtlEnforcedThrough != hc2 {
		t.Fatalf("B did not follow the enrolled signer: %+v", ack)
	}

	// Revoked signer: A revokes C; C's later control is refused on both
	// devices, stays a barrier across restart and erases nothing.
	survivor := a.task(9, repoA, "active")
	a.at++
	revoke, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: sig.KeyRefOf(cPub, record.RoleDevice, machineC), Genesis: a.genesis, Parents: []string{cAdd.Rec.ID}, Reason: "lost"}, a.key.Public().(ed25519.PublicKey), a.machine, a.at, a.key)
	if err != nil {
		t.Fatal(err)
	}
	hr := h.addControl(envelopeOf(revoke.Rec, revoke.Sigs))
	c3 := erasureBy(t, cKey, machineC, "x2-c3", a.at+1, record.Selectors{IDs: []string{survivor.ID}})
	hc3 := h.addControl(c3)
	for i := 0; i < 2; i++ {
		round(wa, ErrControlBlocked)
		c := cursorsOf(t, wa, pa)
		if c.Ctl != hr || c.BarrierHSeq != hc3 || !strings.HasPrefix(c.BarrierReason, "store_") {
			t.Fatalf("revoked signer: A cursors %+v", c)
		}
		if ack := lastAck(testMachine); ack.CtlEnforcedThrough != hr {
			t.Fatalf("revoked signer: A ack %+v", ack)
		}
		if state, body := entryState(t, a.st, survivor.ID); state != "live" || !body {
			t.Fatalf("post-revocation control erased data: %s", state)
		}
		// The supplement admitted before the revocation keeps c1 complete.
		if n := erasurePending(t, a.dir); n != 0 {
			t.Fatalf("revocation reopened c1: %d pending", n)
		}
		wa = a.restart(wa)
	}
	round(wb, ErrControlBlocked)
	if c := cursorsOf(t, wb, pb); c.Ctl != hr || c.BarrierHSeq != hc3 {
		t.Fatalf("revoked signer: B cursors %+v", c)
	}
}
