package syncnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// x2Pair is two enrolled devices of one genesis on one hosted log with page
// size one: A holds the data, B issues controls.
type x2Pair struct {
	a, b   *world
	pa, pb Profile
	h      *hosted
}

func newX2Pair(t *testing.T) *x2Pair {
	t.Helper()
	a := newWorld(t)
	b := joinWorld(t, a, 9, machineB)
	a.hosted.pageLimit = 1
	a.enroll()
	pb := b.enroll()
	pa, err := LoadProfile(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	return &x2Pair{a: a, b: b, pa: pa, pb: pb, h: a.hosted}
}

// unsignedWorker is a receiver whose local private signing key is unavailable.
func (w *world) unsignedWorker() *Worker {
	w.t.Helper()
	wk, err := NewWorker(context.Background(), Config{Dir: w.dir, Store: w.st, Vault: w.vault, TLSRoots: w.hosted.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MaxRetry: 1})
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { _ = wk.state.Close() })
	return wk
}

func (w *world) unsignedRestart(wk *Worker) *Worker {
	w.t.Helper()
	_ = w.restart(wk).state.Close()
	return w.unsignedWorker()
}

func x2Round(t *testing.T, wk *Worker, want error) {
	t.Helper()
	if err := wk.Round(context.Background()); !errors.Is(err, want) && !(want == nil && err == nil) {
		t.Fatalf("round: %v, want %v", err, want)
	}
}

// heldBelow asserts the coverage-pending barrier at c1: cursor and every ACK
// stay below it and the owner is blocked.
func (x *x2Pair) heldBelow(t *testing.T, wk *Worker, stage string, prior, c1 int64) {
	t.Helper()
	c := cursorsOf(t, wk, x.pa)
	if c.Ctl != prior || c.BarrierHSeq != c1 || c.BarrierReason != "coverage_pending" {
		t.Fatalf("%s: A cursors %+v", stage, c)
	}
	for _, ack := range x.h.acksOf(testMachine) {
		if ack.CtlEnforcedThrough >= c1 {
			t.Fatalf("%s: A acknowledged c1 with coverage missing: %+v", stage, ack)
		}
	}
	if !ownerBlocked(x.a.st) {
		t.Fatalf("%s: owner not blocked", stage)
	}
}

func (x *x2Pair) lastAck(t *testing.T) transport.Ack {
	t.Helper()
	acks := x.h.acksOf(testMachine)
	if len(acks) == 0 {
		t.Fatal("A sent no ack")
	}
	return acks[len(acks)-1]
}

// tenantPolicies installs a tenant authority on st as a validated login would
// and returns a signer of that tenant's policies.
func tenantPolicies(t *testing.T, st *store.Store, tenant string) func(seq int64, b record.PolicyBody) record.Envelope {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{63}, 32))
	pub := key.Public().(ed25519.PublicKey)
	root, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(pub, record.RolePolicy, ""), Genesis: tenant}, pub, "", time.Now().UnixMilli(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.InstallTenantPolicyContext(context.Background(), store.TenantPolicyContext{Tenant: tenant, UserID: "user-one", Origin: "https://tenant.example", Root: store.SignedRecord{HeaderJCS: root.Rec.HeaderJCS, BodyJCS: root.Rec.BodyJCS, Sigs: root.Sigs, AdvisoryID: root.Rec.ID}}); err != nil {
		t.Fatal(err)
	}
	return func(seq int64, b record.PolicyBody) record.Envelope {
		t.Helper()
		b.Tenant, b.Seq = tenant, seq
		b.IssuedAt = time.Now().UnixMilli() - 1000
		b.Applies.Users = []string{"*"}
		r, err := record.Build(record.Header{Type: record.KindPolicy, LID: record.PolicyLID(tenant), At: time.Now().UnixMilli(), Author: record.Author{KeyID: sig.KeyID(pub)}, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, &b)
		if err != nil {
			t.Fatal(err)
		}
		s, err := sig.SignRecord(key, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		return envelopeOf(r, []record.Signature{s})
	}
}

func headPolicy(t *testing.T, st *store.Store) (string, *record.PolicyBody) {
	t.Helper()
	id, b, err := st.CapturePolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return id, b
}

func signedEnvelope(e record.Envelope) store.SignedRecord {
	r, err := decodeEnvelope(e)
	if err != nil {
		panic(err)
	}
	return store.SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: e.Sigs, AdvisoryID: e.ID}
}

// X2 c1 → policy → c2 across pages with restarts. While B's id-only erasure
// c1 is coverage-pending on A, a tenant policy that only tightens authority
// commits at once, while a later one that relaxes it is staged and does not
// become the head, across restart. B's signed event supplement c2 completes
// c1; only then does the relaxing policy commit, and the ACK reaches c2.
func TestX2PolicyBetweenCoveragePendingErasureAndSupplement(t *testing.T) {
	ctx := context.Background()
	x := newX2Pair(t)
	a, b, h := x.a, x.b, x.h
	wa := a.worker()
	sk := x2SessionKey(t)
	const canary = "x2_policy_between_canary_7d21"
	k, _, e := a.chunk(sk, canary, "x2-policy")

	sign := tenantPolicies(t, a.st, h.tenant)
	notAfter := time.Now().Add(time.Hour).UnixMilli()
	p1 := sign(1, record.PolicyBody{NotAfter: notAfter, BlockedRepos: []record.BlockedRepo{{RemoteGlob: "github.com/blocked/*", Effect: "no-push"}}})
	if _, err := a.st.Append(ctx, signedEnvelope(p1)); err != nil {
		t.Fatal("initial policy", err)
	}

	// Page 1: c1 by id only. A's owner is blocked; its ACK stays below c1.
	b.at = a.at + 10
	c1 := erasureBy(t, b.key, b.machine, "x2p-c1", b.at, record.Selectors{IDs: []string{k.ID}})
	hc1 := h.addControl(c1)
	x2Round(t, wa, ErrControlBlocked)
	x.heldBelow(t, wa, "page 1", 0, hc1)

	// Page 2: a policy that only tightens (adds a capture kill and a blocked
	// repository) is a restriction and commits immediately.
	p2 := sign(2, record.PolicyBody{NotAfter: notAfter, Kill: record.PolicyKill{CaptureTenantRepos: true}, BlockedRepos: []record.BlockedRepo{{RemoteGlob: "github.com/blocked/*", Effect: "no-push"}, {RemoteGlob: "github.com/also/*", Effect: "no-capture"}}})
	hp2 := h.addControl(p2)
	wa = a.restart(wa)
	x2Round(t, wa, ErrControlBlocked)
	x.heldBelow(t, wa, "page 2", 0, hc1)
	if id, body := headPolicy(t, a.st); id != p2.ID || !body.Kill.CaptureTenantRepos {
		t.Fatalf("restrictive policy not committed while c1 pending: head %s", id[:8])
	}
	if n := count(t, wa, "SELECT count(*) FROM ctl_pending WHERE hseq=? AND reason='staged'", hp2); n != 0 {
		t.Fatal("restrictive policy was staged instead of applied")
	}

	// Page 3: a policy that lifts the kill, unblocks a repository and extends
	// validity relaxes authority. It is staged only, across restart.
	p3 := sign(3, record.PolicyBody{NotAfter: notAfter + 3600000})
	hp3 := h.addControl(p3)
	for i, stage := range []string{"page 3", "page 3 after restart"} {
		if i > 0 {
			wa = a.restart(wa)
		}
		x2Round(t, wa, ErrControlBlocked)
		x.heldBelow(t, wa, stage, 0, hc1)
		if id, body := headPolicy(t, a.st); id != p2.ID || !body.Kill.CaptureTenantRepos {
			t.Fatalf("%s: relaxing policy became live while c1 pending: head %s", stage, id[:8])
		}
		if n := count(t, wa, "SELECT count(*) FROM ctl_pending WHERE hseq=? AND reason='staged'", hp3); n != 1 {
			t.Fatalf("%s: relaxing policy not staged: %d", stage, n)
		}
	}
	wa = a.restart(wa)

	// Page 4: B's event supplement completes c1, then the staged policy commits.
	c2 := erasureBy(t, b.key, b.machine, "x2p-c2", b.at+1, record.Selectors{Events: []record.EventSelector{{Owner: a.genesis, SessionKey: sk, EventID: e}}})
	hc2 := h.addControl(c2)
	x2Round(t, wa, nil)
	if c := cursorsOf(t, wa, x.pa); c.Ctl != hc2 || c.BarrierHSeq != 0 {
		t.Fatalf("supplement did not complete the contiguous prefix: %+v", c)
	}
	if ack := x.lastAck(t); ack.CtlEnforcedThrough != hc2 {
		t.Fatalf("A final ack %+v", ack)
	}
	if id, body := headPolicy(t, a.st); id != p3.ID || body.Kill.CaptureTenantRepos {
		t.Fatalf("staged policy not committed after c1 completed: head %s", id[:8])
	}
	if ownerBlocked(a.st) || erasurePending(t, a.dir) != 0 {
		t.Fatal("owner still blocked after supplement")
	}
	if state, body := entryState(t, a.st, k.ID); state != "invalidated" || body {
		t.Fatalf("chunk not purged: %s", state)
	}
	assertNoCanary(t, a.dir, canary)
}

// A receiver without a local signing key admits another device's erasure and
// recovers a coverage-pending erasure through a newly enrolled signer staged
// in the verification view.
func TestX2ReceiverWithoutSigningKeyRecoversThroughStagedSigner(t *testing.T) {
	x := newX2Pair(t)
	a, b, h := x.a, x.b, x.h
	wa := a.unsignedWorker()
	sk := x2SessionKey(t)

	// A sibling erasure with complete coverage applies without a signer.
	k0, _, e0 := a.chunk(sk, "x2_unsigned_direct_canary_19af", "x2-u0")
	b.at = a.at + 10
	x0 := erasureBy(t, b.key, b.machine, "x2u-x0", b.at, record.Selectors{IDs: []string{k0.ID}, Events: []record.EventSelector{{Owner: a.genesis, SessionKey: sk, EventID: e0}}})
	hx0 := h.addControl(x0)
	x2Round(t, wa, nil)
	if c := cursorsOf(t, wa, x.pa); c.Ctl != hx0 || c.BarrierHSeq != 0 {
		t.Fatalf("sibling erasure blocked a receiver without a signing key: %+v", c)
	}
	if state, body := entryState(t, a.st, k0.ID); state != "invalidated" || body {
		t.Fatalf("sibling erasure not applied: %s", state)
	}

	// c1 by id only, then enrollment of C, then C's supplement, each on its
	// own page with a restart between.
	k, _, e := a.chunk(sk, "x2_unsigned_staged_canary_c04e", "x2-u1")
	b.at = a.at + 10
	c1 := erasureBy(t, b.key, b.machine, "x2u-c1", b.at, record.Selectors{IDs: []string{k.ID}})
	hc1 := h.addControl(c1)
	x2Round(t, wa, ErrControlBlocked)
	x.heldBelow(t, wa, "page 1", hx0, hc1)

	cKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	cPub := cKey.Public().(ed25519.PublicKey)
	a.at = b.at + 1
	cAdd, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(cPub, record.RoleDevice, machineC), Genesis: a.genesis, Parents: []string{a.keyring[len(a.keyring)-1].AdvisoryID}}, a.key.Public().(ed25519.PublicKey), a.machine, a.at, cKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	h.addControl(envelopeOf(cAdd.Rec, cAdd.Sigs))
	wa = a.unsignedRestart(wa)
	x2Round(t, wa, ErrControlBlocked)
	x.heldBelow(t, wa, "page 2", hx0, hc1)
	if inKeyring(t, a.st, cAdd.Rec.ID) {
		t.Fatal("enrollment applied durably while c1 pending")
	}
	wa = a.unsignedRestart(wa)

	c2 := erasureBy(t, cKey, machineC, "x2u-c2", a.at+1, record.Selectors{Events: []record.EventSelector{{Owner: a.genesis, SessionKey: sk, EventID: e}}})
	hc2 := h.addControl(c2)
	x2Round(t, wa, nil)
	if c := cursorsOf(t, wa, x.pa); c.Ctl != hc2 || c.BarrierHSeq != 0 {
		t.Fatalf("unsigned receiver did not recover: %+v", c)
	}
	if ack := x.lastAck(t); ack.CtlEnforcedThrough != hc2 {
		t.Fatalf("A final ack %+v", ack)
	}
	if !inKeyring(t, a.st, cAdd.Rec.ID) {
		t.Fatal("staged enrollment not applied after c1 completed")
	}
	if state, body := entryState(t, a.st, k.ID); state != "invalidated" || body {
		t.Fatalf("chunk not purged: %s", state)
	}
}

// A revocation between a staged enrollment and its signer's supplement applies
// within the view: the revoked signer's c2 is refused, stays the barrier across
// restart, erases nothing and never lets the ACK cross c1.
func TestX2StagedSignerRevokedBeforeSupplementIsRefused(t *testing.T) {
	x := newX2Pair(t)
	a, b, h := x.a, x.b, x.h
	wa := a.worker()
	sk := x2SessionKey(t)
	k, _, e := a.chunk(sk, "x2_revoked_staged_canary_e8b3", "x2-r1")
	b.at = a.at + 10
	c1 := erasureBy(t, b.key, b.machine, "x2r-c1", b.at, record.Selectors{IDs: []string{k.ID}})
	hc1 := h.addControl(c1)

	cKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, 32))
	cPub := cKey.Public().(ed25519.PublicKey)
	a.at = b.at + 1
	cAdd, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(cPub, record.RoleDevice, machineC), Genesis: a.genesis, Parents: []string{a.keyring[len(a.keyring)-1].AdvisoryID}}, a.key.Public().(ed25519.PublicKey), a.machine, a.at, cKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	h.addControl(envelopeOf(cAdd.Rec, cAdd.Sigs))
	a.at++
	revoke, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: sig.KeyRefOf(cPub, record.RoleDevice, machineC), Genesis: a.genesis, Parents: []string{cAdd.Rec.ID}, Reason: "lost"}, a.key.Public().(ed25519.PublicKey), a.machine, a.at, a.key)
	if err != nil {
		t.Fatal(err)
	}
	h.addControl(envelopeOf(revoke.Rec, revoke.Sigs))
	c2 := erasureBy(t, cKey, machineC, "x2r-c2", a.at+1, record.Selectors{Events: []record.EventSelector{{Owner: a.genesis, SessionKey: sk, EventID: e}}})
	hc2 := h.addControl(c2)
	for i := 0; i < 2; i++ {
		x2Round(t, wa, ErrControlBlocked)
		x.heldBelow(t, wa, "revoked staged signer", 0, hc1)
		if n := count(t, wa, "SELECT count(*) FROM ctl_pending WHERE hseq=? AND reason LIKE 'store_%'", hc2); n != 1 {
			t.Fatal("revoked signer's supplement not refused")
		}
		if n := erasurePending(t, a.dir); n != 1 {
			t.Fatalf("revoked signer's supplement completed c1: %d pending", n)
		}
		if inKeyring(t, a.st, cAdd.Rec.ID) {
			t.Fatal("staged enrollment applied durably")
		}
		wa = a.restart(wa)
	}
}

// A revocation of an already enrolled signer while c1 is coverage-pending is a
// restriction: it commits durably at once, not staged, and the revoked
// signer's later supplement is refused and holds the barrier across restart.
func TestX2RevocationDuringCoveragePendingAppliesImmediately(t *testing.T) {
	x := newX2Pair(t)
	a, b, h := x.a, x.b, x.h
	wa := a.worker()
	sk := x2SessionKey(t)
	k, _, e := a.chunk(sk, "x2_revoked_enrolled_canary_51f0", "x2-v1")
	b.at = a.at + 10
	c1 := erasureBy(t, b.key, b.machine, "x2v-c1", b.at, record.Selectors{IDs: []string{k.ID}})
	hc1 := h.addControl(c1)
	a.at = b.at + 1
	bAdd := a.keyring[len(a.keyring)-1]
	revoke, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: sig.KeyRefOf(b.key.Public().(ed25519.PublicKey), record.RoleDevice, machineB), Genesis: a.genesis, Parents: []string{bAdd.AdvisoryID}, Reason: "lost"}, a.key.Public().(ed25519.PublicKey), a.machine, a.at, a.key)
	if err != nil {
		t.Fatal(err)
	}
	hr := h.addControl(envelopeOf(revoke.Rec, revoke.Sigs))
	x2Round(t, wa, ErrControlBlocked)
	x.heldBelow(t, wa, "revocation page", 0, hc1)
	if !inKeyring(t, a.st, revoke.Rec.ID) {
		t.Fatal("revocation not committed while c1 pending")
	}
	if n := count(t, wa, "SELECT count(*) FROM ctl_pending WHERE hseq=? AND reason='staged'", hr); n != 0 {
		t.Fatal("revocation was staged instead of applied")
	}
	c2 := erasureBy(t, b.key, b.machine, "x2v-c2", b.at+1, record.Selectors{Events: []record.EventSelector{{Owner: a.genesis, SessionKey: sk, EventID: e}}})
	hc2 := h.addControl(c2)
	for i := 0; i < 2; i++ {
		wa = a.restart(wa)
		x2Round(t, wa, ErrControlBlocked)
		x.heldBelow(t, wa, "revoked signer supplement", 0, hc1)
		if n := count(t, wa, "SELECT count(*) FROM ctl_pending WHERE hseq=? AND reason LIKE 'store_%'", hc2); n != 1 {
			t.Fatal("revoked signer's supplement not refused")
		}
		if n := erasurePending(t, a.dir); n != 1 {
			t.Fatalf("revoked signer completed c1: %d pending", n)
		}
	}
}
