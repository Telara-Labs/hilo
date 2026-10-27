package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

const (
	day = int64(86400000)
	t0  = int64(1761150000000)
)

func key(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("mnc-test-key/" + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func keyring(t *testing.T, tpk ed25519.PrivateKey) *sig.State {
	t.Helper()
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(pub(tpk), record.RolePolicy, ""), Genesis: "acme"},
		pub(tpk), "", t0, tpk)
	if err != nil {
		t.Fatal(err)
	}
	op.FromLogin = true
	op.Issuer = sig.TrustedIssuer{Tenant: "acme", Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin}
	kr := sig.NewKeyring("")
	if r := sig.VerifyKeyOp(kr, op); r.Status != sig.OpAuthorized {
		t.Fatalf("%+v", r)
	}
	return kr.State()
}

func policyRecord(t *testing.T, signer ed25519.PrivateKey, b record.PolicyBody) (*record.Record, []record.Signature) {
	t.Helper()
	h := record.Header{Type: record.KindPolicy, LID: record.PolicyLID(b.Tenant), Author: record.Author{KeyID: sig.KeyID(pub(signer))},
		At: b.IssuedAt, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}
	r, err := record.Build(h, &b)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := sig.SignRecord(signer, r.ID)
	return r, []record.Signature{s}
}

func body(seq int64) record.PolicyBody {
	return record.PolicyBody{Tenant: "acme", Seq: seq, IssuedAt: t0, RefreshAfter: t0 + day, NotAfter: t0 + 7*day,
		Applies: record.PolicyApplies{Users: []string{"*"}}, Push: record.PolicyPush{MaxProfile: "push-metadata", AllowRepos: []string{"github.com/acme/*"}},
		BlockedRepos: []record.BlockedRepo{{RemoteGlob: "github.com/acme/secret", Effect: "no-push"}}}
}

func TestVerify(t *testing.T) {
	tpk := key("TPK")
	st := keyring(t, tpk)
	r, s := policyRecord(t, tpk, body(1))
	if _, err := Verify(r, s, st, sig.TrustedIssuer{Tenant: "acme", Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin}); err != nil {
		t.Fatal(err)
	}
	r2, s2 := policyRecord(t, key("rogue"), body(1))
	if _, err := Verify(r2, s2, st, sig.TrustedIssuer{Tenant: "acme", Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin}); err == nil {
		t.Fatal("policy signed by an unknown key accepted")
	}
	other := body(1)
	other.Tenant = "globex"
	r3, s3 := policyRecord(t, tpk, other)
	if _, err := Verify(r3, s3, st, sig.TrustedIssuer{Tenant: "acme", Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin}); err == nil {
		t.Fatal("policy of another tenant accepted")
	}
}

func TestChain(t *testing.T) {
	tpk := key("TPK")
	st := keyring(t, tpk)
	mk := func(seq int64, tweak func(*record.PolicyBody)) *Policy {
		b := body(seq)
		if tweak != nil {
			tweak(&b)
		}
		r, s := policyRecord(t, tpk, b)
		p, err := Verify(r, s, st, sig.TrustedIssuer{Tenant: "acme", Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p1, p2, p2b, p3 := mk(1, nil), mk(2, nil), mk(2, func(b *record.PolicyBody) { b.Kill.Sync = true }), mk(3, nil)
	c := NewChain("acme")
	for _, step := range []struct {
		p    *Policy
		want string
	}{{p2, Accepted}, {p1, Rollback}, {p2, Duplicate}, {p2b, Tamper}, {p3, Accepted}} {
		if got, _ := c.Offer(step.p); got != step.want {
			t.Fatalf("offer seq %d: got %s want %s", step.p.Body.Seq, got, step.want)
		}
		if step.want == Tamper && Evaluate(c, RestoreClock(0), t0, false) != TamperedHead {
			t.Fatal("tamper must fail closed")
		}
	}
	if c.Head.ID != p3.ID || c.Tampered {
		t.Fatal("a higher seq clears the tamper state")
	}
	if _, err := NewChain("globex").Offer(p1); err == nil {
		t.Fatal("cross-tenant offer accepted")
	}
}

func TestClockAndFreshness(t *testing.T) {
	c := NewChain("acme")
	p := &Policy{ID: "p", Body: func() *record.PolicyBody { b := body(1); return &b }()}
	c.Offer(p)
	clk := RestoreClock(0)
	if f := Evaluate(c, clk, clk.Now(t0+1, 0), false); f != Fresh {
		t.Fatal(f)
	}
	if f := Evaluate(c, clk, clk.Now(t0+2*day, 0), false); f != RefreshDue {
		t.Fatal(f)
	}
	if f := Evaluate(c, clk, clk.Now(t0+8*day, 0), false); f != Expired {
		t.Fatal(f)
	}
	// restart keeps the floor: setting the wall clock back is detected
	floor := clk.Floor()
	clk2 := RestoreClock(floor)
	tt := clk2.Now(t0+1, 0)
	if !clk2.Rollback() || tt != floor {
		t.Fatal("wall clock below floor must be detected and T must not go back")
	}
	if f := Evaluate(c, clk2, tt, false); f != RolledBack {
		t.Fatal(f)
	}
	// a fresh hosted Date above the floor clears it; T follows the anchor
	observeTestDate(clk2, floor+10, 1000, t0)
	if clk2.Rollback() {
		t.Fatal("fresh date must clear rollback")
	}
	if got := clk2.Now(t0, 1500); got != floor+510 {
		t.Fatalf("anchored time %d", got)
	}
	// a Date below the floor does not clear it
	clk3 := RestoreClock(floor)
	clk3.Now(t0, 0)
	observeTestDate(clk3, floor-1000, 0, t0)
	if !clk3.Rollback() {
		t.Fatal("stale date cleared rollback")
	}
	// no anchor: T is at least the floor
	if got := RestoreClock(500).Now(400, 0); got != 500 {
		t.Fatal(got)
	}
	if Evaluate(NewChain("acme"), RestoreClock(0), t0, true) != Invalid || Evaluate(NewChain("acme"), RestoreClock(0), t0, false) != NoPolicy {
		t.Fatal("no head")
	}
}

func TestEffects(t *testing.T) {
	b := body(1)
	c := NewChain("acme")
	c.Offer(&Policy{ID: "p", Body: &b})
	if e := EffectsOf(c, Fresh); !e.DataPush || !e.DataPull || !e.ControlRefresh || !e.RestrictiveLocal || e.TenantHookPull {
		t.Fatalf("%+v", e)
	}
	for _, f := range []Freshness{Expired, RolledBack, TamperedHead} {
		e := EffectsOf(c, f)
		if e.DataPush || e.DataPull || !e.ControlRefresh || !e.RestrictiveLocal {
			t.Fatalf("%s: %+v", f, e)
		}
	}
	if e := EffectsOf(NewChain("x"), Invalid); e.DataPush || e.DataPull || !e.ControlRefresh {
		t.Fatalf("invalid: %+v", e)
	}
	b.Kill = record.PolicyKill{Sync: true, WithdrawPulled: true}
	b.Seq = 2
	c.Offer(&Policy{ID: "p2", Body: &b})
	if e := EffectsOf(c, Fresh); e.DataPush || e.DataPull || !e.CancelOutbox || !e.WithdrawPulled || !e.ControlRefresh {
		t.Fatalf("kill: %+v", e)
	}
	if !PushAllowed(&b, "github.com/acme/api") || PushAllowed(&b, "github.com/acme/secret") || PushAllowed(&b, "github.com/other/x") {
		t.Fatal("push allow list")
	}
	b.Push.AllowRepos = nil
	if PushAllowed(&b, "github.com/acme/api") {
		t.Fatal("empty allow list allows none")
	}
	if !AppliesTo(&b, "u1") || AppliesTo(&record.PolicyBody{Applies: record.PolicyApplies{Users: []string{"u2"}}}, "u1") {
		t.Fatal("applies")
	}
	bad := record.PolicyBody{BlockedRepos: []record.BlockedRepo{{RemoteGlob: "[", Effect: "no-capture"}}}
	if !RepoBlocked(&bad, "anything", "no-capture") {
		t.Fatal("malformed glob must fail closed")
	}
	if Ceiling(true, false) || !Ceiling(true, true) {
		t.Fatal("ceiling")
	}
}

func TestAuthenticatedAnchorAcknowledgesPriorWallRegression(t *testing.T) {
	c := RestoreClock(1000)
	if c.Now(900, 0) != 1000 || !c.Rollback() {
		t.Fatal("rollback not detected")
	}
	observeTestDate(c, 1100, 10, 900)
	if got := c.Now(900, 20); got != 1110 || c.Rollback() {
		t.Fatalf("same behind-floor wall must recover: %d %v", got, c.Rollback())
	}
	if got := c.Now(900, 30); got != 1120 || c.Rollback() {
		t.Fatal("repeated wall reading is not a new regression")
	}
	if got := c.Now(901, 40); got != 1130 || c.Rollback() {
		t.Fatal("fresh monotonic advance")
	}
	if got := c.Now(899, 50); got < 1130 || !c.Rollback() {
		t.Fatal("new backward wall step must fail closed")
	}
	observeTestDate(c, 1, 60, 899)
	if !c.Rollback() {
		t.Fatal("stale date must not recover")
	}
	observeTestDate(c, 1200, 70, 899)
	if c.Rollback() || c.Now(899, 80) != 1210 {
		t.Fatal("new authenticated date recovers")
	}
}

func observeTestDate(c *Clock, date, mono, wall int64) error {
	return c.ObserveAnchor(DateObservation{Date: date, RequestStartMono: mono, ReceiptMono: mono, ReceiptWall: wall, Authenticated: true, ConfiguredEndpoint: true, BoundLiveResponse: true, NoStore: true, DateCount: 1})
}
