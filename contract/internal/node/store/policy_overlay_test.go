package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"slices"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

// Every intersection allows nothing either input forbids.
func TestIntersectPolicyNeverRelaxes(t *testing.T) {
	base := record.PolicyBody{NotAfter: 100, RefreshAfter: 50, Applies: record.PolicyApplies{Users: []string{"u"}}, BlockedRepos: []record.BlockedRepo{{RemoteGlob: "a/*", Effect: "no-push"}}, Redaction: record.PolicyRedact{MinEpoch: 2, Shapes: []record.Shape{{Name: "s", RE2: "x"}}}, Push: record.PolicyPush{MaxProfile: record.ProfilePushMetadata, AllowRepos: []string{"r1/*", "r2/*"}}, Readback: record.PolicyReadback{CloudPull: true, HookInjection: true}}
	variants := map[string]func(*record.PolicyBody){
		"same":    func(*record.PolicyBody) {},
		"later":   func(b *record.PolicyBody) { b.NotAfter, b.RefreshAfter = 200, 0 },
		"earlier": func(b *record.PolicyBody) { b.NotAfter, b.RefreshAfter = 80, 40 },
		"kill": func(b *record.PolicyBody) {
			b.Kill = record.PolicyKill{Sync: true, CaptureTenantRepos: true, WithdrawPulled: true}
		},
		"unblock": func(b *record.PolicyBody) { b.BlockedRepos = nil },
		"block_more": func(b *record.PolicyBody) {
			b.BlockedRepos = append(b.BlockedRepos, record.BlockedRepo{RemoteGlob: "c/*", Effect: "no-capture"})
		},
		"epoch_down":   func(b *record.PolicyBody) { b.Redaction.MinEpoch = 1 },
		"epoch_up":     func(b *record.PolicyBody) { b.Redaction.MinEpoch = 5 },
		"shapes":       func(b *record.PolicyBody) { b.Redaction.Shapes = []record.Shape{{Name: "t", RE2: "y"}} },
		"no_push":      func(b *record.PolicyBody) { b.Push = record.PolicyPush{} },
		"allow_all":    func(b *record.PolicyBody) { b.Push.AllowRepos = []string{"*"} },
		"allow_other":  func(b *record.PolicyBody) { b.Push.AllowRepos = []string{"r2/*", "r3/*"} },
		"preview":      func(b *record.PolicyBody) { b.Push.RequirePreview = true },
		"readback_on":  func(b *record.PolicyBody) { b.Readback.HostedOriginPull = true },
		"readback_off": func(b *record.PolicyBody) { b.Readback = record.PolicyReadback{} },
		"other_user":   func(b *record.PolicyBody) { b.Applies.Users = []string{"v"} },
	}
	clone := func(b record.PolicyBody) record.PolicyBody {
		b.Applies.Users = slices.Clone(b.Applies.Users)
		b.BlockedRepos = slices.Clone(b.BlockedRepos)
		b.Redaction.Shapes = slices.Clone(b.Redaction.Shapes)
		b.Push.AllowRepos = slices.Clone(b.Push.AllowRepos)
		return b
	}
	for hn, hm := range variants {
		for cn, cm := range variants {
			head, c := clone(base), clone(base)
			hm(&head)
			cm(&c)
			before := clone(head)
			eff := intersectPolicy(&head, &c, "u")
			if policyRelaxes(&head, eff, "u") || policyRelaxes(&c, eff, "u") {
				t.Fatalf("%s ∩ %s relaxes: %+v", hn, cn, eff)
			}
			if eff.RefreshAfter != 0 && (head.RefreshAfter != 0 && eff.RefreshAfter > head.RefreshAfter || c.RefreshAfter != 0 && eff.RefreshAfter > c.RefreshAfter) || eff.RefreshAfter == 0 && (head.RefreshAfter != 0 || c.RefreshAfter != 0) {
				t.Fatalf("%s ∩ %s refresh_after %d", hn, cn, eff.RefreshAfter)
			}
			if eff.Seq != head.Seq || eff.Salt != head.Salt || eff.IssuedAt != head.IssuedAt {
				t.Fatal("intersection changed head identity")
			}
			eff.BlockedRepos = append(eff.BlockedRepos, record.BlockedRepo{RemoteGlob: "z", Effect: "no-push"})
			if len(head.BlockedRepos) != len(before.BlockedRepos) {
				t.Fatal("intersection aliases the head")
			}
		}
	}
}

// installTenant installs a tenant authority on w as a validated login would
// and returns a signer of its policies.
func installTenant(t *testing.T, w *world, tenant string) func(seq int64, b record.PolicyBody) SignedRecord {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	pub := key.Public().(ed25519.PublicKey)
	root, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(pub, record.RolePolicy, ""), Genesis: tenant}, pub, "", time.Now().UnixMilli(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.s.InstallTenantPolicyContext(context.Background(), TenantPolicyContext{Tenant: tenant, UserID: "fixture-user", Origin: "https://tenant.example", Root: wire(root.Rec, root.Sigs)}); err != nil {
		t.Fatal(err)
	}
	return func(seq int64, b record.PolicyBody) SignedRecord {
		t.Helper()
		b.Tenant, b.Seq = tenant, seq
		b.IssuedAt = time.Now().UnixMilli() - 1000
		b.Applies.Users = []string{"fixture-user"}
		r, err := record.Build(record.Header{Type: record.KindPolicy, LID: record.PolicyLID(tenant), At: time.Now().UnixMilli(), Author: record.Author{KeyID: sig.KeyID(pub)}, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, &b)
		if err != nil {
			t.Fatal(err)
		}
		sg, err := sig.SignRecord(key, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		return wire(r, []record.Signature{sg})
	}
}

// effective is the policy decision every consumer reads: the capture and
// disclosure body, the push policy and the pull effect.
type effective struct {
	headID     string
	body       *record.PolicyBody
	readEpoch1 bool // disclosure of a record sealed at epoch 1
	sealNew    bool // capture in a repository only the candidate blocks
	push       SyncPolicy
	pull       bool
}

func effectiveOf(t *testing.T, s *Store, headID string) effective {
	t.Helper()
	ctx := context.Background()
	var out effective
	if err := s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		out.headID = d.tenant.chain.HighestID
		out.body = d.tenant.body()
		probe := &stored{rec: &record.Record{Header: record.Header{Type: record.KindTask, Pol: headID, Red: record.Redact{Epoch: 1}}}}
		out.readEpoch1 = d.policyReadAllowed(probe)
		out.sealNew = d.tenant.sealAllowed("github.com/new/x", 1)
		out.pull = d.tenant.effects.DataPull
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var err error
	if out.push, err = s.SyncPushPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	return out
}

// A staged policy that both tightens and relaxes: its restrictions apply at
// once as the intersection with the committed head, for disclosure, capture,
// push and pull, and survive restart; its relaxations do not. The head's id
// and sequence do not change. Committing the policy clears the overlay. A
// verification without staging leaves the restrictions unenforced, which is
// the defect the overlay closes.
func TestStagedMixedPolicyOverlayTightensAtOnce(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	sign := installTenant(t, w, "tenant-overlay")
	notAfter := time.Now().Add(time.Hour).UnixMilli()
	p1 := sign(1, record.PolicyBody{NotAfter: notAfter, Redaction: record.PolicyRedact{MinEpoch: 1}, Push: record.PolicyPush{MaxProfile: record.ProfilePushMetadata, AllowRepos: []string{"github.com/a/*"}}})
	if _, err := w.s.Append(ctx, p1); err != nil {
		t.Fatal(err)
	}
	// p2 tightens: kills sync, blocks a repository, raises the epoch floor.
	// It relaxes: later expiry, cloud pull, another allowed repository.
	p2 := sign(2, record.PolicyBody{NotAfter: notAfter + 3600000, Kill: record.PolicyKill{Sync: true}, BlockedRepos: []record.BlockedRepo{{RemoteGlob: "github.com/new/*", Effect: "no-capture"}}, Redaction: record.PolicyRedact{MinEpoch: 2}, Push: record.PolicyPush{MaxProfile: record.ProfilePushMetadata, AllowRepos: []string{"github.com/a/*", "github.com/b/*"}}, Readback: record.PolicyReadback{CloudPull: true}})

	before := effectiveOf(t, w.s, p1.AdvisoryID)
	if !before.readEpoch1 || !before.sealNew || !before.push.DataPush || !before.pull || before.headID != p1.AdvisoryID {
		t.Fatalf("fixture head does not allow the probes: %+v", before)
	}

	// Negative control: verifying without staging enforces nothing of p2.
	if relaxes, err := w.s.PolicyRelaxes(ctx, p2, nil); err != nil || !relaxes {
		t.Fatal("mixed policy not a relaxation", relaxes, err)
	}
	if got := effectiveOf(t, w.s, p1.AdvisoryID); !got.readEpoch1 || !got.sealNew || !got.push.DataPush || !got.pull || countRows(t, w.s, "SELECT count(*) FROM policy_overlay") != 0 {
		t.Fatal("verification alone changed authority")
	}

	if relaxes, err := w.s.StagePolicy(ctx, p2, nil); err != nil || !relaxes {
		t.Fatal("stage", relaxes, err)
	}
	check := func(stage string) {
		t.Helper()
		e := effectiveOf(t, w.s, p1.AdvisoryID)
		switch {
		case e.headID != p1.AdvisoryID || e.push.Governed && e.push.PolicyID != "" && e.push.PolicyID != p1.AdvisoryID:
			t.Fatalf("%s: overlay changed head identity: %s", stage, e.headID)
		case e.readEpoch1:
			t.Fatalf("%s: disclosure ignores the staged epoch floor", stage)
		case e.sealNew:
			t.Fatalf("%s: capture ignores the staged repository block", stage)
		case e.push.DataPush || !e.push.CancelOutbox || e.push.PushAllowed("github.com/a/x"):
			t.Fatalf("%s: push ignores the staged kill: %+v", stage, e.push)
		case e.pull:
			t.Fatalf("%s: pull ignores the staged kill", stage)
		case e.body.NotAfter != notAfter || e.body.Readback.CloudPull || slices.Contains(e.body.Push.AllowRepos, "github.com/b/*"):
			t.Fatalf("%s: a staged relaxation is live: %+v", stage, e.body)
		}
		var seq int64
		var id string
		if w.s.conn.QueryRowContext(ctx, "SELECT highest_seq,highest_id FROM tenant_context WHERE active=1").Scan(&seq, &id) != nil || seq != 1 || id != p1.AdvisoryID {
			t.Fatalf("%s: overlay moved the committed chain: %d", stage, seq)
		}
		if countRows(t, w.s, "SELECT count(*) FROM tenant_policy WHERE id=?", p2.AdvisoryID) != 0 {
			t.Fatalf("%s: staged policy stored as a signed policy", stage)
		}
		if id, body, err := w.s.CapturePolicy(ctx); err != nil || id != p1.AdvisoryID || !body.Kill.Sync || body.Redaction.MinEpoch != 2 {
			t.Fatalf("%s: capture policy %v", stage, err)
		}
		if d, err := Inspect(ctx, w.o.Dir); err != nil || d.Policy.Seq != 1 || d.Policy.DataPull || !d.Policy.KillSync {
			t.Fatalf("%s: diagnostics %+v %v", stage, d.Policy, err)
		}
	}
	check("staged")
	if relaxes, err := w.s.StagePolicy(ctx, p2, nil); err != nil || !relaxes || countRows(t, w.s, "SELECT count(*) FROM policy_overlay") != 1 {
		t.Fatal("restaging is not idempotent", err)
	}
	reopenStore(t, &w.s, w.o)
	check("after restart")

	// The staged policy commits normally once allowed; the overlay is gone.
	if _, err := w.s.Append(ctx, p2); err != nil {
		t.Fatal("commit", err)
	}
	if countRows(t, w.s, "SELECT count(*) FROM policy_overlay") != 0 {
		t.Fatal("overlay not cleared by commit")
	}
	after := effectiveOf(t, w.s, p2.AdvisoryID)
	if after.headID != p2.AdvisoryID || after.body.NotAfter != notAfter+3600000 || !after.body.Readback.CloudPull || !slices.Contains(after.body.Push.AllowRepos, "github.com/b/*") || after.push.DataPush || after.sealNew {
		t.Fatalf("committed policy not in effect: %+v", after.body)
	}
	reopenStore(t, &w.s, w.o)
	if e := effectiveOf(t, w.s, p2.AdvisoryID); e.headID != p2.AdvisoryID || !e.body.Readback.CloudPull {
		t.Fatal("restart changed the committed head")
	}

	// Logout removes every staged copy of tenant configuration.
	p3 := sign(3, record.PolicyBody{NotAfter: notAfter + 7200000, Redaction: record.PolicyRedact{MinEpoch: 3}})
	if _, err := w.s.StagePolicy(ctx, p3, nil); err != nil || countRows(t, w.s, "SELECT count(*) FROM policy_overlay") != 1 {
		t.Fatal("second stage", err)
	}
	if err := w.s.LogoutTenant(ctx); err != nil && Code(err) != "physical_pending" {
		t.Fatal(err)
	}
	if countRows(t, w.s, "SELECT count(*) FROM policy_overlay") != 0 {
		t.Fatal("logout kept a staged policy body")
	}
}
