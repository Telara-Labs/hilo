package syncnode

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	"github.com/Telara-Labs/hilo/contract/record"
)

// stagingWithoutOverlay is the node store with staging reduced to verification
// alone, as before the effective-policy overlay. It is the negative control.
type stagingWithoutOverlay struct{ *store.Store }

func (s stagingWithoutOverlay) StagePolicy(ctx context.Context, in store.SignedRecord, staged []store.SignedRecord) (bool, error) {
	return s.PolicyRelaxes(ctx, in, staged)
}

// x2Mixed is the X2 pair with a committed head p1, B's coverage-pending c1 and
// a mixed policy p2 on the following page.
type x2Mixed struct {
	*x2Pair
	sk, event, chunk string
	notAfter         int64
	p1, p2           record.Envelope
	hc1, hp2         int64
}

func newX2Mixed(t *testing.T) *x2Mixed {
	t.Helper()
	ctx := context.Background()
	x := &x2Mixed{x2Pair: newX2Pair(t)}
	a, b, h := x.a, x.b, x.h
	x.sk = x2SessionKey(t)
	k, _, e := a.chunk(x.sk, "x2_mixed_policy_canary_3f9e", "x2-mixed")
	x.chunk, x.event = k.ID, e
	sign := tenantPolicies(t, a.st, h.tenant)
	x.notAfter = time.Now().Add(time.Hour).UnixMilli()
	x.p1 = sign(1, record.PolicyBody{NotAfter: x.notAfter, Push: record.PolicyPush{MaxProfile: record.ProfilePushMetadata, AllowRepos: []string{"github.com/a/*"}}})
	if _, err := a.st.Append(ctx, signedEnvelope(x.p1)); err != nil {
		t.Fatal("initial policy", err)
	}
	b.at = a.at + 10
	x.hc1 = h.addControl(erasureBy(t, b.key, b.machine, "x2m-c1", b.at, record.Selectors{IDs: []string{k.ID}}))
	// p2 tightens (sync kill, a blocked repository) and relaxes (later
	// expiry, cloud pull, another allowed repository).
	x.p2 = sign(2, record.PolicyBody{NotAfter: x.notAfter + 3600000, Kill: record.PolicyKill{Sync: true}, BlockedRepos: []record.BlockedRepo{{RemoteGlob: "github.com/new/*", Effect: "no-capture"}}, Push: record.PolicyPush{MaxProfile: record.ProfilePushMetadata, AllowRepos: []string{"github.com/a/*", "github.com/b/*"}}, Readback: record.PolicyReadback{CloudPull: true}})
	return x
}

// policyNow is what capture, disclosure, push and pull read from the store.
type policyNow struct {
	headID string
	body   *record.PolicyBody
	push   store.SyncPolicy
	pull   bool
}

func readPolicy(t *testing.T, st *store.Store, dir string) policyNow {
	t.Helper()
	ctx := context.Background()
	var p policyNow
	var err error
	if p.headID, p.body, err = st.CapturePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	if p.push, err = st.SyncPushPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	d, err := store.Inspect(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	p.pull = d.Policy.DataPull
	return p
}

// X2 c1 → mixed policy → c2. The mixed policy's tightened fields take effect
// at once as the intersection with the committed head, for capture,
// disclosure, push and pull, and stay in effect across restart while the
// policy is staged; its relaxed fields do not, and the head keeps its id and
// sequence. B's supplement completes c1, the policy commits normally and its
// relaxations take effect.
func TestX2MixedPolicyTightensAtOnceAndRelaxesOnlyAfterSupplement(t *testing.T) {
	x := newX2Mixed(t)
	a, b, h := x.a, x.b, x.h
	wa := a.worker()
	x2Round(t, wa, ErrControlBlocked)
	x.heldBelow(t, wa, "c1", 0, x.hc1)
	if p := readPolicy(t, a.st, a.dir); !p.push.DataPush || !p.pull || p.body.Kill.Sync {
		t.Fatalf("fixture head already restricts: %+v", p.push)
	}

	x.hp2 = h.addControl(x.p2)
	check := func(stage string) {
		t.Helper()
		p := readPolicy(t, a.st, a.dir)
		switch {
		case p.headID != x.p1.ID:
			t.Fatalf("%s: head identity changed while staged", stage)
		case !p.body.Kill.Sync || !slices.Contains(p.body.BlockedRepos, record.BlockedRepo{RemoteGlob: "github.com/new/*", Effect: "no-capture"}):
			t.Fatalf("%s: tightened fields not in effect for capture/disclosure: %+v", stage, p.body)
		case p.push.DataPush || !p.push.CancelOutbox:
			t.Fatalf("%s: tightened kill not in effect for push: %+v", stage, p.push)
		case p.pull:
			t.Fatalf("%s: tightened kill not in effect for pull", stage)
		case p.body.NotAfter != x.notAfter || p.body.Readback.CloudPull || slices.Contains(p.body.Push.AllowRepos, "github.com/b/*"):
			t.Fatalf("%s: relaxed field in effect while staged: %+v", stage, p.body)
		case p.body.Seq != 1:
			t.Fatalf("%s: effective sequence %d", stage, p.body.Seq)
		}
	}
	x2Round(t, wa, ErrControlBlocked)
	x.heldBelow(t, wa, "mixed policy", 0, x.hc1)
	if n := count(t, wa, "SELECT count(*) FROM ctl_pending WHERE hseq=? AND reason='staged'", x.hp2); n != 1 {
		t.Fatalf("mixed policy not staged: %d", n)
	}
	check("staged")
	wa = a.restart(wa)
	check("restart before a round")
	x2Round(t, wa, ErrControlBlocked)
	x.heldBelow(t, wa, "after restart", 0, x.hc1)
	check("restart after a round")
	wa = a.restart(wa)

	c2 := erasureBy(t, b.key, b.machine, "x2m-c2", b.at+1, record.Selectors{Events: []record.EventSelector{{Owner: a.genesis, SessionKey: x.sk, EventID: x.event}}})
	hc2 := h.addControl(c2)
	x2Round(t, wa, nil)
	if c := cursorsOf(t, wa, x.pa); c.Ctl != hc2 || c.BarrierHSeq != 0 {
		t.Fatalf("supplement did not complete the contiguous prefix: %+v", c)
	}
	if ack := x.lastAck(t); ack.CtlEnforcedThrough != hc2 {
		t.Fatalf("A final ack %+v", ack)
	}
	p := readPolicy(t, a.st, a.dir)
	if p.headID != x.p2.ID || p.body.Seq != 2 || p.body.NotAfter != x.notAfter+3600000 || !p.body.Readback.CloudPull || !slices.Contains(p.body.Push.AllowRepos, "github.com/b/*") || !p.body.Kill.Sync || p.push.DataPush {
		t.Fatalf("staged policy not committed after c2: head %s %+v", p.headID[:8], p.body)
	}
	if ownerBlocked(a.st) || erasurePending(t, a.dir) != 0 {
		t.Fatal("owner still blocked after supplement")
	}
	wa = a.restart(wa)
	if p := readPolicy(t, a.st, a.dir); p.headID != x.p2.ID || !p.body.Readback.CloudPull {
		t.Fatal("restart changed the committed policy")
	}
}

// Negative control: the same sequence with staging reduced to verification,
// as before the overlay, leaves the tightened fields unenforced while the
// policy is staged. The overlay assertions above therefore detect its loss.
func TestX2MixedPolicyWithoutOverlayLeavesRestrictionUnenforced(t *testing.T) {
	x := newX2Mixed(t)
	a, h := x.a, x.h
	wk, err := NewWorker(context.Background(), Config{Dir: a.dir, Store: stagingWithoutOverlay{a.st}, Signer: a.keys, Vault: a.vault, TLSRoots: h.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MaxRetry: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wk.state.Close() })
	x2Round(t, wk, ErrControlBlocked)
	x.hp2 = h.addControl(x.p2)
	x2Round(t, wk, ErrControlBlocked)
	x.heldBelow(t, wk, "mixed policy", 0, x.hc1)
	if n := count(t, wk, "SELECT count(*) FROM ctl_pending WHERE hseq=? AND reason='staged'", x.hp2); n != 1 {
		t.Fatalf("mixed policy not staged: %d", n)
	}
	p := readPolicy(t, a.st, a.dir)
	if p.headID != x.p1.ID {
		t.Fatal("head changed")
	}
	if p.body.Kill.Sync || !p.push.DataPush || !p.pull {
		t.Fatal("negative control enforced the restriction without an overlay; the positive test proves nothing")
	}
}
