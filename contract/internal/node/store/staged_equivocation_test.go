package store

import (
	"context"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/policy"
	"github.com/Telara-Labs/hilo/contract/record"
)

// relogin installs the tenant authority again with the root installTenant
// pinned, as a later validated login of the same tenant would.
func relogin(t *testing.T, w *world, tenant string) {
	t.Helper()
	var root SignedRecord
	if err := w.s.write(context.Background(), func() error {
		var h, b, sg []byte
		if err := w.s.conn.QueryRowContext(context.Background(), "SELECT header,body,sigs FROM tenant_key WHERE tenant=? AND login=1", tenant).Scan(&h, &b, &sg); err != nil {
			return err
		}
		root = SignedRecord{HeaderJCS: h, BodyJCS: b, Sigs: decodeSignatures(sg)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r, err := record.Parse(root.HeaderJCS, root.BodyJCS, "")
	if err != nil {
		t.Fatal(err)
	}
	root.AdvisoryID = r.ID
	if err = w.s.InstallTenantPolicyContext(context.Background(), TenantPolicyContext{Tenant: tenant, UserID: "fixture-user", Origin: "https://tenant.example", Root: root}); err != nil {
		t.Fatal(err)
	}
}

// chainOf reports the committed chain as admission loads it, with the
// recorded equivocation facts applied.
func chainOf(t *testing.T, s *Store) (seq int64, id string, tampered bool, fresh policy.Freshness) {
	t.Helper()
	ctx := context.Background()
	if err := s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if d.tenant == nil {
			if d.tenant, err = s.tenant(ctx); err != nil {
				return err
			}
		}
		if d.tenant == nil {
			return failure("policy_context_required")
		}
		seq, id, tampered, fresh = d.tenant.chain.HighestSeq, d.tenant.chain.HighestID, d.tenant.chain.Tampered, d.tenant.freshness
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return
}

// Two distinct relaxing policies with one sequence, both staged behind a
// coverage-pending erasure above committed sequence 1, are an equivocation.
// Staging the second latches it durably at once, with neither policy's
// permissions live, and the fact survives restart and logout. Re-login and
// ordinary commit of either policy at that sequence stay latched; only a
// higher committed sequence clears it.
func TestStagedEquivocationLatchesAtOnceThroughRestartAndLogout(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	const tenant = "tenant-equivocation"
	sign := installTenant(t, w, tenant)
	notAfter := time.Now().Add(time.Hour).UnixMilli()
	push := record.PolicyPush{MaxProfile: record.ProfilePushMetadata, AllowRepos: []string{"github.com/a/*"}}
	p1 := sign(1, record.PolicyBody{NotAfter: notAfter, Push: push})
	if _, err := w.s.Append(ctx, p1); err != nil {
		t.Fatal(err)
	}
	// Both relax p1, differently.
	p2a := sign(2, record.PolicyBody{NotAfter: notAfter + 1000, Push: push, Readback: record.PolicyReadback{CloudPull: true}})
	p2b := sign(2, record.PolicyBody{NotAfter: notAfter + 2000, Push: push, Readback: record.PolicyReadback{HookInjection: true}})
	if p2a.AdvisoryID == p2b.AdvisoryID {
		t.Fatal("fixture policies share an id")
	}
	if e := effectiveOf(t, w.s, p1.AdvisoryID); !e.pull || !e.push.DataPush {
		t.Fatalf("fixture head does not allow data: %+v", e)
	}
	facts := func() int {
		return countRows(t, w.s, "SELECT count(*) FROM policy_equivocation WHERE tenant=? AND seq=2", tenant)
	}

	if relaxes, err := w.s.StagePolicy(ctx, p2a, nil); err != nil || !relaxes {
		t.Fatal("stage first", relaxes, err)
	}
	if _, _, tampered, _ := chainOf(t, w.s); tampered || facts() != 0 {
		t.Fatal("a single staged policy latched")
	}
	staged := []SignedRecord{p2a}
	// Verification alone writes nothing.
	if relaxes, err := w.s.PolicyRelaxes(ctx, p2b, staged); err != nil || !relaxes || facts() != 0 {
		t.Fatal("verification recorded a fact", relaxes, err, facts())
	}
	if relaxes, err := w.s.StagePolicy(ctx, p2b, staged); err != nil || !relaxes {
		t.Fatal("stage second", relaxes, err)
	}
	if facts() != 2 || countRows(t, w.s, "SELECT count(*) FROM policy_equivocation WHERE tenant=? AND seq=2 AND id IN(?,?)", tenant, p2a.AdvisoryID, p2b.AdvisoryID) != 2 {
		t.Fatal("staged equivocation not recorded", facts())
	}
	check := func(stage string) {
		t.Helper()
		seq, id, tampered, fresh := chainOf(t, w.s)
		if seq != 1 || id != p1.AdvisoryID {
			t.Fatalf("%s: equivocation moved the committed chain: %d %s", stage, seq, id)
		}
		if !tampered || fresh != policy.TamperedHead {
			t.Fatalf("%s: equivocation not latched: %v %v", stage, tampered, fresh)
		}
		e := effectiveOf(t, w.s, p1.AdvisoryID)
		if e.pull || e.push.DataPush {
			t.Fatalf("%s: data allowed while latched: %+v", stage, e.push)
		}
		if countRows(t, w.s, "SELECT count(*) FROM tenant_policy WHERE id IN(?,?)", p2a.AdvisoryID, p2b.AdvisoryID) != 0 {
			t.Fatalf("%s: a staged policy was committed", stage)
		}
	}
	check("staged")
	// Restaging either is idempotent.
	if _, err := w.s.StagePolicy(ctx, p2b, staged); err != nil || facts() != 2 {
		t.Fatal("restage", err)
	}
	reopenStore(t, &w.s, w.o)
	check("after restart")

	// Logout drops every staged envelope and overlay, but not the facts.
	if err := w.s.LogoutTenant(ctx); err != nil && Code(err) != "physical_pending" {
		t.Fatal(err)
	}
	if countRows(t, w.s, "SELECT count(*) FROM policy_overlay") != 0 || facts() != 2 {
		t.Fatal("logout lost the equivocation facts or kept an overlay", facts())
	}
	reopenStore(t, &w.s, w.o)
	relogin(t, w, tenant)
	if _, _, tampered, _ := chainOf(t, w.s); !tampered {
		t.Fatal("re-login cleared the latch")
	}
	// Ordinary commit of one of the equivocating policies stays latched.
	if _, err := w.s.Append(ctx, p2a); err != nil {
		t.Fatal(err)
	}
	if seq, id, tampered, fresh := chainOf(t, w.s); seq != 2 || id != p2a.AdvisoryID || !tampered || fresh != policy.TamperedHead {
		t.Fatal("commit at the equivocated sequence cleared the latch", seq, tampered, fresh)
	}
	if e := effectiveOf(t, w.s, p2a.AdvisoryID); e.pull || e.push.DataPush {
		t.Fatal("data allowed at the equivocated sequence")
	}
	// The other one is the ordinary equal-sequence equivocation.
	if res, err := w.s.Append(ctx, p2b); err != nil || res.State != policy.Tamper {
		t.Fatal(res, err)
	}
	reopenStore(t, &w.s, w.o)
	if _, _, tampered, _ := chainOf(t, w.s); !tampered {
		t.Fatal("restart cleared the latch")
	}
	// Only a higher verified sequence clears it.
	p3 := sign(3, record.PolicyBody{NotAfter: notAfter, Push: push})
	if _, err := w.s.Append(ctx, p3); err != nil {
		t.Fatal(err)
	}
	if seq, _, tampered, _ := chainOf(t, w.s); seq != 3 || tampered {
		t.Fatal("higher sequence did not clear the latch", seq, tampered)
	}
	if e := effectiveOf(t, w.s, p3.AdvisoryID); !e.pull || !e.push.DataPush {
		t.Fatalf("data still blocked after the latch cleared: %+v", e.push)
	}
}

// A staged policy that equivocates with the committed head records the fact
// in the staging transaction itself, before ordinary admission sees it.
func TestStagedEquivocationWithCommittedHeadRecordsAtOnce(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	const tenant = "tenant-head-equivocation"
	sign := installTenant(t, w, tenant)
	notAfter := time.Now().Add(time.Hour).UnixMilli()
	p1 := sign(1, record.PolicyBody{NotAfter: notAfter})
	if _, err := w.s.Append(ctx, p1); err != nil {
		t.Fatal(err)
	}
	other := sign(1, record.PolicyBody{NotAfter: notAfter + 1000})
	if relaxes, err := w.s.StagePolicy(ctx, other, nil); err != nil || relaxes {
		t.Fatal("equal-sequence offer reported a relaxation", relaxes, err)
	}
	if countRows(t, w.s, "SELECT count(*) FROM policy_equivocation WHERE tenant=? AND seq=1", tenant) != 2 {
		t.Fatal("equivocation with the committed head not recorded")
	}
	if seq, id, tampered, _ := chainOf(t, w.s); seq != 1 || id != p1.AdvisoryID || !tampered {
		t.Fatal("not latched", seq, tampered)
	}
}

// A policy above the committed chain but below a staged successor is a
// rollback in log order. It stays staged and supplies nothing, not even an
// overlay, and records no equivocation.
func TestStagedRollbackBehindStagedSuccessorSuppliesNothing(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	sign := installTenant(t, w, "tenant-staged-rollback")
	notAfter := time.Now().Add(time.Hour).UnixMilli()
	p1 := sign(1, record.PolicyBody{NotAfter: notAfter})
	if _, err := w.s.Append(ctx, p1); err != nil {
		t.Fatal(err)
	}
	p3 := sign(3, record.PolicyBody{NotAfter: notAfter + 1000})
	if relaxes, err := w.s.StagePolicy(ctx, p3, nil); err != nil || !relaxes {
		t.Fatal(relaxes, err)
	}
	// p2 is restrictive against the committed head, so without sequence
	// reduction it would be committed at once ahead of its staged successor.
	p2 := sign(2, record.PolicyBody{NotAfter: notAfter - 1000})
	if relaxes, err := w.s.PolicyRelaxes(ctx, p2, nil); err != nil || relaxes {
		t.Fatal("fixture policy is not restrictive", relaxes, err)
	}
	if relaxes, err := w.s.StagePolicy(ctx, p2, []SignedRecord{p3}); err != nil || !relaxes {
		t.Fatal("rollback behind a staged successor would commit", relaxes, err)
	}
	if countRows(t, w.s, "SELECT count(*) FROM policy_overlay WHERE id=?", p2.AdvisoryID) != 0 || countRows(t, w.s, "SELECT count(*) FROM policy_equivocation") != 0 {
		t.Fatal("staged rollback supplied an overlay or a fact")
	}
}
