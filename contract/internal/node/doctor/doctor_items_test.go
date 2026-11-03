//go:build darwin || linux

package doctor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	"github.com/Telara-Labs/hilo/contract/internal/node/syncnode"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

// Each test below plants one doctor condition on a real store and asserts
// the reported state. Conditions already covered elsewhere in this package:
// signing backlog (TestDoctorSigningBacklog), hook trust and capture gaps
// (TestDoctorHookTrustCaptureGapsAndSpool, TestDoctorReportsSpoolGaps),
// scrub state (TestDoctorScrubState), refresh-due policy, sync kill and
// enrollment blockers (TestDoctorPolicyStaleKillAndSyncBlockers).

// An installed identity that no longer parses and a custody record that is
// not a regular file are reported as such, never as present.
func TestDoctorKeyStorePlantedCustodyFaults(t *testing.T) {
	n := newNode(t)
	if r := n.doctor(); r.KeyStore.InstalledProfile != "present" || has(r.Problems, "key_store_installed_identity_unreadable") {
		t.Fatalf("clean key store %+v %v", r.KeyStore, r.Problems)
	}
	authority := filepath.Join(n.paths.Data, "installed-authority.json")
	if _, err := os.Lstat(authority); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authority, []byte("not an identity"), 0600); err != nil {
		t.Fatal(err)
	}
	custody := filepath.Join(n.paths.Data, "custody-location.json")
	_ = os.Remove(custody)
	if err := os.Mkdir(custody, 0700); err != nil {
		t.Fatal(err)
	}
	r := n.doctor()
	if r.KeyStore.InstalledProfile != "unreadable" || !has(r.Problems, "key_store_installed_identity_unreadable") {
		t.Fatalf("installed identity %+v %v", r.KeyStore, r.Problems)
	}
	if r.KeyStore.CustodyRecord != "unsafe" || !has(r.Problems, "key_store_custody_record_unsafe") {
		t.Fatalf("custody record %+v %v", r.KeyStore, r.Problems)
	}
	var text bytes.Buffer
	if err := WriteText(&text, r); err != nil || !strings.Contains(text.String(), "unreadable") || strings.Contains(text.String(), "not an identity") {
		t.Fatal("key store faults not rendered safely", err, text.String())
	}
}

// installPolicy pins a tenant policy key and admits one signed policy body.
func installPolicy(t *testing.T, st *store.Store, b *record.PolicyBody) {
	t.Helper()
	ctx := context.Background()
	policyKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{64}, 32))
	pub := policyKey.Public().(ed25519.PublicKey)
	root, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(pub, record.RolePolicy, ""), Genesis: b.Tenant}, pub, "", b.IssuedAt, policyKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.InstallTenantPolicyContext(ctx, store.TenantPolicyContext{Tenant: b.Tenant, UserID: "doctor-user", Origin: "https://tenant.example", Root: store.SignedRecord{HeaderJCS: root.Rec.HeaderJCS, BodyJCS: root.Rec.BodyJCS, Sigs: root.Sigs, AdvisoryID: root.Rec.ID}}); err != nil {
		t.Fatal(err)
	}
	b.Applies.Users = []string{"doctor-user"}
	pr, err := record.Build(record.Header{Type: record.KindPolicy, LID: record.PolicyLID(b.Tenant), At: b.IssuedAt, Author: record.Author{KeyID: sig.KeyID(pub)}, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, b)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := sig.SignRecord(policyKey, pr.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.Append(ctx, store.SignedRecord{HeaderJCS: pr.HeaderJCS, BodyJCS: pr.BodyJCS, Sigs: []record.Signature{sg}, AdvisoryID: pr.ID}); err != nil {
		t.Fatal(err)
	}
}

// A policy whose capture kill switch is set marks capture incomplete. When
// the persisted trusted-time floor is later than the wall clock, policy
// evaluation is a rollback and fails closed, which also blocks a configured
// sync profile.
func TestDoctorPolicyKillCaptureRollbackAndSyncBlocker(t *testing.T) {
	st, dir, _ := standalone(t)
	ctx := context.Background()
	now := time.Now().UnixMilli()
	installPolicy(t, st, &record.PolicyBody{Tenant: "tenant-rollback", Seq: 1, IssuedAt: now - 1000, NotAfter: now + 3600000, Kill: record.PolicyKill{CaptureTenantRepos: true}})
	if err := writeInstalledIdentity(dir, st); err != nil {
		t.Fatal(err)
	}
	if _, err := syncnode.CreateKey(ctx, dir, &memVault{}); err != nil {
		t.Fatal(err)
	}
	r, err := Run(ctx, Config{DataDir: dir, ProbeTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Policy.Installed || r.Policy.Freshness != "fresh" || r.Policy.Stale || r.Policy.FailClosed || !r.Policy.KillCapture {
		t.Fatalf("fresh policy %+v", r.Policy)
	}
	if !has(r.Capture.Reasons, "policy_kill_capture") || !r.Capture.Incomplete || !has(r.Problems, "policy_kill_switch") {
		t.Fatalf("capture kill %+v %v", r.Capture, r.Problems)
	}
	if has(r.Sync.Blockers, "policy_fresh") || has(r.Sync.Blockers, "policy_rollback") {
		t.Fatalf("fresh policy blocked sync %+v", r.Sync)
	}
	setFloor(t, dir, now+24*3600000)
	r, err = Run(ctx, Config{DataDir: dir, ProbeTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if r.Policy.Freshness != "rollback" || !r.Policy.Stale || !r.Policy.FailClosed || !has(r.Problems, "policy_rollback") {
		t.Fatalf("rolled back policy %+v %v", r.Policy, r.Problems)
	}
	if !has(r.Sync.Blockers, "policy_rollback") || !has(r.Problems, "sync_blocked:policy_rollback") {
		t.Fatalf("sync not blocked by fail-closed policy %+v %v", r.Sync, r.Problems)
	}
}

// A policy admitted while current and then past not_after is expired.
func TestDoctorPolicyExpired(t *testing.T) {
	st, dir, _ := standalone(t)
	ctx := context.Background()
	now := time.Now().UnixMilli()
	installPolicy(t, st, &record.PolicyBody{Tenant: "tenant-expired", Seq: 1, IssuedAt: now - 7200000, NotAfter: now - 3600000})
	r, err := Run(ctx, Config{DataDir: dir, ProbeTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if r.Policy.Freshness != "expired" || !r.Policy.Stale || !r.Policy.FailClosed || !has(r.Problems, "policy_expired") {
		t.Fatalf("expired policy %+v %v", r.Policy, r.Problems)
	}
}

// setFloor moves the persisted trusted-time floor, as a later trusted
// observation would have.
func setFloor(t *testing.T, dir string, at int64) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "memory.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("UPDATE trusted_time SET floor=? WHERE singleton=1", at); err != nil {
		t.Fatal(err)
	}
}

// A stored policy head that no longer parses cannot be evaluated. Doctor
// reports the evaluation code, fails closed and blocks a configured sync
// profile with it.
func TestDoctorPolicyEvaluationFailureBlocksSync(t *testing.T) {
	st, dir, _ := standalone(t)
	ctx := context.Background()
	now := time.Now().UnixMilli()
	installPolicy(t, st, &record.PolicyBody{Tenant: "tenant-corrupt", Seq: 1, IssuedAt: now - 1000, NotAfter: now + 3600000})
	if err := writeInstalledIdentity(dir, st); err != nil {
		t.Fatal(err)
	}
	if _, err := syncnode.CreateKey(ctx, dir, &memVault{}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "memory.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE tenant_policy SET header=? WHERE tenant=?", []byte("{}"), "tenant-corrupt"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	r, err := Run(ctx, Config{DataDir: dir, ProbeTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	code := r.Policy.EvaluationCode
	if code == "" || !r.Policy.FailClosed || !has(r.Problems, "policy_"+code) {
		t.Fatalf("evaluation failure %+v %v", r.Policy, r.Problems)
	}
	if !has(r.Sync.Blockers, "policy_"+code) || !has(r.Problems, "sync_blocked:policy_"+code) {
		t.Fatalf("sync not blocked by unevaluable policy %+v %v", r.Sync, r.Problems)
	}
}
