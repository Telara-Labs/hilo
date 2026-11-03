package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

func rootKeyFixture(seed byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	return k, k.Public().(ed25519.PublicKey)
}

func signedRoot(t *testing.T, b record.KeyOpBody, author ed25519.PublicKey, signers ...ed25519.PrivateKey) SignedRecord {
	t.Helper()
	op, err := sig.BuildKeyOp(b, author, "", time.Now().UnixMilli(), signers...)
	if err != nil {
		t.Fatal(err)
	}
	return wire(op.Rec, op.Sigs)
}

// craftedRoot encodes canonical key_op bytes that skip authoring validation.
func craftedRoot(t *testing.T, b record.KeyOpBody, signer ed25519.PrivateKey) SignedRecord {
	t.Helper()
	bodyJCS, err := jcs.MarshalRecord(&b)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.Public().(ed25519.PublicKey)
	h := record.Header{V: record.Version, Type: record.KindKeyOp, LID: record.KeyLID(b.Subject.KeyID), Author: record.Author{KeyID: sig.KeyID(pub)},
		At: time.Now().UnixMilli(), Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}, Body: &record.BodyRef{Digest: record.BodyDigest(bodyJCS), Size: int64(len(bodyJCS))}}
	headerJCS, err := jcs.MarshalRecord(&h)
	if err != nil {
		t.Fatal(err)
	}
	id := record.ContentID(headerJCS)
	s, err := sig.SignRecord(signer, id)
	if err != nil {
		t.Fatal(err)
	}
	return SignedRecord{HeaderJCS: headerJCS, BodyJCS: bodyJCS, Sigs: []record.Signature{s}, AdvisoryID: id}
}

func loginPolicy(t *testing.T, signer ed25519.PrivateKey, tenant string) SignedRecord {
	t.Helper()
	pub := signer.Public().(ed25519.PublicKey)
	now := time.Now().UnixMilli()
	b := &record.PolicyBody{Tenant: tenant, Seq: 1, IssuedAt: now - 1000, NotAfter: now + 3600000, Applies: record.PolicyApplies{Users: []string{"fixture-user"}}}
	r, err := record.Build(record.Header{Type: record.KindPolicy, LID: record.PolicyLID(tenant), At: now, Author: record.Author{KeyID: sig.KeyID(pub)}, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, b)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sig.SignRecord(signer, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return wire(r, []record.Signature{s})
}

func tenantAuthorityRows(t *testing.T, w *world) (keys, active int) {
	t.Helper()
	ctx := context.Background()
	if err := w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM tenant_key").Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if err := w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM tenant_context WHERE active=1").Scan(&active); err != nil {
		t.Fatal(err)
	}
	return keys, active
}

// The login TLS response is the only path that installs a tenant root. Each
// tenant_key invariant is refused there with no pin, no active tenant and no
// policy authority left behind.
func TestTenantKeyLoginInstallRefusesBrokenRoots(t *testing.T) {
	ctx := context.Background()
	tpk, tpkPub := rootKeyFixture(71)
	other, _ := rootKeyFixture(72)
	ref := sig.KeyRefOf(tpkPub, record.RolePolicy, "")
	root := record.KeyOpBody{Op: record.OpTenantKey, Subject: ref, Genesis: "tenant-a"}
	withParents := root
	withParents.Parents = []string{strings.Repeat("cd", 32)}
	twoSigs := signedRoot(t, root, tpkPub, tpk)
	extra, err := sig.SignRecord(other, twoSigs.AdvisoryID)
	if err != nil {
		t.Fatal(err)
	}
	twoSigs.Sigs = append(twoSigs.Sigs, extra)
	cases := []struct {
		name   string
		tenant string
		root   SignedRecord
	}{
		{"zero signatures", "tenant-a", signedRoot(t, root, tpkPub)},
		{"two signatures", "tenant-a", twoSigs},
		{"foreign signature only", "tenant-a", signedRoot(t, root, tpkPub, other)},
		{"author is not the subject", "tenant-a", signedRoot(t, root, other.Public().(ed25519.PublicKey), tpk)},
		{"nonempty parents", "tenant-a", craftedRoot(t, withParents, tpk)},
		{"TLS pin names another tenant", "tenant-b", signedRoot(t, root, tpkPub, tpk)},
		{"service role instead of policy", "tenant-a", signedRoot(t, record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tpkPub, record.RoleService, ""), Genesis: "tenant-a"}, tpkPub, tpk)},
	}
	for _, c := range cases {
		w := newWorld(t)
		err := w.s.InstallTenantPolicyContext(ctx, TenantPolicyContext{Tenant: c.tenant, UserID: "fixture-user", Origin: "https://tenant.example", Root: c.root})
		if Code(err) != "invalid_policy_context" {
			t.Fatalf("%s: install = %v", c.name, err)
		}
		if keys, active := tenantAuthorityRows(t, w); keys != 0 || active != 0 {
			t.Fatalf("%s: refused root left %d pins and %d active tenants", c.name, keys, active)
		}
		if _, err := w.s.Append(ctx, loginPolicy(t, tpk, c.tenant)); Code(err) != "policy_context_required" {
			t.Fatalf("%s: policy admitted without a pinned root: %v", c.name, err)
		}
	}
	// Control: the same root with exactly one subject signature and a matching pin.
	w := newWorld(t)
	if err := w.s.InstallTenantPolicyContext(ctx, TenantPolicyContext{Tenant: "tenant-a", UserID: "fixture-user", Origin: "https://tenant.example", Root: signedRoot(t, root, tpkPub, tpk)}); err != nil {
		t.Fatal(err)
	}
	if keys, active := tenantAuthorityRows(t, w); keys != 1 || active != 1 {
		t.Fatalf("pinned root rows %d/%d", keys, active)
	}
	if _, err := w.s.Append(ctx, loginPolicy(t, tpk, "tenant-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.Append(ctx, loginPolicy(t, other, "tenant-a")); Code(err) != "invalid_policy" {
		t.Fatalf("policy by an unpinned key: %v", err)
	}
}

// A second login of the same tenant must present the pinned root; a
// different key is a pin mismatch, before and after logout.
func TestTenantKeyLoginPinMismatchRefused(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	tpk, tpkPub := rootKeyFixture(73)
	swap, swapPub := rootKeyFixture(74)
	first := signedRoot(t, record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tpkPub, record.RolePolicy, ""), Genesis: "tenant-a"}, tpkPub, tpk)
	install := func(root SignedRecord) error {
		return w.s.InstallTenantPolicyContext(ctx, TenantPolicyContext{Tenant: "tenant-a", UserID: "fixture-user", Origin: "https://tenant.example", Root: root})
	}
	if err := install(first); err != nil {
		t.Fatal(err)
	}
	if err := install(first); err != nil {
		t.Fatalf("re-login with the pinned root: %v", err)
	}
	other := signedRoot(t, record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(swapPub, record.RolePolicy, ""), Genesis: "tenant-a"}, swapPub, swap)
	if err := install(other); Code(err) != "tenant_pin_conflict" {
		t.Fatalf("pin mismatch while active: %v", err)
	}
	if err := w.s.LogoutTenant(ctx); err != nil && Code(err) != "physical_pending" {
		t.Fatal(err)
	}
	if err := install(other); Code(err) != "tenant_pin_conflict" {
		t.Fatalf("pin mismatch after logout: %v", err)
	}
	var keys int
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM tenant_key WHERE tenant='tenant-a'").Scan(&keys)
	if keys != 1 {
		t.Fatalf("pin mismatch stored a root: %d", keys)
	}
	if err := install(first); err != nil {
		t.Fatalf("re-login with the pinned root after logout: %v", err)
	}
	if _, err := w.s.Append(ctx, loginPolicy(t, swap, "tenant-a")); Code(err) != "invalid_policy" {
		t.Fatalf("policy by the refused key: %v", err)
	}
}

// tenant_key outside the login response (sync, bundles, the tenant key
// operation path) is ignored: it never pins or activates a tenant key.
func TestTenantKeyOutsideLoginRefused(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	tpk, tpkPub := rootKeyFixture(75)
	var before int
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record").Scan(&before)
	for _, role := range []record.Role{record.RolePolicy, record.RoleService} {
		root := signedRoot(t, record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tpkPub, role, ""), Genesis: "tenant-a"}, tpkPub, tpk)
		if _, err := w.s.Append(ctx, root); Code(err) != "unsupported_context" {
			t.Fatalf("%s tenant_key through admission: %v", role, err)
		}
		w.s.bundleImport = true
		_, err := w.s.Append(ctx, root)
		w.s.bundleImport = false
		if Code(err) != "unsupported_context" {
			t.Fatalf("%s tenant_key through bundle admission: %v", role, err)
		}
		if err := w.s.OfferTenantKeyOperation(ctx, root); Code(err) != "invalid_policy_context" {
			t.Fatalf("%s tenant_key through key operation offer: %v", role, err)
		}
	}
	if keys, active := tenantAuthorityRows(t, w); keys != 0 || active != 0 {
		t.Fatalf("non-login tenant_key left %d pins and %d active tenants", keys, active)
	}
	var after int
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record").Scan(&after)
	if before == 0 || after != before {
		t.Fatalf("non-login tenant_key stored as a record: %d -> %d", before, after)
	}
}
