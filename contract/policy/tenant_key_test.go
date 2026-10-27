package policy_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/Telara-Labs/hilo/contract/policy"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

const rootAt = int64(1761150000000)

func rootKey(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("policy-root-test/" + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func rootPub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func signedPolicy(t *testing.T, signer ed25519.PrivateKey, tenant string) (*record.Record, []record.Signature) {
	t.Helper()
	b := record.PolicyBody{Tenant: tenant, Seq: 1, IssuedAt: rootAt, RefreshAfter: rootAt + 86400000, NotAfter: rootAt + 7*86400000,
		Applies: record.PolicyApplies{Users: []string{"*"}}, Push: record.PolicyPush{MaxProfile: "push-metadata"}}
	h := record.Header{Type: record.KindPolicy, LID: record.PolicyLID(tenant), Author: record.Author{KeyID: sig.KeyID(rootPub(signer))},
		At: rootAt, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}
	r, err := record.Build(h, &b)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sig.SignRecord(signer, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return r, []record.Signature{s}
}

// A policy verifies only under a policy key activated by a tenant_key root
// with exactly one subject possession signature, empty parents and a matching
// TLS login pin. Every refused root leaves the policy unverifiable.
func TestPolicyRequiresPinnedTenantKeyRoot(t *testing.T) {
	tpk := rootKey("tpk")
	other := rootKey("other")
	pinned := sig.TrustedIssuer{Tenant: "acme", Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin}
	cases := []struct {
		name      string
		signers   []ed25519.PrivateKey
		fromLogin bool
		issuer    sig.TrustedIssuer
		ok        bool
	}{
		{"pinned root", []ed25519.PrivateKey{tpk}, true, pinned, true},
		{"zero signatures", nil, true, pinned, false},
		{"two signatures", []ed25519.PrivateKey{tpk, other}, true, pinned, false},
		{"foreign signature", []ed25519.PrivateKey{other}, true, pinned, false},
		{"not from login", []ed25519.PrivateKey{tpk}, false, pinned, false},
		{"admission instead of TLS", []ed25519.PrivateKey{tpk}, true, sig.TrustedIssuer{Tenant: "acme", Role: record.RolePolicy, Provenance: sig.AuthenticatedAdmission}, false},
		{"pin names another tenant", []ed25519.PrivateKey{tpk}, true, sig.TrustedIssuer{Tenant: "globex", Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin}, false},
		{"pin names the service role", []ed25519.PrivateKey{tpk}, true, sig.TrustedIssuer{Tenant: "acme", Role: record.RoleService, Provenance: sig.PinnedTLSLogin}, false},
	}
	r, s := signedPolicy(t, tpk, "acme")
	for _, c := range cases {
		op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(rootPub(tpk), record.RolePolicy, ""), Genesis: "acme"}, rootPub(tpk), "", rootAt, c.signers...)
		if err != nil {
			t.Fatal(err)
		}
		op.FromLogin = c.fromLogin
		op.Issuer = c.issuer
		kr := sig.NewKeyring("")
		res := sig.VerifyKeyOp(kr, op)
		if (res.Status == sig.OpAuthorized) != c.ok {
			t.Fatalf("%s: root status %s", c.name, res.Status)
		}
		_, err = policy.Verify(r, s, kr.State(), pinned)
		if (err == nil) != c.ok {
			t.Fatalf("%s: policy verify err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
	// A service-role tenant_key, even when pinned, never verifies a policy.
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(rootPub(tpk), record.RoleService, ""), Genesis: "acme"}, rootPub(tpk), "", rootAt, tpk)
	if err != nil {
		t.Fatal(err)
	}
	op.FromLogin = true
	op.Issuer = sig.TrustedIssuer{Tenant: "acme", Role: record.RoleService, Provenance: sig.PinnedTLSLogin}
	kr := sig.NewKeyring("")
	if res := sig.VerifyKeyOp(kr, op); res.Status != sig.OpAuthorized {
		t.Fatalf("service root: %+v", res)
	}
	if _, err := policy.Verify(r, s, kr.State(), pinned); err == nil {
		t.Fatal("policy verified under a service key")
	}
}
