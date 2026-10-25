package policy_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/policy"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

func fuzzTPK() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("mnc-fuzz-key/TPK"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func tenantState(tb testing.TB, tpk ed25519.PrivateKey, tenant string) (*sig.State, bool) {
	tb.Helper()
	pub := tpk.Public().(ed25519.PublicKey)
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(pub, record.RolePolicy, ""), Genesis: tenant}, pub, "", 1761150000000, tpk)
	if err != nil {
		return nil, false
	}
	op.FromLogin = true
	op.Issuer = sig.TrustedIssuer{Tenant: tenant, Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin}
	kr := sig.NewKeyring("")
	if r := sig.VerifyKeyOp(kr, op); r.Status != sig.OpAuthorized {
		return nil, false
	}
	return kr.State(), true
}

// policyHeader frames arbitrary body bytes as a policy record header so the
// admission decoder, not a typed constructor, decides what is accepted.
func policyHeader(tpk ed25519.PrivateKey, body []byte) ([]byte, string, bool) {
	var probe struct {
		Tenant   string `json:"tenant"`
		IssuedAt int64  `json:"issued_at"`
	}
	if json.Unmarshal(body, &probe) != nil {
		return nil, "", false
	}
	h := record.Header{V: record.Version, Type: record.KindPolicy, LID: record.PolicyLID(probe.Tenant),
		Author: record.Author{KeyID: sig.KeyID(tpk.Public().(ed25519.PublicKey))}, At: probe.IssuedAt, Prov: record.ProvUser,
		Red: record.Redact{Profile: record.ProfileLocal}, Body: &record.BodyRef{Digest: record.BodyDigest(body), Size: int64(len(body))}}
	raw, err := jcs.MarshalRecord(&h)
	if err != nil {
		return nil, "", false
	}
	return raw, probe.Tenant, true
}

func addPolicySeeds(f *testing.F) {
	raw, err := os.ReadFile("../testdata/v03-records.json")
	if err != nil {
		f.Fatal(err)
	}
	var fs []struct{ HeaderJCS, BodyJCS string }
	if err := json.Unmarshal(raw, &fs); err != nil {
		f.Fatal(err)
	}
	for _, x := range fs {
		if strings.Contains(x.HeaderJCS, `"type":"policy"`) {
			f.Add([]byte(x.BodyJCS))
		}
	}
	t0 := int64(1761150000000)
	for _, b := range []record.PolicyBody{
		{Tenant: "acme", Seq: 2, IssuedAt: t0, RefreshAfter: t0 + 86400000, NotAfter: t0 + 7*86400000,
			Applies: record.PolicyApplies{Users: []string{"*"}}, Push: record.PolicyPush{MaxProfile: "push-metadata", AllowRepos: []string{"github.com/acme/*"}},
			BlockedRepos: []record.BlockedRepo{{RemoteGlob: "github.com/acme/secret", Effect: "no-push"}}},
		{Tenant: "acme", Seq: 3, IssuedAt: t0, NotAfter: t0 + 1, Applies: record.PolicyApplies{Users: []string{"*"}}, Kill: record.PolicyKill{Sync: true, WithdrawPulled: true}},
	} {
		h := record.Header{Type: record.KindPolicy, LID: record.PolicyLID(b.Tenant), Author: record.Author{KeyID: sig.KeyID(fuzzTPK().Public().(ed25519.PublicKey))},
			At: b.IssuedAt, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}
		r, err := record.Build(h, &b)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(r.BodyJCS)
	}
	base := `"issued_at":1761150000456,"not_after":1761236400456,"salt":"whtCSgsWyAlkLzsV0Be2Wg","seq":1,"tenant":"acme"`
	f.Add([]byte(`{"applies":{"users":["*"]},"blocked_repos":[{"effect":"no-push","remote_glob":"github.com/acme/secret"}],` + base + `}`))
	f.Add([]byte(`{"applies":{"users":["*"]},"push":{"allow_repos":["github.com/acme/*"],"max_profile":"push-metadata"},"refresh_after":1761200000000,` + base + `}`))
	f.Add([]byte(`{"applies":{"users":["*"]},"kill":{"sync":true},` + base + `}`))
	f.Add([]byte(`{"applies":{"users":["*"]},"push":{"allow_repos":["` + strings.Repeat("a", 1<<16) + `"]},` + base + `}`))
	many := make([]string, 4096)
	for i := range many {
		many[i] = `"github.com/acme/r` + strings.Repeat("x", i%64) + `"`
	}
	f.Add([]byte(`{"applies":{"users":[` + strings.Join(many, ",") + `]},` + base + `}`))
	f.Add([]byte(`{"applies":{"users":["*"]},"unknown":{"deep":[[[[1]]]]},` + base + `}`))
	f.Add([]byte(`{"applies":{"users":["*"]},"issued_at":1,"not_after":0,"salt":"","seq":-1,"tenant":""}`))
}

// FuzzPolicyDecode admits arbitrary policy body bytes. Accepted bodies
// round-trip byte for byte, verify only under their own tenant's pinned
// policy key, never verify after mutation, and evaluate without panics.
func FuzzPolicyDecode(f *testing.F) {
	addPolicySeeds(f)
	tpk := fuzzTPK()
	f.Fuzz(func(t *testing.T, body []byte) {
		header, tenant, ok := policyHeader(tpk, body)
		if !ok {
			return
		}
		start := time.Now()
		r, err := record.Parse(header, body, "")
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("policy decode took %v", d)
		}
		if err != nil {
			return
		}
		b, isPolicy := r.Body.(*record.PolicyBody)
		if !isPolicy {
			t.Fatal("policy header decoded a non-policy body")
		}
		again, err := jcs.MarshalRecord(b)
		if err != nil || !bytes.Equal(again, body) {
			t.Fatal("policy decode-encode round trip differs")
		}
		if err := record.ValidatePolicyShape(b); err != nil {
			t.Fatalf("admitted policy fails its shape check: %v", err)
		}
		st, ok := tenantState(t, tpk, tenant)
		if !ok {
			return
		}
		s, err := sig.SignRecord(tpk, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		issuer := sig.TrustedIssuer{Tenant: tenant, Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin}
		p, err := policy.Verify(r, []record.Signature{s}, st, issuer)
		if err != nil {
			t.Fatalf("admitted, correctly signed policy refused: %v", err)
		}
		other := issuer
		other.Tenant = tenant + "-other"
		if _, err := policy.Verify(r, []record.Signature{s}, st, other); err == nil {
			t.Fatal("policy verified under another tenant")
		}
		mutated := append([]byte(nil), body...)
		mutated[len(mutated)/2] ^= 0x01
		if _, err := policy.Verify(&record.Record{ID: r.ID, HeaderJCS: header, BodyJCS: mutated}, []record.Signature{s}, st, issuer); err == nil {
			t.Fatal("mutated policy body verified")
		}
		c := policy.NewChain(tenant)
		if out, err := c.Offer(p); err != nil || out != policy.Accepted {
			t.Fatalf("first offer %s %v", out, err)
		}
		if out, err := c.Offer(p); err != nil || out != policy.Duplicate {
			t.Fatalf("second offer %s %v", out, err)
		}
		for _, at := range []int64{0, b.IssuedAt, b.RefreshAfter, b.NotAfter, jcs.MaxSafeInteger} {
			fresh := policy.Evaluate(c, policy.RestoreClock(0), at, false)
			_ = policy.EffectsOf(c, fresh)
		}
		_ = policy.MaxProfile(b)
		_ = policy.PushAllowed(b, "github.com/acme/api")
		_ = policy.RepoBlocked(b, "github.com/acme/api", "no-push")
		_ = policy.AppliesTo(b, "user")
	})
}
