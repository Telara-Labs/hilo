package sig_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

const tenantKeyAt = int64(1761150000000)

func tenantKeyPriv(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("tenant-key-test/" + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func tenantKeyPub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func loginIssuer(tenant string, role record.Role) sig.TrustedIssuer {
	return sig.TrustedIssuer{Tenant: tenant, Role: role, Provenance: sig.PinnedTLSLogin}
}

// tenantRoot builds an unsigned tenant_key op for subject in tenant.
func tenantRoot(t *testing.T, subject ed25519.PrivateKey, role record.Role, tenant string) *sig.KeyOp {
	t.Helper()
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tenantKeyPub(subject), role, ""), Genesis: tenant}, tenantKeyPub(subject), "", tenantKeyAt)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func signWith(t *testing.T, op *sig.KeyOp, signers ...ed25519.PrivateKey) {
	t.Helper()
	op.Sigs = nil
	for _, k := range signers {
		s, err := sig.SignRecord(k, op.Rec.ID)
		if err != nil {
			t.Fatal(err)
		}
		op.Sigs = append(op.Sigs, s)
	}
}

// craftKeyOp encodes canonical key_op bytes without the authoring validation,
// so the verifier, not the builder, must refuse a malformed body.
func craftKeyOp(t *testing.T, b record.KeyOpBody, author ed25519.PublicKey, machine ...string) *record.Record {
	t.Helper()
	bodyJCS, err := jcs.MarshalRecord(&b)
	if err != nil {
		t.Fatal(err)
	}
	h := record.Header{V: record.Version, Type: record.KindKeyOp, LID: record.KeyLID(b.Subject.KeyID), Author: record.Author{KeyID: sig.KeyID(author), MachineID: strings.Join(machine, "")},
		At: tenantKeyAt, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}, Body: &record.BodyRef{Digest: record.BodyDigest(bodyJCS), Size: int64(len(bodyJCS))}}
	headerJCS, err := jcs.MarshalRecord(&h)
	if err != nil {
		t.Fatal(err)
	}
	return &record.Record{ID: record.ContentID(headerJCS), HeaderJCS: headerJCS, BodyJCS: bodyJCS}
}

func assertNotBound(t *testing.T, kr *sig.Keyring, subject ed25519.PrivateKey, role record.Role, tenant string) {
	t.Helper()
	if k := kr.State().KeyFor(sig.KeyID(tenantKeyPub(subject)), role, tenant); k != nil {
		t.Fatalf("refused tenant_key still activated %s key %s", role, k.KeyID)
	}
}

func TestTenantKeyRootRequiresEmptyParents(t *testing.T) {
	tsk := tenantKeyPriv("tsk")
	for _, role := range []record.Role{record.RoleService, record.RolePolicy} {
		// Control: the crafted encoding of the same root without parents verifies,
		// so the refusals below are caused by the parents alone.
		good := record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tenantKeyPub(tsk), role, ""), Genesis: "acme"}
		goodRec := craftKeyOp(t, good, tenantKeyPub(tsk))
		gs, _ := sig.SignRecord(tsk, goodRec.ID)
		if res := sig.VerifyKeyOp(sig.NewKeyring(""), &sig.KeyOp{Rec: goodRec, Body: &good, Sigs: []record.Signature{gs}, FromLogin: true, Issuer: loginIssuer("acme", role)}); res.Status != sig.OpAuthorized {
			t.Fatalf("%s: crafted control root refused: %+v", role, res)
		}
		parent := strings.Repeat("ab", 32)
		b := record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tenantKeyPub(tsk), role, ""), Genesis: "acme", Parents: []string{parent}}
		if _, err := sig.BuildKeyOp(b, tenantKeyPub(tsk), "", tenantKeyAt, tsk); err == nil {
			t.Fatalf("%s: tenant_key with parents was authored", role)
		}
		rec := craftKeyOp(t, b, tenantKeyPub(tsk))
		if _, err := record.Parse(rec.HeaderJCS, rec.BodyJCS, rec.ID); err == nil {
			t.Fatalf("%s: tenant_key with parents parsed", role)
		}
		s, _ := sig.SignRecord(tsk, rec.ID)
		kr := sig.NewKeyring("")
		res := sig.VerifyKeyOp(kr, &sig.KeyOp{Rec: rec, Body: &b, Sigs: []record.Signature{s}, FromLogin: true, Issuer: loginIssuer("acme", role)})
		if res.Status != sig.OpInvalid || res.Err == nil {
			t.Fatalf("%s: tenant_key with parents = %+v", role, res)
		}
		if len(kr.Ops()) != 0 {
			t.Fatalf("%s: refused op stored", role)
		}
		assertNotBound(t, kr, tsk, role, "acme")
	}
	// The empty-parent exemption belongs to the roots only.
	tsk2 := tenantKeyPriv("tsk2")
	rot := record.KeyOpBody{Op: record.OpTenantKeyRotate, Subject: sig.KeyRefOf(tenantKeyPub(tsk2), record.RoleService, ""), Genesis: "acme", Previous: sig.KeyID(tenantKeyPub(tsk))}
	if _, err := sig.BuildKeyOp(rot, tenantKeyPub(tsk), "", tenantKeyAt, tsk); err == nil {
		t.Fatal("tenant_key_rotate without parents was authored")
	}
	rec := craftKeyOp(t, rot, tenantKeyPub(tsk))
	if _, err := record.Parse(rec.HeaderJCS, rec.BodyJCS, rec.ID); err == nil {
		t.Fatal("tenant_key_rotate without parents parsed")
	}
}

func TestTenantKeyExactlyOnePossessionSignature(t *testing.T) {
	tsk := tenantKeyPriv("tsk")
	other := tenantKeyPriv("other")
	cases := []struct {
		name string
		sign func(op *sig.KeyOp)
	}{
		{"zero signatures", func(op *sig.KeyOp) { op.Sigs = nil }},
		{"empty signature list", func(op *sig.KeyOp) { op.Sigs = []record.Signature{} }},
		{"subject and second key", func(op *sig.KeyOp) { signWith(t, op, tsk, other) }},
		{"second key and subject", func(op *sig.KeyOp) { signWith(t, op, other, tsk) }},
		{"subject twice", func(op *sig.KeyOp) { signWith(t, op, tsk, tsk) }},
		{"only a non-subject key", func(op *sig.KeyOp) { signWith(t, op, other) }},
		{"subject key id over a foreign signature", func(op *sig.KeyOp) {
			signWith(t, op, other)
			op.Sigs[0].KeyID = sig.KeyID(tenantKeyPub(tsk))
		}},
		{"subject signature under another context", func(op *sig.KeyOp) {
			m, err := sig.RecordMessage(op.Rec.ID)
			if err != nil {
				t.Fatal(err)
			}
			op.Sigs = []record.Signature{sig.Sign(tsk, sig.CtxReceipt, m)}
		}},
		{"subject signature tampered", func(op *sig.KeyOp) {
			signWith(t, op, tsk)
			v := []byte(op.Sigs[0].Value)
			if v[0] == 'A' {
				v[0] = 'B'
			} else {
				v[0] = 'A'
			}
			op.Sigs[0].Value = string(v)
		}},
	}
	for _, role := range []record.Role{record.RoleService, record.RolePolicy} {
		for _, c := range cases {
			op := tenantRoot(t, tsk, role, "acme")
			c.sign(op)
			op.FromLogin = true
			op.Issuer = loginIssuer("acme", role)
			kr := sig.NewKeyring("")
			if res := sig.VerifyKeyOp(kr, op); res.Status != sig.OpInvalid || res.Err == nil {
				t.Fatalf("%s/%s: %+v", role, c.name, res)
			}
			if len(kr.Ops()) != 0 {
				t.Fatalf("%s/%s: refused op stored", role, c.name)
			}
			assertNotBound(t, kr, tsk, role, "acme")
			assertNotBound(t, kr, other, role, "acme")
		}
		// Control: exactly one possession signature under Subject.pub, inside login.
		op := tenantRoot(t, tsk, role, "acme")
		signWith(t, op, tsk)
		op.FromLogin = true
		op.Issuer = loginIssuer("acme", role)
		kr := sig.NewKeyring("")
		if res := sig.VerifyKeyOp(kr, op); res.Status != sig.OpAuthorized {
			t.Fatalf("%s: valid tenant_key refused: %+v", role, res)
		}
		k := kr.State().KeyFor(sig.KeyID(tenantKeyPub(tsk)), role, "acme")
		if k == nil || k.Status != sig.KeyActive || k.Tenant != "acme" || k.Role != role || k.MachineID != "" {
			t.Fatalf("%s: tenant key not active: %+v", role, k)
		}
	}
}

func TestTenantKeyRequiresMatchingTLSPin(t *testing.T) {
	tsk := tenantKeyPriv("tsk")
	cases := []struct {
		name      string
		fromLogin bool
		issuer    sig.TrustedIssuer
		want      sig.OpStatus
	}{
		{"signature alone, not from login", false, loginIssuer("acme", record.RoleService), sig.OpIgnored},
		{"no trusted issuer", true, sig.TrustedIssuer{}, sig.OpUnauthorized},
		{"authenticated admission instead of TLS login", true, sig.TrustedIssuer{Tenant: "acme", Role: record.RoleService, Provenance: sig.AuthenticatedAdmission}, sig.OpIgnored},
		{"unknown provenance", true, sig.TrustedIssuer{Tenant: "acme", Role: record.RoleService, Provenance: "bundle"}, sig.OpUnauthorized},
		{"pinned tenant differs from body tenant", true, loginIssuer("globex", record.RoleService), sig.OpUnauthorized},
		{"pinned role differs from subject role", true, loginIssuer("acme", record.RolePolicy), sig.OpUnauthorized},
		{"pinned role is device", true, loginIssuer("acme", record.RoleDevice), sig.OpUnauthorized},
		{"empty pinned tenant", true, sig.TrustedIssuer{Role: record.RoleService, Provenance: sig.PinnedTLSLogin}, sig.OpUnauthorized},
	}
	for _, c := range cases {
		op := tenantRoot(t, tsk, record.RoleService, "acme")
		signWith(t, op, tsk)
		op.FromLogin = c.fromLogin
		op.Issuer = c.issuer
		kr := sig.NewKeyring("")
		res := sig.VerifyKeyOp(kr, op)
		if res.Status != c.want {
			t.Fatalf("%s: status %s, want %s", c.name, res.Status, c.want)
		}
		assertNotBound(t, kr, tsk, record.RoleService, "acme")
		assertNotBound(t, kr, tsk, record.RoleService, "globex")
		assertNotBound(t, kr, tsk, record.RolePolicy, "acme")
		if st := kr.State(); st.Key(sig.KeyID(tenantKeyPub(tsk))) != nil {
			t.Fatalf("%s: refused tenant key visible through inspection", c.name)
		}
	}
	// A matching pin binds only the pinned tenant and role.
	op := tenantRoot(t, tsk, record.RoleService, "acme")
	signWith(t, op, tsk)
	op.FromLogin = true
	op.Issuer = loginIssuer("acme", record.RoleService)
	kr := sig.NewKeyring("")
	if res := sig.VerifyKeyOp(kr, op); res.Status != sig.OpAuthorized {
		t.Fatalf("matching pin refused: %+v", res)
	}
	if kr.State().KeyFor(sig.KeyID(tenantKeyPub(tsk)), record.RoleService, "acme") == nil {
		t.Fatal("matching pin did not bind")
	}
	assertNotBound(t, kr, tsk, record.RoleService, "globex")
	assertNotBound(t, kr, tsk, record.RolePolicy, "acme")
}

func TestTenantKeyAuthorAndSubjectShape(t *testing.T) {
	tsk := tenantKeyPriv("tsk")
	other := tenantKeyPriv("other")
	// The header author of a root op is its subject.
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tenantKeyPub(tsk), record.RoleService, ""), Genesis: "acme"}, tenantKeyPub(other), "", tenantKeyAt, tsk)
	if err != nil {
		t.Fatal(err)
	}
	op.FromLogin = true
	op.Issuer = loginIssuer("acme", record.RoleService)
	kr := sig.NewKeyring("")
	if res := sig.VerifyKeyOp(kr, op); res.Status == sig.OpAuthorized {
		t.Fatal("tenant_key authored by a non-subject key authorized")
	}
	assertNotBound(t, kr, tsk, record.RoleService, "acme")
	// A tenant key names no machine, neither as subject nor as author.
	machine := "6f1c1d7e-5b8a-4c11-9d2e-0a1b2c3d4e5f"
	authored := record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tenantKeyPub(tsk), record.RoleService, ""), Genesis: "acme"}
	withMachine := craftKeyOp(t, authored, tenantKeyPub(tsk), machine)
	ms, _ := sig.SignRecord(tsk, withMachine.ID)
	if res := sig.VerifyKeyOp(sig.NewKeyring(""), &sig.KeyOp{Rec: withMachine, Body: &authored, Sigs: []record.Signature{ms}, FromLogin: true, Issuer: loginIssuer("acme", record.RoleService)}); res.Status == sig.OpAuthorized {
		t.Fatal("tenant_key authored with a machine id authorized")
	}
	bad := []record.KeyOpBody{
		{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tenantKeyPub(tsk), record.RoleDevice, machine), Genesis: "acme"},
		{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tenantKeyPub(tsk), record.RoleService, machine), Genesis: "acme"},
		{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tenantKeyPub(tsk), record.RoleService, "")},
		{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tenantKeyPub(tsk), record.RoleService, ""), Genesis: "acme", Previous: sig.KeyID(tenantKeyPub(other))},
		{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tenantKeyPub(tsk), record.RoleService, ""), Genesis: "acme", Reason: "lost"},
	}
	wrongID := sig.KeyRefOf(tenantKeyPub(tsk), record.RoleService, "")
	wrongID.KeyID = sig.KeyID(tenantKeyPub(other))
	bad = append(bad, record.KeyOpBody{Op: record.OpTenantKey, Subject: wrongID, Genesis: "acme"})
	wrongAlg := sig.KeyRefOf(tenantKeyPub(tsk), record.RoleService, "")
	wrongAlg.Alg = "ed448"
	bad = append(bad, record.KeyOpBody{Op: record.OpTenantKey, Subject: wrongAlg, Genesis: "acme"})
	// Control: the crafted encoding with the author as subject verifies.
	good := record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(tenantKeyPub(tsk), record.RoleService, ""), Genesis: "acme"}
	goodRec := craftKeyOp(t, good, tenantKeyPub(tsk))
	gs, _ := sig.SignRecord(tsk, goodRec.ID)
	if res := sig.VerifyKeyOp(sig.NewKeyring(""), &sig.KeyOp{Rec: goodRec, Body: &good, Sigs: []record.Signature{gs}, FromLogin: true, Issuer: loginIssuer("acme", record.RoleService)}); res.Status != sig.OpAuthorized {
		t.Fatalf("crafted control root refused: %+v", res)
	}
	for i, b := range bad {
		if _, err := sig.BuildKeyOp(b, tenantKeyPub(tsk), "", tenantKeyAt, tsk); err == nil {
			t.Fatalf("bad tenant_key %d authored", i)
		}
		rec := craftKeyOp(t, b, tenantKeyPub(tsk))
		s, _ := sig.SignRecord(tsk, rec.ID)
		role := b.Subject.Role
		if role == record.RoleDevice {
			role = record.RoleService
		}
		kr := sig.NewKeyring("")
		if res := sig.VerifyKeyOp(kr, &sig.KeyOp{Rec: rec, Body: &b, Sigs: []record.Signature{s}, FromLogin: true, Issuer: loginIssuer("acme", role)}); res.Status != sig.OpInvalid {
			t.Fatalf("bad tenant_key %d: %+v", i, res)
		}
		assertNotBound(t, kr, tsk, role, "acme")
	}
}

// A refused root cannot be repaired by a later rotation: the rotation's
// parent is never authorized, so its subject never activates.
func TestTenantKeyRefusedRootAuthorizesNoRotation(t *testing.T) {
	tsk := tenantKeyPriv("tsk")
	next := tenantKeyPriv("next")
	root := tenantRoot(t, tsk, record.RoleService, "acme")
	signWith(t, root, tsk)
	root.Issuer = loginIssuer("acme", record.RoleService) // signature alone: not from login
	rot, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKeyRotate, Subject: sig.KeyRefOf(tenantKeyPub(next), record.RoleService, ""), Genesis: "acme",
		Previous: sig.KeyID(tenantKeyPub(tsk)), Parents: []string{root.Rec.ID}}, tenantKeyPub(tsk), "", tenantKeyAt+1, tsk)
	if err != nil {
		t.Fatal(err)
	}
	rot.Issuer = loginIssuer("acme", record.RoleService)
	kr := sig.NewKeyring("")
	if res := sig.VerifyKeyOp(kr, root); res.Status != sig.OpIgnored {
		t.Fatalf("root: %+v", res)
	}
	if res := sig.VerifyKeyOp(kr, rot); res.Status == sig.OpAuthorized {
		t.Fatalf("rotation of an unpinned root authorized: %+v", res)
	}
	assertNotBound(t, kr, tsk, record.RoleService, "acme")
	assertNotBound(t, kr, next, record.RoleService, "acme")
}
