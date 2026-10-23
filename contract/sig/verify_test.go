package sig

import (
	"crypto/ed25519"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

const task = "3f2a91c0-1111-4222-8333-444455556666"

var saltKey = make([]byte, 32)

func taskRecord(t *testing.T, owner string, signer ed25519.PublicKey, machine string, prov record.Prov) *record.Record {
	t.Helper()
	h := record.Header{Type: record.KindTask, LID: record.TaskLID(owner, task),
		Author: record.Author{MachineID: machine, KeyID: KeyID(signer)}, At: 1761150001000, Prov: prov,
		Subj: record.Subject{TaskID: task}, Red: record.Redact{Profile: record.ProfileLocal}}
	if prov == record.ProvMCPExplicit {
		h.Op = hx("op")
	}
	r, err := record.Build(h, &record.TaskBody{Name: "n", Status: "active"}, saltKey)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func signed(t *testing.T, r *record.Record, k ed25519.PrivateKey) []record.Signature {
	s, err := SignRecord(k, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return []record.Signature{s}
}

func TestSignedBytes(t *testing.T) {
	id := hx("x")
	m, _ := RecordMessage(id)
	if string(m[:14]) != "mnc/v1/record\x00" || len(m) != 14+32 {
		t.Fatalf("record message %q", m)
	}
	if _, err := RecordMessage("ABC"); err == nil {
		t.Fatal("bad id accepted")
	}
	b := BundleMessage([]byte(`{}`))
	if string(b[:14]) != "mnc/v1/bundle\x00" || len(b) != 46 {
		t.Fatal("bundle message")
	}
	k := key("A")
	if KeyID(pub(k)) != hx(string(pub(k)))[:32] {
		t.Fatal("key id formula")
	}
	// the same message under another context does not verify
	s := Sign(k, CtxRecord, m)
	if Verify(pub(k), CtxBundle, m, s) != ErrCtx {
		t.Fatal("context not bound")
	}
	s2 := Sign(k, CtxBundle, BundleMessage(m))
	s2.Ctx = CtxRecord
	if Verify(pub(k), CtxRecord, m, s2) != ErrSignature {
		t.Fatal("signature under another context must fail")
	}
}

func TestVerifyRecord(t *testing.T) {
	w := newWorld(t)
	B, C := key("B"), key("C")
	w.add("addB", B, mB, w.genesis, mA, w.id("genesis"))
	w.rotate("rotB", B, C, mB, w.id("addB"))
	st := w.fold([]string{"genesis", "addB", "rotB"})
	owner := w.gid()

	r := taskRecord(t, owner, pub(w.genesis), mA, record.ProvMCPExplicit)
	if res := VerifyRecord(r, signed(t, r, w.genesis), st, Context{}); res.Status != StatusVerified || res.Owner != owner {
		t.Fatalf("%+v", res)
	}
	// retired key (backlog after rotation) still verifies
	rb := taskRecord(t, owner, pub(B), mB, record.ProvMCPExplicit)
	if res := VerifyRecord(rb, signed(t, rb, B), st, Context{}); res.Status != StatusVerified {
		t.Fatalf("retired: %+v", res)
	}
	cases := []struct {
		name string
		rec  *record.Record
		sigs func() []record.Signature
		want SigStatus
	}{
		{"malleated", r, func() []record.Signature {
			s := signed(t, r, w.genesis)
			v := []byte(s[0].Value)
			v[5] ^= 1
			s[0].Value = string(v)
			return s
		}, StatusInvalid},
		{"wrong ctx", r, func() []record.Signature {
			s := signed(t, r, w.genesis)
			s[0].Ctx = CtxBundle
			return s
		}, StatusInvalid},
		{"two sigs", r, func() []record.Signature { return append(signed(t, r, w.genesis), signed(t, r, w.genesis)...) }, StatusInvalid},
		{"signed by another key", r, func() []record.Signature { return signed(t, r, C) }, StatusInvalid},
		{"unknown signer", taskRecord(t, owner, pub(key("Q")), mA, record.ProvMCPExplicit), nil, StatusUnknownSigner},
		{"machine mismatch", taskRecord(t, owner, pub(w.genesis), mB, record.ProvMCPExplicit), nil, StatusInvalid},
		{"wrong role (device signs gateway)", taskRecord(t, owner, pub(w.genesis), mA, record.ProvGateway), nil, StatusInvalid},
		{"owner namespace", taskRecord(t, "tenant:acme", pub(w.genesis), mA, record.ProvMCPExplicit), nil, StatusInvalid},
	}
	signerOf := map[string]ed25519.PrivateKey{KeyID(pub(w.genesis)): w.genesis, KeyID(pub(key("Q"))): key("Q")}
	for _, c := range cases {
		var sigs []record.Signature
		if c.sigs != nil {
			sigs = c.sigs()
		} else {
			sigs = signed(t, c.rec, signerOf[c.rec.Header.Author.KeyID])
		}
		if res := VerifyRecord(c.rec, sigs, st, Context{}); res.Status != c.want {
			t.Errorf("%s: got %+v", c.name, res)
		}
	}
}

func TestValidityAcrossRevocation(t *testing.T) {
	w := newWorld(t)
	B, T := key("B"), key("TSK")
	w.add("addB", B, mB, w.genesis, mA, w.id("genesis"))
	w.revoke("revB", B, mB, "lost", w.genesis, mA, w.id("addB"))
	tsk := w.op("tsk", record.KeyOpBody{Op: record.OpTenantKey, Subject: KeyRefOf(pub(T), record.RoleService, ""), Genesis: "acme"}, T, "", T)
	tsk.FromLogin = true
	w.ops["revB"].AdmittedSeq = 50
	revReceipt, _ := SignReceipt(T, record.Receipt{ID: w.id("revB"), Tenant: "acme", DeviceID: mA, AcceptedAt: 1000, HSeq: 8, Policy: hx("policy")})
	w.ops["revB"].Receipt = &revReceipt
	w.ops["revB"].ReceiptIssuer = TrustedIssuer{Tenant: "acme", Role: record.RoleService, Provenance: AuthenticatedAdmission}
	st := w.fold([]string{"genesis", "addB", "revB", "tsk"})
	kB := st.Key(KeyID(pub(B)))
	if kB.Status != KeyRevoked || kB.RevokedSeq != 50 {
		t.Fatalf("%+v", kB)
	}
	r := taskRecord(t, w.gid(), pub(B), mB, record.ProvMCPExplicit)
	sigs := signed(t, r, B)
	if res := VerifyRecord(r, sigs, st, Context{AdmittedSeq: 60}); res.Status != StatusSignerRevoked {
		t.Fatalf("after: %+v", res)
	}
	if res := VerifyRecord(r, sigs, st, Context{AdmittedSeq: 40}); res.Status != StatusVerified {
		t.Fatalf("admitted before: %+v", res)
	}
	rc, _ := SignReceipt(T, record.Receipt{ID: r.ID, Tenant: "acme", DeviceID: mB, AcceptedAt: 999, HSeq: 9, Policy: hx("policy")})
	if res := VerifyRecord(r, sigs, st, Context{AdmittedSeq: 60, Receipt: &rc, ReceiptIssuer: TrustedIssuer{Tenant: "acme", Role: record.RoleService, Provenance: AuthenticatedAdmission}}); res.Status != StatusVerified {
		t.Fatalf("receipt before: %+v", res)
	}
	late, _ := SignReceipt(T, record.Receipt{ID: r.ID, Tenant: "acme", DeviceID: mB, AcceptedAt: 1001, HSeq: 9, Policy: hx("policy")})
	if res := VerifyRecord(r, sigs, st, Context{AdmittedSeq: 60, Receipt: &late, ReceiptIssuer: TrustedIssuer{Tenant: "acme", Role: record.RoleService, Provenance: AuthenticatedAdmission}}); res.Status != StatusSignerRevoked {
		t.Fatalf("receipt after: %+v", res)
	}
	forged := rc
	forged.AcceptedAt -= 5 // altered after signing
	if res := VerifyRecord(r, sigs, st, Context{AdmittedSeq: 60, Receipt: &forged, ReceiptIssuer: TrustedIssuer{Tenant: "acme", Role: record.RoleService, Provenance: AuthenticatedAdmission}}); res.Status != StatusSignerRevoked {
		t.Fatalf("forged receipt: %+v", res)
	}
	other, _ := SignReceipt(key("rogue"), record.Receipt{ID: r.ID, Tenant: "acme", AcceptedAt: 1})
	if VerifyReceipt(other, st, TrustedIssuer{Tenant: "acme", Role: record.RoleService, Provenance: AuthenticatedAdmission}) == nil {
		t.Fatal("receipt by an unknown key accepted")
	}
}

func TestGitImportIgnoresControl(t *testing.T) {
	w := newWorld(t)
	st := w.fold([]string{"genesis"})
	lid, _ := record.ControlLID(record.KindRetraction, w.gid(), "00112233445566778899aabbccddeeff")
	h := record.Header{Type: record.KindRetraction, LID: lid, Author: record.Author{MachineID: mA, KeyID: w.gid()},
		At: 1761150002000, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}
	r, err := record.Build(h, &record.RetractionBody{IDs: []string{hx("a")}, Reason: "rule_removed"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sigs := signed(t, r, w.genesis)
	if res := VerifyRecord(r, sigs, st, Context{Route: record.RouteGitImport}); res.Status != StatusIgnored {
		t.Fatalf("%+v", res)
	}
	if res := VerifyRecord(r, sigs, st, Context{Route: record.RouteLocal}); res.Status != StatusVerified {
		t.Fatalf("%+v", res)
	}
}
