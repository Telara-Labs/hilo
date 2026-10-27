package sig

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
)

// Craft and sign the original receiver bytes without authoring validation.
// Invalid wire cases must reach Parse/AddContext rather than a builder refusal.
func genesisWireOp(t *testing.T, b record.KeyOpBody, author ed25519.PrivateKey, machine string, signers ...ed25519.PrivateKey) *KeyOp {
	t.Helper()
	bj, err := jcs.MarshalRecord(&b)
	parityNoError(t, err)
	h := record.Header{V: record.Version, Type: record.KindKeyOp, LID: record.KeyLID(b.Subject.KeyID), Author: record.Author{KeyID: KeyID(pub(author)), MachineID: machine}, At: 1761150000000, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}, Body: &record.BodyRef{Digest: record.BodyDigest(bj), Size: int64(len(bj))}}
	hj, err := jcs.MarshalRecord(&h)
	parityNoError(t, err)
	op := &KeyOp{Rec: &record.Record{ID: record.ContentID(hj), HeaderJCS: hj, BodyJCS: bj}, Body: &b}
	for _, signer := range signers {
		s, err := SignRecord(signer, op.Rec.ID)
		parityNoError(t, err)
		op.Sigs = append(op.Sigs, s)
	}
	return op
}

func TestOptionalGenesisPreservesSignedWireAndSameAuthority(t *testing.T) {
	root, child := key("optional-root"), key("optional-child")
	gid := KeyID(pub(root))
	r := taskRecord(t, gid, pub(child), mB, record.ProvMCPExplicit)
	var previousKeys map[string]*Key
	var previousID string
	for _, explicit := range []bool{false, true} {
		b := record.KeyOpBody{Op: record.OpGenesis, Subject: KeyRefOf(pub(root), record.RoleDevice, mA)}
		if explicit {
			b.Genesis = gid
		}
		op := genesisWireOp(t, b, root, mA, root)
		header, body, id := append([]byte(nil), op.Rec.HeaderJCS...), append([]byte(nil), op.Rec.BodyJCS...), op.Rec.ID
		sigs := append([]record.Signature(nil), op.Sigs...)
		kr := NewKeyring("")
		result := VerifyKeyOpContext(context.Background(), kr, op)
		parityNoError(t, result.Err)
		parityEqual(t, OpAuthorized, result.Status)
		parityEqual(t, gid, kr.pinned)
		add, err := BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: KeyRefOf(pub(child), record.RoleDevice, mB), Genesis: gid, Parents: []string{id}}, pub(root), mA, 1761150000001, child, root)
		parityNoError(t, err)
		parityEqual(t, OpAuthorized, VerifyKeyOp(kr, add).Status)
		st, err := kr.StateContext(context.Background())
		parityNoError(t, err)
		parityEqual(t, gid, st.Genesis)
		parityEqual(t, gid, st.KeyFor(gid, record.RoleDevice, "").Genesis)
		parityEqual(t, KeyActive, st.KeyFor(KeyID(pub(child)), record.RoleDevice, "").Status)
		verified := VerifyRecord(r, signed(t, r, child), st, Context{})
		parityEqual(t, StatusVerified, verified.Status)
		parityEqual(t, gid, verified.Owner)
		clone, err := kr.CloneContext(context.Background())
		parityNoError(t, err)
		for _, retained := range []*KeyOp{op, kr.Ops()[id], st.Ops[id], kr.State().Ops[id], clone.State().Ops[id]} {
			parityEqual(t, id, retained.Rec.ID)
			parityEqual(t, header, retained.Rec.HeaderJCS)
			parityEqual(t, body, retained.Rec.BodyJCS)
			parityEqual(t, sigs, retained.Sigs)
			parityEqual(t, b.Genesis, retained.Body.Genesis)
			message, err := RecordMessage(retained.Rec.ID)
			parityNoError(t, err)
			parityNoError(t, Verify(pub(root), CtxRecord, message, retained.Sigs[0]))
		}
		var fields map[string]json.RawMessage
		parityNoError(t, json.Unmarshal(body, &fields))
		_, present := fields["genesis"]
		parityEqual(t, explicit, present)
		if previousKeys != nil {
			parityEqual(t, previousKeys, st.Keys)
			if previousID == id {
				t.Fatal("distinct signed explicit/omitted bodies collapsed to one record id")
			}
		}
		previousKeys, previousID = st.Keys, id
	}
}

func TestOmittedGenesisRequiresSubjectPossessionBeforePinning(t *testing.T) {
	root, foreign := key("omitted-root"), key("omitted-foreign")
	b := record.KeyOpBody{Op: record.OpGenesis, Subject: KeyRefOf(pub(root), record.RoleDevice, mA)}
	for _, name := range []string{"missing", "foreign", "forged-label", "wrong-context"} {
		t.Run(name, func(t *testing.T) {
			op := genesisWireOp(t, b, root, mA)
			switch name {
			case "foreign", "forged-label":
				op.Sigs = signed(t, op.Rec, foreign)
				if name == "forged-label" {
					op.Sigs[0].KeyID = b.Subject.KeyID
				}
			case "wrong-context":
				op.Sigs = []record.Signature{pbCrossContext(t, root, op.Rec.ID)}
			}
			kr := NewKeyring("")
			result := VerifyKeyOp(kr, op)
			parityEqual(t, OpInvalid, result.Status)
			if result.Err == nil {
				t.Fatal("possession refusal missing error")
			}
			parityEqual(t, "", kr.pinned)
			parityEmpty(t, kr.Ops())
			parityEmpty(t, kr.State().Keys)
		})
	}
}

func TestOmittedGenesisCannotBeFilledBeforeAdmission(t *testing.T) {
	root := key("unfilled-root")
	op := genesisWireOp(t, record.KeyOpBody{Op: record.OpGenesis, Subject: KeyRefOf(pub(root), record.RoleDevice, mA)}, root, mA, root)
	header, body, id := append([]byte(nil), op.Rec.HeaderJCS...), append([]byte(nil), op.Rec.BodyJCS...), op.Rec.ID
	sigs := append([]record.Signature(nil), op.Sigs...)
	op.Body.Genesis = op.Body.Subject.KeyID // A receiver must not normalize its decoded body.
	kr := NewKeyring("")
	result := VerifyKeyOp(kr, op)
	parityEqual(t, OpInvalid, result.Status)
	if result.Err == nil {
		t.Fatal("decoded body no longer matches original signed bytes")
	}
	parityEqual(t, "", kr.pinned)
	parityEmpty(t, kr.Ops())
	parityEqual(t, header, op.Rec.HeaderJCS)
	parityEqual(t, body, op.Rec.BodyJCS)
	parityEqual(t, id, op.Rec.ID)
	parityEqual(t, sigs, op.Sigs)
}

func TestOptionalGenesisKeepsDomainAuthorAndMachineRefusals(t *testing.T) {
	root, foreign := key("domain-root"), key("domain-foreign")
	gid := KeyID(pub(root))
	for _, name := range []string{"explicit-mismatch", "foreign-pinned-root", "wrong-author", "wrong-machine", "service-subject", "policy-subject", "parents"} {
		t.Run(name, func(t *testing.T) {
			b := record.KeyOpBody{Op: record.OpGenesis, Subject: KeyRefOf(pub(root), record.RoleDevice, mA)}
			author, machine, pinned := root, mA, ""
			want := OpInvalid
			switch name {
			case "explicit-mismatch":
				b.Genesis = KeyID(pub(foreign))
			case "foreign-pinned-root":
				pinned, want = KeyID(pub(foreign)), OpUnauthorized
			case "wrong-author":
				author = foreign
			case "wrong-machine":
				machine = mB
			case "service-subject", "policy-subject":
				b.Subject.Role, b.Subject.MachineID, machine = record.RoleService, "", ""
				if name == "policy-subject" {
					b.Subject.Role = record.RolePolicy
				}
			case "parents":
				b.Parents = []string{hx("absent")}
			}
			op := genesisWireOp(t, b, author, machine, root)
			kr := NewKeyring(pinned)
			result := VerifyKeyOp(kr, op)
			parityEqual(t, want, result.Status)
			parityEmpty(t, kr.State().Keys)
			if name == "explicit-mismatch" || name == "service-subject" || name == "policy-subject" || name == "parents" {
				parityEqual(t, pinned, kr.pinned)
				parityEmpty(t, kr.Ops())
			}
			parityNil(t, kr.State().KeyFor(gid, record.RoleService, gid))
		})
	}
}

func TestOptionalGenesisDoesNotSupplyOtherAuthorityDomains(t *testing.T) {
	root, child := key("domain-root"), key("domain-child")
	gid := KeyID(pub(root))
	for _, name := range []string{"foreign-device-genesis", "missing-device-genesis", "tenant-without-issuer", "tenant-wrong-issuer", "tenant-missing-authority"} {
		t.Run(name, func(t *testing.T) {
			kr := NewKeyring("")
			g := genesisWireOp(t, record.KeyOpBody{Op: record.OpGenesis, Subject: KeyRefOf(pub(root), record.RoleDevice, mA)}, root, mA, root)
			parityEqual(t, OpAuthorized, VerifyKeyOp(kr, g).Status)
			b := record.KeyOpBody{Op: record.OpDeviceAdd, Subject: KeyRefOf(pub(child), record.RoleDevice, mB), Genesis: KeyID(pub(key("other-domain"))), Parents: []string{g.Rec.ID}}
			var op *KeyOp
			if name == "foreign-device-genesis" || name == "missing-device-genesis" {
				if name == "missing-device-genesis" {
					b.Genesis = ""
				}
				op = genesisWireOp(t, b, root, mA, child, root)
			} else {
				b = record.KeyOpBody{Op: record.OpTenantKey, Subject: KeyRefOf(pub(root), record.RoleService, ""), Genesis: "acme"}
				if name == "tenant-missing-authority" {
					b.Genesis = ""
				}
				op = genesisWireOp(t, b, root, "", root)
				op.FromLogin = true
				if name != "tenant-without-issuer" {
					op.Issuer = TrustedIssuer{Tenant: "globex", Role: record.RoleService, Provenance: PinnedTLSLogin}
				}
			}
			want := OpUnauthorized
			if name == "missing-device-genesis" || name == "tenant-missing-authority" {
				want = OpInvalid
			}
			parityEqual(t, want, VerifyKeyOp(kr, op).Status)
			st := kr.State()
			parityNoError(t, st.Err())
			parityLen(t, st.Keys, 1)
			parityEqual(t, KeyActive, st.KeyFor(gid, record.RoleDevice, "").Status)
			parityNil(t, st.KeyFor(gid, record.RoleService, "acme"))
			parityNil(t, st.KeyFor(KeyID(pub(child)), record.RoleDevice, ""))
		})
	}
}
