package record

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
)

func TestGenesisAuthorityFieldWireRules(t *testing.T) {
	cases := []struct {
		name    string
		op      string
		genesis string
		valid   bool
	}{
		{"genesis-omitted", OpGenesis, "", true},
		{"genesis-explicit-self", OpGenesis, "self", true},
		{"genesis-explicit-other", OpGenesis, tKeyID, false},
		{"genesis-explicit-malformed", OpGenesis, "tenant", false},
		{"device-add-missing", OpDeviceAdd, "", false},
		{"device-rotate-missing", OpDeviceRotate, "", false},
		{"device-revoke-missing", OpDeviceRevoke, "", false},
		{"tenant-key-missing", OpTenantKey, "", false},
		{"tenant-rotate-missing", OpTenantKeyRotate, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, body := fixtures()["key_op"]()
			b := body.(*KeyOpBody)
			b.Op, b.Genesis = tc.op, tc.genesis
			if tc.genesis == "self" {
				b.Genesis = b.Subject.KeyID
			}
			if tc.op != OpGenesis && tc.op != OpTenantKey {
				b.Parents = []string{hx("parent")}
			}
			if tc.op == OpDeviceRotate || tc.op == OpTenantKeyRotate {
				b.Previous = tKeyID
			}
			if tc.op == OpDeviceRevoke {
				b.Reason = "lost"
			}
			if tc.op == OpTenantKey || tc.op == OpTenantKeyRotate {
				b.Subject.Role, b.Subject.MachineID = RoleService, ""
				h.Author.MachineID = ""
			}
			hj, bj := raw(t, h, b)
			id := ContentID(hj)
			parsed, err := Parse(hj, bj, id)
			if !tc.valid {
				if err == nil || parsed != nil {
					t.Fatal("invalid authority accepted", parsed, err)
				}
				if _, err := Build(h, b); err == nil {
					t.Fatal("invalid authority authored")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Body.(*KeyOpBody).Genesis != b.Genesis || parsed.ID != id || !bytes.Equal(hj, parsed.HeaderJCS) || !bytes.Equal(bj, parsed.BodyJCS) {
				t.Fatal("received authority or signed bytes normalized")
			}
			if b.Genesis == "" {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(parsed.BodyJCS, &fields); err != nil {
					t.Fatal(err)
				}
				if _, present := fields["genesis"]; present {
					t.Fatal("omitted authority filled into received body")
				}
			}
			built, err := Build(h, b)
			if err != nil || built.ID != id || !bytes.Equal(built.HeaderJCS, hj) || !bytes.Equal(built.BodyJCS, bj) {
				t.Fatal("new genesis authoring changed explicit/omitted encoding", err)
			}
		})
	}
}

func TestOptionalGenesisStillRejectsEmptyNullAndWrongWireTypes(t *testing.T) {
	for _, value := range []string{`""`, `null`, `0`, `false`, `[]`, `{}`} {
		t.Run(value, func(t *testing.T) {
			h, body := fixtures()["key_op"]()
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &obj); err != nil {
				t.Fatal(err)
			}
			obj["genesis"] = json.RawMessage(value)
			bj, err := jcs.Marshal(obj) // General JCS permits crafting forbidden null.
			if err != nil {
				t.Fatal(err)
			}
			h.V = Version
			h.Body = &BodyRef{Digest: BodyDigest(bj), Size: int64(len(bj))}
			hj, err := jcs.MarshalRecord(&h)
			if err != nil {
				t.Fatal(err)
			}
			if r, err := Parse(hj, bj, ContentID(hj)); err == nil || r != nil {
				t.Fatal("optional omission became permissive wire normalization", r, err)
			}
		})
	}
}
