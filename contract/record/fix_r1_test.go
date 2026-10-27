package record

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/Telara-Labs/hilo/contract/jcs"
)

func TestV3BuildRejectsInvalidUTF8BeforeClone(t *testing.T) {
	bad := string([]byte{0xff})
	for _, tc := range []struct {
		name, fixture string
		mutate        func(any)
	}{
		{"task string", "task", func(b any) { b.(*TaskBody).Name = bad }},
		{"nested slice", "checkpoint", func(b any) { b.(*CheckpointBody).TaskTree = []Step{{Title: bad}} }},
		{"nested map key", "chunk", func(b any) { b.(*ChunkBody).Events[0].Meta = map[string]string{bad: "value"} }},
		{"nested map value", "chunk", func(b any) { b.(*ChunkBody).Events[0].Meta = map[string]string{"key": bad} }},
		{"nested call key", "chunk", func(b any) { b.(*ChunkBody).Events[0].Call.Args = map[string]string{bad: "value"} }},
		{"nested call value", "chunk", func(b any) { b.(*ChunkBody).Events[0].Call.Args = map[string]string{"key": bad} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, body := fixtures()[tc.fixture]()
			tc.mutate(body)
			_, unchanged := fixtures()[tc.fixture]()
			tc.mutate(unchanged)
			r, err := Build(h, body)
			var e *jcs.Error
			if r != nil || !errors.As(err, &e) || e.Code != jcs.CodeInvalidUTF8 {
				t.Fatalf("invalid typed string repaired before rejection: %v", err)
			}
			// Ordinary JSON comparison would repair both sides and could hide
			// a mutation from invalid UTF-8 to a replacement character.
			if !reflect.DeepEqual(body, unchanged) {
				t.Fatal("failed authoring mutated caller")
			}
		})
	}
	h, b := fixtures()["task"]()
	b.(*TaskBody).Name = "valid replacement rune \ufffd"
	if _, err := Build(h, b); err != nil {
		t.Fatal("valid U+FFFD rejected", err)
	}
}

func TestV3RequiredTaskStatusAdmission(t *testing.T) {
	// The independent wire cases encode the required status from the contract,
	// rather than deriving requiredness from Go tags.
	raw, err := os.ReadFile("../testdata/v03-task-status.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, Error string
		Body        json.RawMessage
	}
	if err := json.Unmarshal(raw, &cases); err != nil || len(cases) != 6 {
		t.Fatal("task status fixture", err)
	}
	h, _ := fixtures()["task"]()
	if r, err := Build(h, &TaskBody{}); err == nil || r != nil {
		t.Error("author accepted absent required task status")
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			bj, err := jcs.CanonicalizeRecord(tc.Body)
			if err != nil {
				t.Fatal(err)
			}
			hh := h
			hh.V = Version
			hh.Body = &BodyRef{Digest: BodyDigest(bj), Size: int64(len(bj))}
			hj, err := jcs.MarshalRecord(hh)
			if err != nil {
				t.Fatal(err)
			}
			r, err := Parse(hj, bj, ContentID(hj))
			if tc.Error != "" {
				if err == nil || CodeOf(err) != tc.Error || r != nil {
					t.Fatalf("wanted %s, got %v", tc.Error, err)
				}
				return
			}
			if err != nil || !bytes.Equal(r.BodyJCS, bj) {
				t.Fatal("valid status rejected or rewritten", err)
			}
		})
	}
}

func TestV3CallCommitmentGeneralJSON(t *testing.T) {
	const salt = "AwMDAwMDAwMDAwMDAwMDAw"
	const tool = "telara_knowledge_search"
	key, _ := base64.RawURLEncoding.DecodeString(salt)
	for _, tc := range []struct{ name, raw, canonical string }{
		{"null", "null", "null"},
		{"fraction", `{"score":0.5}`, `{"score":0.5}`},
		{"nested", ` {"z":[null,0.5,{"n":-1.25e2}],"a":true} `, `{"a":true,"z":[null,0.5,{"n":-125}]}`},
		{"boolean", "false", "false"},
		{"string", `"result"`, `"result"`},
		{"array", `[null,0.5]`, `[null,0.5]`},
		{"negative zero", "-0", "0"},
		{"large double", "1e30", "1e+30"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, b := fixtures()["call"]()
			body := *b.(*CallBody)
			body.Tool = tool
			sealed, err := BuildCall(h, body, json.RawMessage(tc.raw), json.RawMessage(tc.raw))
			if err != nil {
				t.Fatal("valid JSON preimage rejected", err)
			}
			c := sealed.Body.(*CallBody)
			for _, part := range []string{"args", "result"} {
				got, err := CallCommitment(salt, part, tool, json.RawMessage(tc.raw))
				mac := hmac.New(sha256.New, key)
				mac.Write([]byte(`["mnc3-call-` + part + `","` + tool + `",` + tc.canonical + `]`))
				if err != nil || got != hex.EncodeToString(mac.Sum(nil)) {
					t.Fatalf("commitment preimage mismatch: %s %v", got, err)
				}
				canonical, err := CallCommitment(salt, part, tool, json.RawMessage(tc.canonical))
				if err != nil || got != canonical {
					t.Fatal("noncanonical spelling changed commitment", err)
				}
				sealedKey, _ := base64.RawURLEncoding.DecodeString(c.Salt)
				sealedMAC := hmac.New(sha256.New, sealedKey)
				sealedMAC.Write([]byte(`["mnc3-call-` + part + `","` + tool + `",` + tc.canonical + `]`))
				want := hex.EncodeToString(sealedMAC.Sum(nil))
				if part == "args" && c.ArgsHash != want || part == "result" && c.ResultHash != want {
					t.Fatal("author commitment did not cover the canonical JSON value")
				}
			}
			if c.ArgsHash == "" || c.ResultHash == "" || c.ArgsHash == c.ResultHash {
				t.Fatal("available null/value omitted or domain separation lost")
			}
			if _, err := jcs.CanonicalizeRecord(sealed.BodyJCS); err != nil {
				t.Fatal("general preimage weakened wire record profile", err)
			}
		})
	}
	for _, raw := range []json.RawMessage{nil, {}, []byte(`{"x":1,"x":2}`), []byte(`"\ud800"`), []byte(`1e9999`), []byte(`1e-9999`), []byte(`null true`), {0xff}} {
		if _, err := CallCommitment(salt, "result", tool, raw); err == nil {
			t.Fatalf("invalid I-JSON accepted: %q", raw)
		}
	}
	h, b := fixtures()["call"]()
	sealed, err := BuildCall(h, *b.(*CallBody), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := sealed.Body.(*CallBody)
	if c.ArgsHash != "" || c.ResultHash != "" {
		t.Fatal("unavailable preimages created commitments")
	}
}
