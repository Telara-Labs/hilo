package contract_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"os"
	"testing"
)

func fixture(t *testing.T, name string, dst any) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, dst); err != nil {
		t.Fatal(err)
	}
}
func TestV1JSON(t *testing.T) {
	var cases []struct {
		Name, Raw, Canonical, Error string
		RawBase64                   string `json:"raw_base64"`
		Noncanonical                bool
	}
	fixture(t, "v01-jcs.json", &cases)
	if len(cases) == 0 {
		t.Fatal("empty JCS fixture")
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			raw := []byte(c.Raw)
			if c.RawBase64 != "" {
				var err error
				raw, err = base64.StdEncoding.DecodeString(c.RawBase64)
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := jcs.Canonicalize(raw)
			if c.Error != "" {
				var e *jcs.Error
				if !errors.As(err, &e) || e.Code != c.Error {
					t.Fatalf("error %v wanted %s", err, c.Error)
				}
				return
			}
			if err != nil || string(got) != c.Canonical {
				t.Fatalf("%s %v", got, err)
			}
			if c.Noncanonical && jcs.IsCanonicalRecord(raw) {
				t.Fatal("noncanonical input accepted")
			}
		})
	}
}
func TestV2JSON(t *testing.T) {
	var f map[string]string
	fixture(t, "v02-identity.json", &f)
	sk, _ := record.SessionKey("claude-code", "local", record.NativeGlobal, "native-7", "")
	local, _ := record.SessionKey("claude-code", "local", record.NativeLocal, "native-7", f["machine"])
	repo, _ := record.RepoID("github.com/acme/api")
	event, _ := record.EventID(sk, "tool_call", record.Anchor{NativeItemID: "item-1", Inner: 2})
	if sk != f["session_global"] || local != f["session_local"] || repo != f["repo"] || event != f["event_inner2"] || record.H("test", "one", "two") != f["h"] {
		t.Fatal("identity vector mismatch")
	}
	other, _ := record.EventID(sk, "tool_call", record.Anchor{NativeItemID: "item-1", Inner: 1})
	if other == event {
		t.Fatal("inner ordinal collision")
	}
}
func TestV3JSON(t *testing.T) {
	var fs []struct{ Name, HeaderJCS, BodyJCS, ID, Digest string }
	fixture(t, "v03-records.json", &fs)
	kinds := map[record.Kind]bool{}
	for _, f := range fs {
		t.Run(f.Name, func(t *testing.T) {
			r, err := record.Parse([]byte(f.HeaderJCS), []byte(f.BodyJCS), f.ID)
			if err != nil {
				t.Fatal(err)
			}
			kinds[r.Header.Type] = true
			if r.Header.Body.Digest != f.Digest {
				t.Fatal("digest mismatch")
			}
			if r.WithoutBody().ID != f.ID {
				t.Fatal("body purge changed identity")
			}
			if _, err = record.Parse([]byte(f.HeaderJCS), nil, f.ID); err != nil {
				t.Fatal("header-only admission", err)
			}
		})
	}
	if len(kinds) != len(record.Kinds) {
		t.Fatal("missing kind fixture")
	}
}
func TestV4JSON(t *testing.T) {
	var f struct {
		SaltKeyHex string      `json:"salt_key_hex"`
		Kind       record.Kind `json:"kind"`
		LID        string      `json:"lid"`
		Body       string      `json:"body_without_salt"`
		Salt       string      `json:"salt"`
	}
	fixture(t, "v04-salt.json", &f)
	key, _ := hex.DecodeString(f.SaltKeyHex)
	got, _ := record.Salt(key, f.Kind, f.LID, []byte(f.Body))
	if got != f.Salt {
		t.Fatal("salt mismatch")
	}
	other, _ := record.Salt(bytes.Repeat([]byte{8}, 32), f.Kind, f.LID, []byte(f.Body))
	sibling, _ := record.Salt(key, f.Kind, f.LID, []byte(`{"text":"sibling"}`))
	if got == other || got == sibling {
		t.Fatal("salt did not isolate keys or versions")
	}
	if _, err := record.Salt(nil, f.Kind, f.LID, []byte(f.Body)); err == nil {
		t.Fatal("key outage allowed unsalted seal")
	}
}
func TestV5JSON(t *testing.T) {
	var f struct {
		HeaderJCS   string           `json:"header_jcs"`
		BodyJCS     string           `json:"body_jcs"`
		SaltKeyHex  string           `json:"salt_key_hex"`
		TestSeedHex string           `json:"test_seed_hex"`
		PubHex      string           `json:"pub_hex"`
		RecordID    string           `json:"record_id"`
		MessageHex  string           `json:"message_hex"`
		Signature   record.Signature `json:"signature"`
	}
	fixture(t, "v05-signature.json", &f)
	pub, _ := hex.DecodeString(f.PubHex)
	r, err := record.Parse([]byte(f.HeaderJCS), []byte(f.BodyJCS), f.RecordID)
	if err != nil || r.Header.V != 2 || r.Header.Author.KeyID != f.Signature.KeyID {
		t.Fatal("signed v2 header fixture", err)
	}
	key, _ := hex.DecodeString(f.SaltKeyHex)
	built, err := record.Build(r.Header, r.Body, key)
	if err != nil || !bytes.Equal(built.HeaderJCS, r.HeaderJCS) || built.ID != f.RecordID {
		t.Fatal("production header build fixture", err)
	}
	seed, _ := hex.DecodeString(f.TestSeedHex)
	actual, err := sig.SignRecord(ed25519.NewKeyFromSeed(seed), built.ID)
	if err != nil || actual != f.Signature {
		t.Fatal("production signature fixture", err)
	}
	msg, _ := sig.RecordMessage(f.RecordID)
	if hex.EncodeToString(msg) != f.MessageHex || sig.Verify(ed25519.PublicKey(pub), sig.CtxRecord, msg, f.Signature) != nil {
		t.Fatal("signature fixture")
	}
	if sig.Verify(ed25519.PublicKey(pub), sig.CtxBundle, msg, f.Signature) == nil {
		t.Fatal("cross context signature")
	}
	bad := f.Signature
	value, _ := base64.RawURLEncoding.DecodeString(bad.Value)
	value[63] |= 0x80
	bad.Value = base64.RawURLEncoding.EncodeToString(value)
	if sig.Verify(ed25519.PublicKey(pub), sig.CtxRecord, msg, bad) == nil {
		t.Fatal("malleable signature")
	}
}

func TestV15MatrixJSON(t *testing.T) {
	var f struct {
		Allowed [][3]string `json:"allowed"`
	}
	fixture(t, "v15-matrix.json", &f)
	allowed := map[[3]string]bool{}
	for _, row := range f.Allowed {
		allowed[row] = true
	}
	for _, role := range []record.Role{record.RoleDevice, record.RoleService, record.RolePolicy, "unknown"} {
		for _, prov := range append(append([]record.Prov(nil), record.Provs...), "unknown") {
			for _, kind := range append(append([]record.Kind(nil), record.Kinds...), "unknown") {
				want := allowed[[3]string{string(role), string(prov), string(kind)}]
				if record.MatrixAllows(role, prov, kind) != want {
					t.Fatalf("matrix differs at %s %s %s", role, prov, kind)
				}
			}
		}
	}
}

func TestV4EventJSON(t *testing.T) {
	var f struct {
		Nonce string       `json:"test_nonce_hex"`
		Key   string       `json:"salt_key_hex"`
		Event record.Event `json:"event"`
	}
	fixture(t, "v04-events.json", &f)
	raw, _ := json.Marshal(f.Event)
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	delete(fields, "revision")
	delete(fields, "salt")
	payload, err := jcs.MarshalRecord(fields)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := hex.DecodeString(f.Nonce)
	key, _ := hex.DecodeString(f.Key)
	msg, err := jcs.StringArray("mnc2-event-salt", f.Event.ID, base64.RawURLEncoding.EncodeToString(nonce), string(payload))
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16]) != f.Event.Salt {
		t.Fatal("event salt vector")
	}
	rev, err := record.EventRevision(f.Event)
	if err != nil || rev != f.Event.Revision {
		t.Fatal("protected revision fixture", err)
	}
}
