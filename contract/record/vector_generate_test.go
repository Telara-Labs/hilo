package record

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"sort"
	"testing"
)

var updateV3 = flag.Bool("update-v3", false, "regenerate public test-only mnc/3 fixtures")

// Entropy injection is private to this package's tests. These public constants
// NEVER serve as production entropy or certify an author's entropy source.
func TestRegenerateV3Fixtures(t *testing.T) {
	if !*updateV3 {
		return
	}
	names := []string{}
	for name := range fixtures() {
		names = append(names, name)
	}
	sort.Strings(names)
	type fixture struct{ Name, HeaderJCS, BodyJCS, ID, Digest string }
	out := []fixture{}
	for _, name := range names {
		h, b := fixtures()[name]()
		seed := sha256.Sum256([]byte("public mnc3 fixture " + name))
		r, err := build(h, b, bytes.NewReader(bytes.Repeat(seed[:], 64)), false)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out = append(out, fixture{name, string(r.HeaderJCS), string(r.BodyJCS), r.ID, r.Header.Body.Digest})
	}
	write := func(name string, v any) {
		t.Helper()
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile("../testdata/"+name, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("v03-records.json", out)
	seed := bytes.Repeat([]byte{3}, 16)
	write("v04-salt.json", map[string]string{"test_entropy_hex": hex.EncodeToString(seed), "salt": base64.RawURLEncoding.EncodeToString(seed), "note": "PUBLIC TEST ONLY. Direct injected independent bytes, never production entropy."})
	e := Event{ID: tEvent(0), Kind: "assistant_final", Prov: "transcript", Text: &Text{Body: "private redacted prose"}}
	sealed, err := reviseEvent(e, nil, bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	write("v04-events.json", map[string]any{"test_nonce_hex": hex.EncodeToString(seed), "event": sealed})
	keyed, err := reviseTextEvent(Event{ID: tEvent(0), Kind: "assistant_final", Prov: "transcript"}, nil, "public redacted fixture text", actualRedactor{}, 600, bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	write("v04-keyed-text.json", map[string]any{"test_entropy_hex": hex.EncodeToString(seed), "event": keyed, "full_redacted_text": "public redacted fixture text"})

}
