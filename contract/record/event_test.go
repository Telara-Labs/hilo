package record

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type failedEntropy struct{}

func (failedEntropy) Read([]byte) (int, error) { return 0, errors.New("no entropy") }
func TestProtectedEventSaltAndFailure(t *testing.T) {
	e := Event{ID: tEvent(0), Kind: "assistant_final", Prov: "transcript", Text: &Text{Body: "private redacted prose"}}
	a, err := reviseEvent(e, nil, tSaltKey, bytes.NewReader(bytes.Repeat([]byte{3}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	same, err := reviseEvent(e, nil, tSaltKey, bytes.NewReader(bytes.Repeat([]byte{3}, 32)))
	if err != nil || a.Revision != same.Revision {
		t.Fatal("fixed-entropy vector not reproducible")
	}
	b, err := ReviseEvent(e, nil, tSaltKey)
	if err != nil || a.Revision == b.Revision || a.Salt == b.Salt {
		t.Fatal("fresh sealing reused entropy")
	}
	got, _ := EventRevision(a)
	if got != a.Revision {
		t.Fatal("receiver cannot recompute")
	}
	bad := a
	bad.Salt = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 16))
	wrong, _ := EventRevision(bad)
	if wrong == a.Revision {
		t.Fatal("guessed payload with wrong salt reproduced retained revision")
	}
	if _, err = ReviseEvent(e, nil, nil); err == nil {
		t.Fatal("key outage sealed")
	}
	if _, err = reviseEvent(e, nil, tSaltKey, failedEntropy{}); err == nil {
		t.Fatal("entropy outage sealed")
	}
	e.Salt = ""
	if _, err = EventRevision(e); err == nil {
		t.Fatal("legacy unsalted event entered protected path")
	}
	copied := a
	if copied.Revision != a.Revision || copied.Salt != a.Salt {
		t.Fatal("unchanged copy changed seal")
	}
}

func TestProductionEventDerivationMatchesFrozenVector(t *testing.T) {
	var f struct {
		Nonce string `json:"test_nonce_hex"`
		Key   string `json:"salt_key_hex"`
		Event Event  `json:"event"`
	}
	raw, err := os.ReadFile("../testdata/v04-events.json")
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture")
	}
	nonce, _ := hex.DecodeString(f.Nonce)
	key, _ := hex.DecodeString(f.Key)
	got, err := reviseEvent(f.Event, f.Event.Replaces, key, bytes.NewReader(nonce))
	if err != nil || got.Salt != f.Event.Salt || got.Revision != f.Event.Revision {
		t.Fatalf("production salt/vector mismatch %v", err)
	}
}
func TestBuildPreservesCorrectionFrontier(t *testing.T) {
	h, b := fixtures()["chunk"]()
	chunk := b.(*ChunkBody)
	predecessor := hx("prior-revision")
	chunk.Events[0].Replaces = []string{predecessor}
	r, err := Build(h, chunk, tSaltKey)
	if err != nil || len(r.Body.(*ChunkBody).Events[0].Replaces) != 1 || r.Body.(*ChunkBody).Events[0].Replaces[0] != predecessor {
		t.Fatal("Build dropped correction frontier", err)
	}
	for _, parents := range [][]string{{"not-a-hash"}, {predecessor, predecessor}, {hx("1"), hx("2"), hx("3"), hx("4"), hx("5"), hx("6"), hx("7"), hx("8"), hx("9")}} {
		h, b = fixtures()["chunk"]()
		b.(*ChunkBody).Events[0].Replaces = parents
		if _, err = Build(h, b, tSaltKey); err == nil {
			t.Fatal("Build hid invalid predecessors")
		}
	}
}
