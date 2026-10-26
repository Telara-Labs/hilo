package contract_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

func TestEmbeddedRedactionDataIsPinnedAndDetached(t *testing.T) {
	for _, tc := range []struct {
		path string
		get  func() []byte
	}{
		{"testdata/redact-corpus-v1/corpus.json", contract.RedactionCorpusV1},
		{"testdata/redact-corpus-v1/actual-engine-golden.json", contract.RedactionGoldenV1},
	} {
		want, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		first := tc.get()
		if !bytes.Equal(first, want) || len(first) == 0 {
			t.Fatal("embedded data differs from pinned fixture", tc.path)
		}
		first[0] ^= 0xff
		if !bytes.Equal(tc.get(), want) {
			t.Fatal("accessor exposed mutable embedded data", tc.path)
		}
	}
	prior := append([]byte(nil), contract.RedactCorpusV1...)
	t.Cleanup(func() { contract.RedactCorpusV1 = prior })
	contract.RedactCorpusV1 = []byte("caller mutation")
	if bytes.Equal(contract.RedactionCorpusV1(), contract.RedactCorpusV1) {
		t.Fatal("runtime corpus depends on mutable compatibility variable")
	}
	var golden record.Ruleset
	if err := json.Unmarshal(contract.RedactionGoldenV1(), &golden); err != nil {
		t.Fatal(err)
	}
	if golden.Epoch != 42 || golden.Engine != "tap-discover/d4bd1496f20d" || golden.Digest != "7a8a5173474a5a4a3317c56a1f7c41f56bd00a12cc85fb5040b5ba8765b7dd05" || golden.Behavior != "ae83f631a285ace70469636cf4d0ae13236944fa45c47a4030ea5a1507c23b5d" {
		t.Fatal("pinned golden changed")
	}
}
