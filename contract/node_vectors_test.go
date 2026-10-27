package contract_test

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

const canonicalNode3SourceSHA256 = "11864fe0149e2f240a64e62f8e6903e567d06e7c13f7f767a21c15c7c4bdeadf"

func TestCanonicalNode3VectorDrift(t *testing.T) {
	raw := mustRead(t, "testdata/oracle-history/node-mnc3/SOURCE.json")
	if digestBytes(raw) != canonicalNode3SourceSHA256 {
		t.Fatal("canonical node3 source pin changed")
	}
	var s struct {
		Contract, Status string
		Files            map[string]string
		Digest           string `json:"vector_set_sha256"`
	}
	if json.Unmarshal(raw, &s) != nil || s.Contract != "mnc/3.0" || s.Status != "COPIED_CANONICAL_NODE_FIXTURES" {
		t.Fatal("node provenance")
	}
	names := make([]string, 0, len(s.Files))
	for n := range s.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	var set strings.Builder
	for _, n := range names {
		got := digestBytes(mustRead(t, "testdata/oracle-history/node-mnc3/"+n))
		if got != s.Files[n] {
			t.Fatal("copied node vector drift", n)
		}
		fmt.Fprintf(&set, "%s\x00%s\n", n, got)
	}
	if digestBytes([]byte(set.String())) != s.Digest {
		t.Fatal("node vector set digest")
	}
	checkExactHistoryFiles(t, historyRoot+"node-mnc3", s.Files, map[string]bool{"SOURCE.json": true})
	declared := strings.Fields(string(mustRead(t, "testdata/oracle-history/node-mnc3/vectors.sha256")))
	if len(declared) != 2 || declared[0] != digestBytes(mustRead(t, "testdata/oracle-history/node-mnc3/vectors.json")) {
		t.Fatal("node registry digest")
	}
}
