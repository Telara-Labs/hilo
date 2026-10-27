package contract_test

import (
	"encoding/json"
	"fmt"
	"github.com/Telara-Labs/hilo/contract/record"
	"sort"
	"strings"
	"testing"
)

const provisionalV3SourceSHA256 = "539b783d2ea9a0c45d5d8e5b70655be27375bd6ed4d0034fca2d6a29bc38c5b0"

func TestV3ProvisionalVectorDrift(t *testing.T) {
	raw := mustRead(t, "testdata/oracle-history/v3/SOURCE.json")
	if digestBytes(raw) != provisionalV3SourceSHA256 {
		t.Fatal("v3 source pin changed; review required")
	}
	var s struct {
		Contract, Status string
		Files            map[string]string
		Digest           string `json:"vector_set_sha256"`
	}
	if json.Unmarshal(raw, &s) != nil || s.Contract != record.ContractVersion || s.Status != "PROVISIONAL" {
		t.Fatal("provisional provenance")
	}
	names := make([]string, 0, len(s.Files))
	for n := range s.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	var set strings.Builder
	for _, n := range names {
		got := digestBytes(mustRead(t, "testdata/oracle-history/v3/"+n))
		if got != s.Files[n] {
			t.Fatal("v3 fixture drift", n)
		}
		fmt.Fprintf(&set, "%s\x00%s\n", n, got)
	}
	if digestBytes([]byte(set.String())) != s.Digest {
		t.Fatal("v3 set digest")
	}
	checkExactHistoryFiles(t, historyRoot+"v3", s.Files, map[string]bool{"SOURCE.json": true})
	t.Log("PROVISIONAL gateway fixtures from accepted07; historical gateway-generated supplement; actual canonical node3 fixtures are separately pinned; no runtime/physical-erasure conformance inferred")
}
