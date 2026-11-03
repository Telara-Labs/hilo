package localpolicy

import (
	"bytes"
	"encoding/json"
	"testing"

	tapredact "github.com/Telara-Labs/TAP-Runtime/discover/redact"
	contract "github.com/Telara-Labs/hilo/contract"
	"github.com/Telara-Labs/hilo/contract/record"
)

func TestImmutableMeasuredPolicy(t *testing.T) {
	r, e := Ruleset()
	if e != nil {
		t.Fatal(e)
	}
	var golden record.Ruleset
	if json.Unmarshal(contract.RedactionGoldenV1(), &golden) != nil || r != golden {
		t.Fatal("measured ruleset changed")
	}
	old := append([]byte(nil), contract.RedactCorpusV1...)
	defer func() { contract.RedactCorpusV1 = old }()
	contract.RedactCorpusV1 = bytes.Repeat([]byte("x"), len(old))
	again, e := Ruleset()
	if e != nil || again != golden {
		t.Fatal("mutable compatibility corpus changed policy")
	}
	c, e := record.ParseCorpus(contract.RedactionCorpusV1())
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range c.Entries {
		if Text(v.Value()) != tapredact.Redact(v.Value()) || Argument(v.Name, v.Value()) != tapredact.Argument(v.Name, v.Value()) {
			t.Fatalf("published output changed for corpus ID %s", v.ID)
		}
	}
	p, e := New("local", false)
	if e != nil || !p.Selected() || p.Ruleset() != golden {
		t.Fatal("LOCAL selection failed")
	}
	for _, profile := range []string{"", "tenant", "local-with-overlay"} {
		if _, e := New(profile, false); e == nil {
			t.Fatal("unsupported selection accepted")
		}
	}
	if _, e := New("local", true); e == nil {
		t.Fatal("tenant overlay accepted")
	}
}
