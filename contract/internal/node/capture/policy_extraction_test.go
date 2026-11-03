package capture

import (
	"testing"

	tapredact "github.com/Telara-Labs/TAP-Runtime/discover/redact"
	contract "github.com/Telara-Labs/hilo/contract"
	"github.com/Telara-Labs/hilo/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/hilo/contract/record"
)

func TestSharedPolicyPreservesCaptureBoundary(t *testing.T) {
	p, e := selectLocalPolicy("local", false)
	if e != nil || !p.selected {
		t.Fatal("selection changed")
	}
	for _, q := range []struct {
		profile string
		overlay bool
	}{{"", false}, {"tenant", false}, {"local", true}} {
		if _, e := selectLocalPolicy(q.profile, q.overlay); e == nil {
			t.Fatal("unsupported capture policy accepted")
		}
	}
	c, e := record.ParseCorpus(contract.RedactionCorpusV1())
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range c.Entries {
		if p.text(v.Value()) != tapredact.Redact(v.Value()) || p.argument(v.Name, v.Value()) != tapredact.Argument(v.Name, v.Value()) {
			t.Fatal("capture redaction output changed")
		}
	}
	r, e := checkedRuleset()
	shared, se := localpolicy.Ruleset()
	if e != nil || se != nil || r != shared || localPolicyID != localpolicy.ID {
		t.Fatal("capture seal ruleset changed")
	}
	// Compatibility-normalized view text must never enter native sealing.
	if p.text("① Ａ") != "① Ａ" {
		t.Fatal("NFKC introduced into capture")
	}
}
