package localpolicy

import (
	tapredact "github.com/Telara-Labs/TAP-Runtime/discover/redact"
	"strings"
	"testing"
)

func TestNodeLocalAdapterUsesSharedCorpus(t *testing.T) {
	cases := tapredact.Corpus()
	if len(cases) != 903 {
		t.Fatalf("shared corpus count = %d", len(cases))
	}
	tested := 0
	for _, c := range cases {
		if c.Profile != "" && c.Profile != "local" {
			continue
		}
		tested++
		t.Run(c.ID, func(t *testing.T) {
			out := tapredact.Normalize(Text(c.Input))
			for _, secret := range c.MustRedact {
				if strings.Contains(out, tapredact.Normalize(secret)) {
					t.Error("local adapter retained a synthetic credential")
				}
			}
			for _, ordinary := range c.MustSurvive {
				if !strings.Contains(out, ordinary) {
					t.Error("local adapter lost required ordinary text")
				}
			}
		})
	}
	if tested != 786 {
		t.Fatalf("local corpus denominator = %d", tested)
	}
}
