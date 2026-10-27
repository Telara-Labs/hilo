package syncnode

import (
	tapredact "github.com/Telara-Labs/TAP-Runtime/discover/redact"
	"strings"
	"testing"
)

func TestNodeExportAdapterUsesEverySharedCorpusCase(t *testing.T) {
	cases := tapredact.Corpus()
	if len(cases) != 903 {
		t.Fatalf("shared corpus count = %d", len(cases))
	}
	redactor := exportRedactor{}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			profile := c.Profile
			if profile == "" {
				profile = "local"
			}
			out := tapredact.Normalize(redactor.RedactProfile(profile, c.Input))
			for _, secret := range c.MustRedact {
				if strings.Contains(out, tapredact.Normalize(secret)) {
					t.Error("export adapter retained a synthetic credential")
				}
			}
			for _, ordinary := range c.MustSurvive {
				if !strings.Contains(out, ordinary) {
					t.Error("export adapter lost required ordinary text")
				}
			}
		})
	}
}
