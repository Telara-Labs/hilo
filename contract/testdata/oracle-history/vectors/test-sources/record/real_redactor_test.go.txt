package record

import (
	"encoding/json"
	tapredact "github.com/Telara-Labs/TAP-Runtime/discover/redact"
	"os"
	"strings"
	"testing"
)

type actualRedactor struct{}

func (actualRedactor) Redact(s string) string                  { return tapredact.Redact(s) }
func (actualRedactor) Argument(n, s string) string             { return tapredact.Argument(n, s) }
func (actualRedactor) Profiles() []string                      { return nil }
func (actualRedactor) RedactProfile(_ string, s string) string { return tapredact.Redact(s) }
func TestRedactBeforeBoundaryAndActualGolden(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a", 36)
	raw := strings.Repeat("x", 590) + " " + secret + " tail"
	text := SealText(raw, actualRedactor{}, 600)
	if strings.Contains(text.Body, "ghp_") || text.Digest == BodyDigest([]byte(raw)) || !text.Truncated {
		t.Fatalf("redaction must precede byte bound: %+v", text)
	}
	corpus := loadCorpus(t)
	behavior, err := Behavior(corpus, actualRedactor{})
	if err != nil {
		t.Fatal(err)
	}
	up := tapredact.CurrentRuleset()
	current := Ruleset{Epoch: up.Epoch, Digest: up.Digest, Engine: "tap-discover/cd7b481855de", Behavior: behavior}
	rawGolden, err := os.ReadFile("../testdata/redact-corpus-v1/actual-engine-golden.json")
	if err != nil {
		t.Fatalf("golden missing; measured %+v", current)
	}
	var golden Ruleset
	if json.Unmarshal(rawGolden, &golden) != nil {
		t.Fatal("invalid golden")
	}
	if golden != current {
		t.Fatalf("actual engine changed: measured %+v", current)
	}
	changed := current
	changed.Behavior = H("changed-argument-output")
	if CheckGolden(golden, changed) == nil || changed.Fingerprint() == golden.Fingerprint() {
		t.Fatal("Argument behavior must require epoch bump")
	}
}
