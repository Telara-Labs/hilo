package record

import (
	"os"
	"strings"
	"testing"
)

// toyRedactor is a stand-in engine. The real engine is measured by the node,
// which imports it; the contract module only defines the measurement.
type toyRedactor struct{ argMask string }

func (r toyRedactor) Redact(s string) string {
	for _, p := range []string{"ghp_", "glpat-", "xoxb-", "AKIA"} {
		if i := strings.Index(s, p); i >= 0 {
			return s[:i] + "[REDACTED]"
		}
	}
	return s
}

func (r toyRedactor) Argument(name, value string) string {
	n := strings.ToLower(name)
	if strings.Contains(n, "password") || strings.Contains(n, "key") || strings.Contains(n, "token") {
		return r.argMask
	}
	return r.Redact(value)
}

func (toyRedactor) Profiles() []string { return []string{"push", "email"} }

func (r toyRedactor) RedactProfile(p, s string) string {
	if p == "email" && strings.Contains(s, "@") {
		return "[EMAIL]"
	}
	return r.Redact(s)
}

func loadCorpus(t *testing.T) *Corpus {
	t.Helper()
	raw, err := os.ReadFile("../testdata/redact-corpus-v1/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCorpus(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRulesetFingerprintAndGolden(t *testing.T) {
	c := loadCorpus(t)
	b1, err := Behavior(c, toyRedactor{argMask: "[REDACTED]"})
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := Behavior(c, toyRedactor{argMask: "[REDACTED]"})
	if b1 != b2 || !IsHex64(b1) {
		t.Fatal("behaviour must be deterministic")
	}
	golden := Ruleset{Epoch: 1, Digest: hx("rules"), Engine: "v0.3.0", Behavior: b1}
	// Changing Argument behaviour changes the fingerprint and fails the
	// golden check until the epoch is bumped.
	b3, _ := Behavior(c, toyRedactor{argMask: "***"})
	changed := golden
	changed.Behavior = b3
	if b3 == b1 || changed.Fingerprint() == golden.Fingerprint() {
		t.Fatal("argument behaviour change must change the fingerprint")
	}
	if CheckGolden(golden, changed) == nil {
		t.Fatal("behaviour change without epoch bump must fail")
	}
	changed.Epoch = 2
	if err := CheckGolden(golden, changed); err != nil {
		t.Fatal(err)
	}
	rules := golden
	rules.Digest = hx("rules-2")
	if CheckGolden(golden, rules) == nil {
		t.Fatal("rule change without epoch bump must fail")
	}
	down := golden
	down.Epoch = 0
	if CheckGolden(golden, down) == nil {
		t.Fatal("epoch going down must fail")
	}
	engine := golden
	engine.Engine = "v0.3.1"
	if CheckGolden(golden, engine) != nil || engine.Fingerprint() == golden.Fingerprint() {
		t.Fatal("engine change alone passes the golden check but changes the fingerprint")
	}
	if golden.Fingerprint() != H("ruleset", "1", golden.Digest, "v0.3.0", b1) {
		t.Fatal("fingerprint formula")
	}
}

func TestParseCorpusRejects(t *testing.T) {
	bad := []string{
		`{"version":"v","entries":[]}`,
		`{"version":"v","entries":[{"id":"a","kind":"text","parts":["x"]},{"id":"a","kind":"text","parts":["y"]}]}`,
		`{"version":"v","entries":[{"id":"a","kind":"blob","parts":["x"]}]}`,
		`{"version":"v","entries":[{"id":"a","kind":"argument","parts":["x"]}]}`,
		`{"version":"v","entries":[{"id":"a","kind":"text","name":"n","parts":["x"]}]}`,
		`{"version":"v","extra":1,"entries":[{"id":"a","kind":"text","parts":["x"]}]}`,
	}
	for _, b := range bad {
		if _, err := ParseCorpus([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
}
