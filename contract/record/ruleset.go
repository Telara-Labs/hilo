package record

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	contractdata "github.com/Telara-Labs/telara-memory/contract"
	"sort"
	"strconv"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
)

// Ruleset identifies the redaction behaviour a record was sealed under
// Digest covers rule names and patterns; Engine is the version of the
// module that implements them; Behavior is the hash of what that engine
// actually outputs on the versioned corpus. Replicas compare Fingerprint,
// never Digest alone.
type Ruleset struct {
	Epoch    int
	Digest   string
	Engine   string
	Behavior string
}

// Fingerprint is H("ruleset", epoch, digest, engine, behavior), with the
// epoch written in decimal.
func (r Ruleset) Fingerprint() string {
	return H("ruleset", strconv.Itoa(r.Epoch), r.Digest, r.Engine, r.Behavior)
}

// Redactor is the redaction engine under measurement. The contract module
// does not import an engine; the node and the hosted service pass theirs.
type Redactor interface {
	// Redact redacts free text.
	Redact(text string) string
	// Argument redacts one tool argument value by its name.
	Argument(name, value string) string
	// Profiles lists the extra profile names the engine supports.
	Profiles() []string
	// RedactProfile redacts text with the extra shapes of one profile.
	RedactProfile(profile, text string) string
}

// CorpusEntry is one input of the redaction corpus. The value is the
// concatenation of Parts; storing secret-shaped samples in pieces keeps
// repository secret scanners from flagging the corpus.
type CorpusEntry struct {
	ID    string   `json:"id"`
	Kind  string   `json:"kind"` // text | argument
	Name  string   `json:"name,omitempty"`
	Parts []string `json:"parts"`
	Note  string   `json:"note,omitempty"`
}

// Value returns the entry's input string.
func (e CorpusEntry) Value() string { return strings.Join(e.Parts, "") }

// Corpus is a versioned redaction corpus.
type Corpus struct {
	Version string        `json:"version"`
	Entries []CorpusEntry `json:"entries"`
}

// ParseCorpus decodes and checks a corpus file.
func ParseCorpus(raw []byte) (*Corpus, error) {
	var c Corpus
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("corpus: %w", err)
	}
	if c.Version == "" || len(c.Entries) == 0 {
		return nil, fmt.Errorf("corpus: version and entries are required")
	}
	seen := map[string]bool{}
	for _, e := range c.Entries {
		if e.ID == "" || seen[e.ID] {
			return nil, fmt.Errorf("corpus: entry id %q missing or repeated", e.ID)
		}
		seen[e.ID] = true
		if e.Kind != "text" && e.Kind != "argument" {
			return nil, fmt.Errorf("corpus: entry %s kind %q", e.ID, e.Kind)
		}
		if (e.Kind == "argument") != (e.Name != "") {
			return nil, fmt.Errorf("corpus: entry %s: argument entries, and only they, carry a name", e.ID)
		}
	}
	return &c, nil
}

// Behavior returns hex sha256 of the JCS list of the engine's outputs over
// the corpus. The list holds, for every entry in corpus order, the triple
// [entry id, "redact" or "argument", output], and then, for every profile in
// sorted order and every entry, [entry id, "profile:<name>", output]
// (OPEN-QUESTIONS Q17).
func Behavior(c *Corpus, r Redactor) (string, error) {
	pinned, err := ParseCorpus(contractdata.RedactionCorpusV1())
	if err != nil {
		return "", err
	}
	actual, err := jcs.Marshal(c)
	if err != nil {
		return "", err
	}
	defer clear(actual)
	expected, err := jcs.Marshal(pinned)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(actual, expected) {
		return "", fmt.Errorf("only the public pinned corpus may be fingerprinted")
	}

	var out [][]string
	for _, e := range c.Entries {
		if e.Kind == "argument" {
			out = append(out, []string{e.ID, "argument", r.Argument(e.Name, e.Value())})
		} else {
			out = append(out, []string{e.ID, "redact", r.Redact(e.Value())})
		}
	}
	profiles := append([]string(nil), r.Profiles()...)
	sort.Strings(profiles)
	for _, p := range profiles {
		for _, e := range c.Entries {
			out = append(out, []string{e.ID, "profile:" + p, r.RedactProfile(p, e.Value())})
		}
	}
	b, err := jcs.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("behavior: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// CheckGolden compares the current ruleset with the recorded golden one. A
// change of Digest or Behavior without a higher epoch is an error, as is an
// epoch that went down. A changed Engine alone is allowed: it is in the
// fingerprint, and Behavior shows whether it matters.
func CheckGolden(golden, current Ruleset) error {
	switch {
	case current.Epoch < golden.Epoch:
		return fmt.Errorf("ruleset epoch went down from %d to %d", golden.Epoch, current.Epoch)
	case current.Epoch == golden.Epoch && current.Digest != golden.Digest:
		return fmt.Errorf("ruleset rules changed without an epoch bump (epoch %d)", current.Epoch)
	case current.Epoch == golden.Epoch && current.Behavior != golden.Behavior:
		return fmt.Errorf("ruleset behaviour on the corpus changed without an epoch bump (epoch %d)", current.Epoch)
	}
	return nil
}
