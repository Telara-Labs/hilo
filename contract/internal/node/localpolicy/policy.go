// Package localpolicy is the concrete LOCAL policy shared by node adapters.
// It never accepts caller rules, profiles, overlays, or redaction callbacks.
package localpolicy

import (
	"encoding/json"

	tapredact "github.com/Telara-Labs/TAP-Runtime/discover/redact"
	contract "github.com/Telara-Labs/telara-memory/contract"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

const Engine = "tap-discover/d4bd1496f20d"
const ID = Engine + "/local"

type policyError struct{}

func (policyError) Error() string { return "local_policy_unavailable" }

// Policy must be selected and golden-verified before use by a runtime factory.
type Policy struct {
	selected bool
	rules    record.Ruleset
}

func New(profile string, tenantOverlay bool) (Policy, error) {
	if profile != "local" || tenantOverlay {
		return Policy{}, policyError{}
	}
	r, err := Ruleset()
	if err != nil {
		return Policy{}, err
	}
	return Policy{true, r}, nil
}
func (p Policy) Selected() bool          { return p.selected }
func (p Policy) Ruleset() record.Ruleset { return p.rules }

// Text and Argument preserve the published TAP output exactly. No view
// normalization or display fitting belongs at this sealing/argument boundary.
func Text(s string) string                 { return tapredact.Redact(s) }
func Argument(name, value string) string   { return tapredact.Argument(name, value) }
func (Policy) Text(s string) string        { return Text(s) }
func (Policy) Argument(n, s string) string { return Argument(n, s) }

type measured struct{}

func (measured) Redact(s string) string      { return Text(s) }
func (measured) Argument(n, s string) string { return Argument(n, s) }
func (measured) Profiles() []string          { return tapredact.CurrentRuleset().Profiles() }
func (measured) RedactProfile(profile string, s string) string {
	return tapredact.CurrentRuleset().RedactProfile(profile, s)
}

// Ruleset uses immutable embedded accessors, never the mutable compatibility
// variable. Failures are finite and contain none of the corpus input.
func Ruleset() (record.Ruleset, error) {
	var empty record.Ruleset
	c, e := record.ParseCorpus(contract.RedactionCorpusV1())
	if e != nil {
		return empty, policyError{}
	}
	b, e := record.Behavior(c, measured{})
	if e != nil {
		return empty, policyError{}
	}
	u := tapredact.CurrentRuleset()
	actual := record.Ruleset{Epoch: u.Epoch, Digest: u.Digest, Engine: Engine, Behavior: b}
	var expected record.Ruleset
	if json.Unmarshal(contract.RedactionGoldenV1(), &expected) != nil || expected != actual || record.CheckGolden(expected, actual) != nil {
		return empty, policyError{}
	}
	return actual, nil
}
