package view

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	contractdata "github.com/Telara-Labs/telara-memory/contract"
	"regexp"
	"testing"
)

// Bind the actual internal/external package separately. Root AST proof joins
// both tables and requires every matching source function exactly once.
func TestConformanceVectors(t *testing.T) {
	var r struct {
		Contract string
		Vectors  []struct {
			ID    string
			Tests []struct {
				Package string
				Run     string
			}
		}
	}
	raw := contractdata.ConformanceRegistry()
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != contractdata.ConformanceRegistryDigest || json.Unmarshal(raw, &r) != nil || r.Contract != "mnc/3.0" || len(r.Vectors) != 30 {
		t.Fatal("canonical registry/version/count")
	}
	tests := []testing.InternalTest{
		{Name: "TestAvailableInvalidBodyCannotReauthorizePresence", F: TestAvailableInvalidBodyCannotReauthorizePresence},
		{Name: "TestBindingTopRankTieAndCorrection", F: TestBindingTopRankTieAndCorrection},
		{Name: "TestBodylessInvalidSourceOverridesRetainedHistory", F: TestBodylessInvalidSourceOverridesRetainedHistory},
		{Name: "TestCausalEventRepackingAndConflicts", F: TestCausalEventRepackingAndConflicts},
		{Name: "TestCoverageAndTaintBySequence", F: TestCoverageAndTaintBySequence},
		{Name: "TestEqualCaptureTaintAndComplementaryCoverage", F: TestEqualCaptureTaintAndComplementaryCoverage},
		{Name: "TestEqualityWitnessDependencyInvalidationAndRestart", F: TestEqualityWitnessDependencyInvalidationAndRestart},
		{Name: "TestKnownErasedVersusUnknownPredecessorAndHeadLimit", F: TestKnownErasedVersusUnknownPredecessorAndHeadLimit},
		{Name: "TestLaterMissingPageKeepsEarlierSettledPrefix", F: TestLaterMissingPageKeepsEarlierSettledPrefix},
		{Name: "TestReadBackAndOwnerTaskBoundary", F: TestReadBackAndOwnerTaskBoundary},
		{Name: "TestSaltedIndependentCapturesAndCausalOccurrences", F: TestSaltedIndependentCapturesAndCausalOccurrences},
		{Name: "TestSessionMultiMachineCorrectionSurvivesRepack", F: TestSessionMultiMachineCorrectionSurvivesRepack},
		{Name: "TestV3EqualityRequiresCompleteOwnKeyText", F: TestV3EqualityRequiresCompleteOwnKeyText},
		{Name: "TestV3SelfReviewTruncatedResultCannotEstablishEquality", F: TestV3SelfReviewTruncatedResultCannotEstablishEquality},
		{Name: "TestV3TenantPolicyPrecedesEveryReadChannel", F: TestV3TenantPolicyPrecedesEveryReadChannel},
	}
	executed := 0
	for _, v := range r.Vectors {
		for _, sel := range v.Tests {
			if sel.Package != "./view" {
				continue
			}
			pattern, err := regexp.Compile(sel.Run)
			if err != nil {
				t.Fatal(err)
			}
			for _, test := range tests {
				if pattern.MatchString(test.Name) {
					executed++
					t.Run(v.ID+"/"+test.Name, func(t *testing.T) {
						t.Cleanup(func() {
							if t.Skipped() {
								t.Error("conformance test skipped")
							}
						})
						test.F(t)
					})
				}
			}
		}
	}
	if executed == 0 {
		t.Fatal("no local package conformance matches")
	}
}
