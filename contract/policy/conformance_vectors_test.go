package policy

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
		{Name: "TestAuthenticatedAnchorAcknowledgesPriorWallRegression", F: TestAuthenticatedAnchorAcknowledgesPriorWallRegression},
		{Name: "TestChain", F: TestChain},
		{Name: "TestClockAcceptsLargeRuntimeMonotonicOffsets", F: TestClockAcceptsLargeRuntimeMonotonicOffsets},
		{Name: "TestClockAndFreshness", F: TestClockAndFreshness},
		{Name: "TestClockLargeOffsetsStillRefuseRegressionAndOverflow", F: TestClockLargeOffsetsStillRefuseRegressionAndOverflow},
		{Name: "TestClockRetainsReceiptAndOriginRefusals", F: TestClockRetainsReceiptAndOriginRefusals},
		{Name: "TestEffects", F: TestEffects},
		{Name: "TestV3DatePrecisionFreshnessAndHighWater", F: TestV3DatePrecisionFreshnessAndHighWater},
		{Name: "TestV3OneTenantAndOmittedCeiling", F: TestV3OneTenantAndOmittedCeiling},
		{Name: "TestV3PolicyReplacementLogoutAndTamperFacts", F: TestV3PolicyReplacementLogoutAndTamperFacts},
		{Name: "TestV3RejectsUntrustedDates", F: TestV3RejectsUntrustedDates},
		{Name: "TestV3SelfReviewLogoutTamperAndMonotonicBaseline", F: TestV3SelfReviewLogoutTamperAndMonotonicBaseline},
		{Name: "TestV3SelfReviewUnknownRepoAndGlobalBlock", F: TestV3SelfReviewUnknownRepoAndGlobalBlock},
		{Name: "TestV3TamperBlocksAllTenantReadback", F: TestV3TamperBlocksAllTenantReadback},
		{Name: "TestVerify", F: TestVerify},
	}
	executed := 0
	for _, v := range r.Vectors {
		for _, sel := range v.Tests {
			if sel.Package != "./policy" {
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
