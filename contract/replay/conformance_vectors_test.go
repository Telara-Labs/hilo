package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	contractdata "github.com/Telara-Labs/hilo/contract"
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
		{Name: "TestComparatorDependencyUnion", F: TestComparatorDependencyUnion},
		{Name: "TestDeliveryConfirmationGeneration", F: TestDeliveryConfirmationGeneration},
		{Name: "TestStableOperationAndDisclosureReplay", F: TestStableOperationAndDisclosureReplay},
		{Name: "TestV3ReplayDependencySetBoundaries", F: TestV3ReplayDependencySetBoundaries},
		{Name: "TestV3ReplayRejectsUnsignedInputRoots", F: TestV3ReplayRejectsUnsignedInputRoots},
		{Name: "TestV3ReplayTransferredRenderRootErasure", F: TestV3ReplayTransferredRenderRootErasure},
		{Name: "TestV3SelfReviewCanonicalOperationLinkage", F: TestV3SelfReviewCanonicalOperationLinkage},
	}
	executed := 0
	for _, v := range r.Vectors {
		for _, sel := range v.Tests {
			if sel.Package != "./replay" {
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
