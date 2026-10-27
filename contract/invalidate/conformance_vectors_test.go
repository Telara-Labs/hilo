package invalidate

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
		{Name: "TestAncestryPendingAndRebuild", F: TestAncestryPendingAndRebuild},
		{Name: "TestAuthority", F: TestAuthority},
		{Name: "TestClosure", F: TestClosure},
		{Name: "TestClosureCancellationR16", F: TestClosureCancellationR16},
		{Name: "TestCompactCausesMatchExplicitClosuresR17", F: TestCompactCausesMatchExplicitClosuresR17},
		{Name: "TestDistinctOverlappingRetractionsR17", F: TestDistinctOverlappingRetractionsR17},
		{Name: "TestErasureChainEveryOrder", F: TestErasureChainEveryOrder},
		{Name: "TestErasureSelectorKinds", F: TestErasureSelectorKinds},
		{Name: "TestEvaluationBudgetsR17", F: TestEvaluationBudgetsR17},
		{Name: "TestEvaluationCacheTracksSupplementalFactsAndExposureR16", F: TestEvaluationCacheTracksSupplementalFactsAndExposureR16},
		{Name: "TestEvaluationCancellationDoesNotCachePartialResultR16", F: TestEvaluationCancellationDoesNotCachePartialResultR16},
		{Name: "TestEvaluationWorkAndCacheR16", F: TestEvaluationWorkAndCacheR16},
		{Name: "TestEventErasedFailsClosedOnEvaluationAndMaterializationRefusal", F: TestEventErasedFailsClosedOnEvaluationAndMaterializationRefusal},
		{Name: "TestEventOccurrenceErasureAndRecaptureBan", F: TestEventOccurrenceErasureAndRecaptureBan},
		{Name: "TestInvalidationAmplificationR17", F: TestInvalidationAmplificationR17},
		{Name: "TestLateAuthenticatedGrantResolvesPending", F: TestLateAuthenticatedGrantResolvesPending},
		{Name: "TestLateExposureAndOwnerScopedAbsentTask", F: TestLateExposureAndOwnerScopedAbsentTask},
		{Name: "TestLegacyCauseCopyBudgetDoesNotPublishPartialOrPoisonCache", F: TestLegacyCauseCopyBudgetDoesNotPublishPartialOrPoisonCache},
		{Name: "TestLegacyCauseMaterializationIsCompleteAndDetached", F: TestLegacyCauseMaterializationIsCompleteAndDetached},
		{Name: "TestLegacyEvaluationRefusalIsNonNilAndNeverLive", F: TestLegacyEvaluationRefusalIsNonNilAndNeverLive},
		{Name: "TestLineageHold", F: TestLineageHold},
		{Name: "TestOpCacheRows", F: TestOpCacheRows},
		{Name: "TestOrderIndependenceProperty", F: TestOrderIndependenceProperty},
		{Name: "TestPendingToHoldTransitiveSemanticClosure", F: TestPendingToHoldTransitiveSemanticClosure},
		{Name: "TestPublicEvaluationCancellationWinsOverCachedSnapshots", F: TestPublicEvaluationCancellationWinsOverCachedSnapshots},
		{Name: "TestPublicEvaluationsDetachMapsSlicesAndCompactMembership", F: TestPublicEvaluationsDetachMapsSlicesAndCompactMembership},
		{Name: "TestRetractionClosureAndReplacement", F: TestRetractionClosureAndReplacement},
		{Name: "TestUnresolvedSemanticAncestryAndDuplicateGrants", F: TestUnresolvedSemanticAncestryAndDuplicateGrants},
		{Name: "TestV3CallOriginAncestryNeverDefaultEmpty", F: TestV3CallOriginAncestryNeverDefaultEmpty},
		{Name: "TestV3MissingMembershipAllNamespacesRequired", F: TestV3MissingMembershipAllNamespacesRequired},
		{Name: "TestV3MissingMembershipSessionBanRecovery", F: TestV3MissingMembershipSessionBanRecovery},
		{Name: "TestV3SignedCrossDeviceEventErasure", F: TestV3SignedCrossDeviceEventErasure},
		{Name: "TestV3SupplementalCoveragePendingAndRecovery", F: TestV3SupplementalCoveragePendingAndRecovery},
		{Name: "TestWithdrawalBeforeFirstArrival", F: TestWithdrawalBeforeFirstArrival},
		{Name: "TestWithdrawalByGrant", F: TestWithdrawalByGrant},
	}
	executed := 0
	for _, v := range r.Vectors {
		for _, sel := range v.Tests {
			if sel.Package != "./invalidate" {
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
