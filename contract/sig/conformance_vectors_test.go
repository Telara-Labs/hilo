package sig

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
		{Name: "TestAbandonedCausalRebuildChargesAreTransactional", F: TestAbandonedCausalRebuildChargesAreTransactional},
		{Name: "TestCausalStateMatchesFullRefoldR17", F: TestCausalStateMatchesFullRefoldR17},
		{Name: "TestCompromiseAndLosingRotationDescendants", F: TestCompromiseAndLosingRotationDescendants},
		{Name: "TestConflictRetirementNeverRevivesLosingRotator", F: TestConflictRetirementNeverRevivesLosingRotator},
		{Name: "TestDeliveryGrantBindings", F: TestDeliveryGrantBindings},
		{Name: "TestDuplicateKeyOpCannotDowngradeIssuer", F: TestDuplicateKeyOpCannotDowngradeIssuer},
		{Name: "TestGitImportIgnoresControl", F: TestGitImportIgnoresControl},
		{Name: "TestHistoryBudgetPrechargesR17", F: TestHistoryBudgetPrechargesR17},
		{Name: "TestKeyOpShapeRejects", F: TestKeyOpShapeRejects},
		{Name: "TestKeySnapshotCopyIsPrechargedWithoutPoisoningCache", F: TestKeySnapshotCopyIsPrechargedWithoutPoisoningCache},
		{Name: "TestKeyringCompromiseCascades", F: TestKeyringCompromiseCascades},
		{Name: "TestKeyringConcurrentRotationLowestIDWins", F: TestKeyringConcurrentRotationLowestIDWins},
		{Name: "TestKeyringDeviceAddNeedsAuthorizer", F: TestKeyringDeviceAddNeedsAuthorizer},
		{Name: "TestKeyringEnrollRotateRevoke", F: TestKeyringEnrollRotateRevoke},
		{Name: "TestKeyringHeldParentsFillLater", F: TestKeyringHeldParentsFillLater},
		{Name: "TestKeyringMutualRevokeRevokesBoth", F: TestKeyringMutualRevokeRevokesBoth},
		{Name: "TestKeyringRevokedAuthorizerCannotAddAfterRevocation", F: TestKeyringRevokedAuthorizerCannotAddAfterRevocation},
		{Name: "TestKeyringSecondGenesisRefused", F: TestKeyringSecondGenesisRefused},
		{Name: "TestLaterLoginUpgradesEarlierUnpinnedRoot", F: TestLaterLoginUpgradesEarlierUnpinnedRoot},
		{Name: "TestLegacyKeyRefusalIsNonNilAndNeverAuthorizes", F: TestLegacyKeyRefusalIsNonNilAndNeverAuthorizes},
		{Name: "TestOmittedGenesisCannotBeFilledBeforeAdmission", F: TestOmittedGenesisCannotBeFilledBeforeAdmission},
		{Name: "TestOmittedGenesisRequiresSubjectPossessionBeforePinning", F: TestOmittedGenesisRequiresSubjectPossessionBeforePinning},
		{Name: "TestOpsAccessorDetached", F: TestOpsAccessorDetached},
		{Name: "TestOptionalGenesisDoesNotSupplyOtherAuthorityDomains", F: TestOptionalGenesisDoesNotSupplyOtherAuthorityDomains},
		{Name: "TestOptionalGenesisKeepsDomainAuthorAndMachineRefusals", F: TestOptionalGenesisKeepsDomainAuthorAndMachineRefusals},
		{Name: "TestOptionalGenesisPreservesSignedWireAndSameAuthority", F: TestOptionalGenesisPreservesSignedWireAndSameAuthority},
		{Name: "TestPublicKeySnapshotsDetachEveryAuthorityMember", F: TestPublicKeySnapshotsDetachEveryAuthorityMember},
		{Name: "TestRetainedHistoryCancellationR17", F: TestRetainedHistoryCancellationR17},
		{Name: "TestRetainedHistoryLinearWorkR17", F: TestRetainedHistoryLinearWorkR17},
		{Name: "TestRevocationCutoffWorkAndCancellationR17", F: TestRevocationCutoffWorkAndCancellationR17},
		{Name: "TestSignedBytes", F: TestSignedBytes},
		{Name: "TestStateOperationSnapshotsDetached", F: TestStateOperationSnapshotsDetached},
		{Name: "TestTenantKeys", F: TestTenantKeys},
		{Name: "TestTenantRootRoleAndDRKDomainsIsolated", F: TestTenantRootRoleAndDRKDomainsIsolated},
		{Name: "TestTenantRotationCannotPoisonDeviceBinding", F: TestTenantRotationCannotPoisonDeviceBinding},
		{Name: "TestTenantSharedSuccessorConflictIsolation", F: TestTenantSharedSuccessorConflictIsolation},
		{Name: "TestV3MalformedBodiesCannotAcquireQuarantine", F: TestV3MalformedBodiesCannotAcquireQuarantine},
		{Name: "TestV3SelfReviewUnknownMajorStillQuarantines", F: TestV3SelfReviewUnknownMajorStillQuarantines},
		{Name: "TestV3SignedEventSelectorOwnerScope", F: TestV3SignedEventSelectorOwnerScope},
		{Name: "TestV6PossessionBootstrapVector", F: TestV6PossessionBootstrapVector},
		{Name: "TestValidityAcrossRevocation", F: TestValidityAcrossRevocation},
		{Name: "TestVerifyRecord", F: TestVerifyRecord},
	}
	executed := 0
	for _, v := range r.Vectors {
		for _, sel := range v.Tests {
			if sel.Package != "./sig" {
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
