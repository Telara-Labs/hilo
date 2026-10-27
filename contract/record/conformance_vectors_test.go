package record

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
		{Name: "TestBuildAndParseEveryKind", F: TestBuildAndParseEveryKind},
		{Name: "TestBuildPreservesCorrectionFrontier", F: TestBuildPreservesCorrectionFrontier},
		{Name: "TestExportRepositoryExplicitBodyHeaderMismatchRefused", F: TestExportRepositoryExplicitBodyHeaderMismatchRefused},
		{Name: "TestExportRepositoryIdentityComesOnlyFromSource", F: TestExportRepositoryIdentityComesOnlyFromSource},
		{Name: "TestExportRepositoryRedactedRemoteCannotChangeIdentity", F: TestExportRepositoryRedactedRemoteCannotChangeIdentity},
		{Name: "TestExportRepositoryUsesCanonicalWireIdentity", F: TestExportRepositoryUsesCanonicalWireIdentity},
		{Name: "TestGenesisAuthorityFieldWireRules", F: TestGenesisAuthorityFieldWireRules},
		{Name: "TestHAndKeys", F: TestHAndKeys},
		{Name: "TestOptionalGenesisStillRejectsEmptyNullAndWrongWireTypes", F: TestOptionalGenesisStillRejectsEmptyNullAndWrongWireTypes},
		{Name: "TestParseCorpusRejects", F: TestParseCorpusRejects},
		{Name: "TestParseRejections", F: TestParseRejections},
		{Name: "TestProductionEventDerivationMatchesFrozenVector", F: TestProductionEventDerivationMatchesFrozenVector},
		{Name: "TestProtectedEventSaltAndFailure", F: TestProtectedEventSaltAndFailure},
		{Name: "TestRedactBeforeBoundaryAndActualGolden", F: TestRedactBeforeBoundaryAndActualGolden},
		{Name: "TestReducersAndClasses", F: TestReducersAndClasses},
		{Name: "TestRegenerateV3Fixtures", F: TestRegenerateV3Fixtures},
		{Name: "TestRulesetFingerprintAndGolden", F: TestRulesetFingerprintAndGolden},
		{Name: "TestSalt", F: TestSalt},
		{Name: "TestUnknownBodyFieldRejected", F: TestUnknownBodyFieldRejected},
		{Name: "TestV3BuildRejectsInvalidUTF8BeforeClone", F: TestV3BuildRejectsInvalidUTF8BeforeClone},
		{Name: "TestV3CallCommitmentGeneralJSON", F: TestV3CallCommitmentGeneralJSON},
		{Name: "TestV3CallCommitmentsAndSignedDependencies", F: TestV3CallCommitmentsAndSignedDependencies},
		{Name: "TestV3CallRefInternalEntropyAndFailure", F: TestV3CallRefInternalEntropyAndFailure},
		{Name: "TestV3ExportMetadataAndRegrant", F: TestV3ExportMetadataAndRegrant},
		{Name: "TestV3ExportSessionUsesOnlyManifestPointers", F: TestV3ExportSessionUsesOnlyManifestPointers},
		{Name: "TestV3IndependentSecretsEveryBody", F: TestV3IndependentSecretsEveryBody},
		{Name: "TestV3IssuedOperationTokens", F: TestV3IssuedOperationTokens},
		{Name: "TestV3KeyedTextBeforeTruncation", F: TestV3KeyedTextBeforeTruncation},
		{Name: "TestV3MinimalPublicKeyFacts", F: TestV3MinimalPublicKeyFacts},
		{Name: "TestV3NestedEnumsAndPolicyCredentials", F: TestV3NestedEnumsAndPolicyCredentials},
		{Name: "TestV3OperationSnapshotRejectsInvalidState", F: TestV3OperationSnapshotRejectsInvalidState},
		{Name: "TestV3OptionalOmissionAndPointerZeros", F: TestV3OptionalOmissionAndPointerZeros},
		{Name: "TestV3RecursiveClosedSchemaShapes", F: TestV3RecursiveClosedSchemaShapes},
		{Name: "TestV3RequiredTaskStatusAdmission", F: TestV3RequiredTaskStatusAdmission},
		{Name: "TestV3SelfReviewCallRefHasNoPublicEntropyOverride", F: TestV3SelfReviewCallRefHasNoPublicEntropyOverride},
		{Name: "TestV3TokenFailureIsAtomic", F: TestV3TokenFailureIsAtomic},
	}
	executed := 0
	for _, v := range r.Vectors {
		for _, sel := range v.Tests {
			if sel.Package != "./record" {
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
