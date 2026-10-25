// Package contract carries the shared data of the memory node contract: the
// redaction corpus and the conformance vectors. The contract itself lives in
// the subpackages jcs, record, sig, heads, invalidate, policy and view.
package contract

import _ "embed"

// RedactCorpusV1 is testdata/redact-corpus-v1/corpus.json, the corpus the
// ruleset behaviour fingerprint is computed over (record.Behavior).
var RedactCorpusV1 = RedactionCorpusV1()

//go:embed testdata/redact-corpus-v1/corpus.json
var redactionCorpusV1 string

//go:embed testdata/redact-corpus-v1/actual-engine-golden.json
var redactionGoldenV1 string

// RedactionCorpusV1 returns an independent copy of the embedded corpus. Runtime
// verification uses this immutable source rather than the compatibility variable.
func RedactionCorpusV1() []byte { return []byte(redactionCorpusV1) }

// RedactionGoldenV1 returns an independent copy of the pinned engine's expected
// ruleset. It is contract data, not a caller-selected ruleset or runtime policy.
func RedactionGoldenV1() []byte { return []byte(redactionGoldenV1) }

// ConformanceRegistryDigest pins the registry and its referenced fixture hashes.
const ConformanceRegistryDigest = "7c540ff8f07d94f98f55ee72530656c85e22ecacd52c7fa7d54dcdd6e11d7c6d"

//go:embed testdata/vectors.json
var conformanceRegistry string

func ConformanceRegistry() []byte { return []byte(conformanceRegistry) }
