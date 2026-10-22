// Package contract carries the shared data of the memory node contract: the
// redaction corpus and the conformance vectors. The contract itself lives in
// the subpackages jcs, record, sig, heads, invalidate, policy and view.
package contract

import _ "embed"

// RedactCorpusV1 is testdata/redact-corpus-v1/corpus.json, the corpus the
// ruleset behaviour fingerprint is computed over (record.Behavior).
//
//go:embed testdata/redact-corpus-v1/corpus.json
var RedactCorpusV1 []byte
