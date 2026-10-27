# Independent Go fixture corpus

Fixed signed fixture bytes are pending admitted Go execution. Do not create them with JavaScript or treat a missing corpus as a passing test.

The TEST-ONLY generator is `contract/releaseauth/npm_fixture_test.go`. Its public seed recipe is SHA256 of the ASCII string `telara-memory npm fixture TEST ONLY v1; NEVER RELEASE`. The seed cannot sign releases accepted by the compiled project key. Go signs the valid fixtures through the existing private signer, verifies every positive and negative expectation through the existing private verifier, checks all six authenticated targets and logs one `NPM_RELEASE_AUTH_CORPUS_V1 ` record containing base64 JSON.

After the approved remote compile-first job succeeds, extract that record to `go-release-auth-v1.json`, retain the source snapshot and job receipt, and run the Node fixture tests. Do not regenerate corpus signatures inside Node. Go-accepted noncanonical JSON and base64 fixtures intentionally fail the narrower npm metadata profile.

The separate Node test harness substitutes the corpus public key into an isolated VM copy. Production exports have no public-key argument or test mode and must reject that same corpus.
