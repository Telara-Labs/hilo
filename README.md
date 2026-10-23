# Memory contract

The `mnc/2.0` Go contract lives in `contract/`. It provides
strict canonical JSON, typed records, content identities, signatures and causal
key operations, owner-scoped heads, invalidation and grant inheritance, session
and trust reducers, policy freshness, and pure sync/bundle/replay gates.

The contract reuses the published TAP canonicalizer. Its behavioral golden tests
also exercise the published TAP redactor. It does not provide an installed memory
node, filesystem spool, hosted endpoint, credential bootstrap or age encryption
adapter. Private components under `contract/internal/node/` include a
single-owner SQLite store and a narrow Claude/Codex JSONL capture pipeline.
Capture uses held file descriptors, redaction before sealing, and atomic
store admission with progress and retry receipts. These components have
separate implementation and acceptance gates. They do not provide an
installed collector, model-facing MCP server, synchronization or a running node.

A private byte-budgeted disclosure kernel is under development alongside these
components. Its scope includes separate read and task-write permissions, durable
operation outcomes, conservative exposure records, and current authorization
checks before releasing quoted text. A prepared reply carries no readable text
until release. Design approval is separate from implementation and acceptance
evidence.

The initial fresh-search scope requires positive field completeness from the
fixed task builder. Native transcript fields and generated digests remain outside
fresh search until their provenance gates pass. Permitted quoted lookup has
separate availability checks and labels. Native scope discovery, installed
credentials, qualified echo, token-budget APIs, calibrated retrieval, encryption
and synchronization remain unfinished.

Private development temporarily shares a Go module between the contract and
runtime. The pinned SQLite dependency requires Go 1.26. Pure packages have a
tested dependency boundary against node and database packages, but this does
not make the combined module consumable by Go 1.25. A separate runtime module
and proof of the resulting pure module with the older supported compiler are
required before publication. The earlier pure-only commit `de5bb533ea80`
passed unit tests and vet with the actual Go 1.25.14 compiler in a clean export.
That result does not cover this temporary combined module.

From `contract/`, run `GOWORK=off go test ./...` and `GOWORK=off go vet ./...`.
The shared vector registry and frozen wire fixtures are in `contract/testdata/`.
Run `GOWORK=off go run ./cmd/conformance --pure` for the pure checks. The JSON
report keeps storage and transport release gates marked `INCOMPLETE`; omitting
`--pure` returns exit status 2 while any such gate remains outstanding.

An independent Python runner checks V1–V5 using RFC 8785 and Ed25519 libraries.
Install `contract/conformance/requirements.txt` into an isolated environment,
then run `python3 conformance/python_vectors.py` from `contract/`. A pip
`--target` directory can instead be passed with `--deps`.

The current implementation is under development and has no tagged release.
See `contract/OPEN-QUESTIONS.md` for interpretation and scope notes.

Apache License 2.0. See [LICENSE](LICENSE).
