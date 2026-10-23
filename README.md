# Memory contract

The `mnc/2.0` Go contract lives in `contract/`. It provides
strict canonical JSON, typed records, content identities, signatures and causal
key operations, owner-scoped heads, invalidation and grant inheritance, session
and trust reducers, policy freshness, and pure sync/bundle/replay gates.

The contract reuses the published TAP canonicalizer. Its behavioral golden tests
also exercise the published TAP redactor. It does not contain a running memory
node, filesystem spool, hosted endpoint, transport credentials or age encryption
adapter. A private SQLite adapter is being developed under
`contract/internal/node/`; its implementation and acceptance gates are separate
from the passing pure contract checks.

Private development temporarily shares a Go module between the contract and
runtime. The pinned SQLite dependency requires Go 1.26. Pure packages have a
tested dependency boundary against node and database packages, but this does
not make the combined module consumable by Go 1.25. A separate runtime module
and proof with the older supported compiler are required before publication.

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
