# Contract interpretation and remaining gates

This module implements the pure parts of `mnc/3.0`. The earlier draft's open
questions are resolved as follows.

- Canonical encoding reuses the published strict TAP contract. A narrower gate
  rejects record nulls, noninteger numbers, duplicate members, invalid UTF-8,
  lone surrogates, noncharacters and trailing data. Nesting is bounded to64.
  Typed marshaling rejects invalid strings before Go can repair them.
- Required header `subj` and `trust` use `{}` when empty. Required redaction
  epoch/findings use explicit zero. Empty optional fields remain omitted.
  Member names use exact wire spelling. Unknown header and metadata fields fail.
- A request conclusion carries `request_key` separately from its redacted
  `request` text. Receivers recompute its LID. Verified signer identity scopes
  all task state, references, supersession, graph and cache joins.
- All defined kinds have body schemas. A header-only record is a record whose
  referenced body is absent or erased, preserving its ID. No new bodyless kind
  is invented. Compression belongs to the transport adapter, with a decoded
  size ceiling enforced before parsing.
- Authority bindings use the complete user/genesis/device or issuer-tenant/role/key-ID
  namespace. Shared public key material in another domain never mutates the original
  binding. Trusted issuer context records pinned TLS login or authenticated admission
  provenance and is never selected from wire metadata. Key roles and machine/tenant
  bindings are immutable within that domain. Foreign genesis is
  refused. Causal key operations authorize against their verified history.
  Global revocation is device-only. Compromise and losing rotation branches
  conservatively revoke add/rotate descendants even with alternate authority.
  Retirement cannot restore a revoked key. Caller snapshots never alias stored
  canonical operations or receipt pointers.
- Revocation grandfathering uses prior verified admission or exact signed
  issuer receipts before every relevant revocation receipt. Author timestamps
  confer no authority. Missing cause receipts fail the receipt alternative.
- Authenticated delivery grants are distinct from acceptance receipts. Their
  tenant generation follows copied and recalled content, including duplicate
  deliveries over another route. Withdrawal fences old generations before
  first arrival. A new grant requires newer policy and a new content ID.
- Exposure facts survive delivery dedup, compaction and body deletion. Late
  exposure, binding and controls recompute lineage holds and grant inheritance.
  Pending copied or semantic ancestry remains ineligible for disclosure.
  Present export origins participate in pending traversal; absent origins are
  expected for metadata received without its private source.
- Every new data body, binding, call and policy configuration draws its own
  independent internal CSPRNG16 secret. Every event draws a separate secret.
  No content, LID, operation or device/master key derives these secrets. Retired
  deterministic authoring entry points reject. Import/retry copies exact seals.
  Adapters resolve committed/unknown/erased transition settlement BEFORE authoring.
  Missing committed bodies never license resealing. Historical major2 artifacts
  remain test evidence and are rejected by every major3 admission boundary.
- Text.digest is event-keyed over full redacted text before truncation. Call
  arguments/results use separate keyed domains under the call body's secret.
  Call commitment_deps is required, exactly matches signed derived_from, and
  includes all mutation/input/render roots. Missing ancestry blocks the entire
  comparator, including recursive origin ancestry. Bodyless calls restore no key.
  Comparator copies depend on the call id AND its complete signed dependency set.
- Closed recursive schemas reject nulls, unknown members, wrong types, noncanonical
  optional zero/empty objects and unbounded lists before retaining bodies/facts.
  Controls have finite reasons only; policy credential literals are rejected.
- Signed owner/session/event selectors enforce cross-device bans without the
  issuer chunk. Omitted known membership or unknown selected-body membership keeps
  owner data blocked until authenticated supplemental coverage completes.
  Invalid late bodies must fail the complete parser/signature gates before the
  adapter supplies membership facts. Physical scrub and durable ACK remain adapters.
- Header/envelope3, bundle mnc/3 and HELLO3.0 independently reject legacy artifacts.
  Identity mnc1/sk1/ev1 and signature-format mnc/v1 domains remain unchanged.
- Event corrections use explicit causal revisions. Repacking does not order
  revisions, and conflicts prevent automatic coverage. Settled coverage is a
  verified gap-free prefix; a later missing page does not erase an earlier
  settled prefix. Observed taint is separate from recomputed uncertainty.
- Trusted time consumes measured authenticated configured-origin live responses,
  no-store, exactly one Date, Age absent/zero and a maximum30s monotonic RTT.
  Date-only legacy calls fail closed. Replacement evaluates the old clock first,
  accepts D<W only when D+999+RTT>=W without lowering W, and detects arithmetic or
  wall/monotonic regressions. Persist Floor periodically and at shutdown.
- One active tenant authority applies. Equal-highest verified sequence conflicts
  latch tamper until a higher verified sequence; logout purges current config/salt
  and keeps rollback/tamper facts. Absent push.max_profile means local and cannot
  authorize PUSH or governed bundles. Both directions deny policy-governed full
  bodies; metadata needs current applicable push-metadata authority and all gates.
- Operation tokens come from receiver issuance state bound to an installed
  credential. The pure ledger generates exactly8 fresh tokens per eligible
  initialize, never more than128 unused; no partial issuance or caller entropy.
  Atomic durable issuance/consumption and mutation settlement are adapter gates.
  Syntax-only supplied-op helpers reject. Fallback uses opaque receiver request
  tokens with no arguments or arbitrary wire RPC ids. Erased/keyless replay returns
  one unavailable result before candidate tool/args comparisons, never a new key.
- Hook v3 contains identity/path hints only. Every nonempty native/version/path
  or process argv0 hint requires a client-specific validator plus byte/control
  character bounds. Unknown fields are rejected with content-free diagnostics.
  The adapter additionally resolves symlinks against the known client root.
- Metadata is limited to session and task allowlists. Task metadata carries
  only salt and declared status. Every send checks current disclosure gates,
  including explicit approval rows. Ruleset behavior is measured over the
  shared corpus with the actual published redactor and a pinned golden.

## Temporary runtime boundary

Private development places runtime adapters under `internal/node/` in this
module. Pure packages must not import them or their database dependencies.
The combined module temporarily requires Go 1.26 for its pinned SQLite runtime;
the earlier pure-only commit `de5bb533ea80` passed unit tests and vet with
the actual Go 1.25.14 compiler in a clean export. This does not prove the
combined module's older compiler compatibility. Before publication, split
runtime dependencies into a separate module and verify the resulting pure
module with the older supported compiler. Package isolation alone does not
preserve an older module requirement.

## Adapter obligations

Pure helpers accept already authenticated, verified receiver facts. A caller
must not derive those facts from untrusted transport labels. The pure packages
do not implement database transactions, physical cleanup, authenticated Date
freshness, key storage, DPoP, age encryption, compression or filesystem I/O.
Its in-memory models are single-transaction reference reducers, not concurrent
stores. Adapters must persist authority facts and exposures, verify signatures
and nonce-bound client acknowledgements, and apply each page/mutation atomically.

`testdata/vectors.json` lists all V1–V30 checks, their executable pure tests and
remaining adapter requirements. `cmd/conformance` reports these as incomplete
until the real adapter supplies the missing storage/transport proof. Pure
success never certifies a deployed node or hosted service.

## Major3 adoption boundary

These are pure source/reference guarantees only. Node producers, SQLite schema,
MCP initialization and receipt wiring, real managed bundles/age restore, hosted
contract mirroring and encrypted Postgres admission require separate adoption.
All tenant-derived read channels consume current policy eligibility independently
of client grants; a tamper latch also blocks them after current config is purged.
NewCallRef uses internal CSPRNG entropy and rejects caller readers.
Calls passing a third legacy key argument to Build/ReviseEvent now fail closed,
including nil. Salt, SuppliedOpID and raw RPC identity helpers reject. Use BuildCall
for newly authored commitments and OperationTokens for verified supplied identities.
Physical byte scrubbing in managed artifacts, durable token/transition recovery and
migration of orphan major2 content verifiers remain UNVERIFIED here. Never silently
relabel, rewrap, replay a mutation or relax a retained erasure ban during migration.
