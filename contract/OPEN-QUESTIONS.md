# Contract interpretation and remaining gates

This module implements the pure parts of `mnc/2.0`. The earlier draft's open
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
- Event revisions have a body-only salt derived from a fresh internal CSPRNG nonce
  mixed with the existing device salt key. Only the salt is persisted in the erasable
  event body; nonce/HMAC intermediates are discarded. Stored retries/repack copy the
  exact prior seal. Private unexposed candidates may be rebuilt only after recovered
  same-store transition history proves noncommit; unknown settlement and unavailable
  committed bodies never permit resealing. The runtime must retain committed transition
  facts after erasure and check them before stale-progress refusal or minting. Restore
  reconciliation is a separate unimplemented gate. Equality witnesses and complete admitted presence facts retain
  provenance, never salt/payload/hash witnesses. Active causal equality rebuilds from
  identity by least fixed point, so losing parent support deactivates dependent aliases.
  Every managed capture of an erased source occurrence is purged and recapture is
  banned before sealing. Fresh restores lacking erased witnesses fail closed.
- Header/envelope2, bundle mnc/2 and HELLO2.0 gates reject legacy artifacts. Existing
  mnc1/sk1/ev1 hash/identity domains and mnc/v1 signature-format domains keep their
  unchanged primitive versions; the signed header major cannot be overridden.
- Event corrections use explicit causal revisions. Repacking does not order
  revisions, and conflicts prevent automatic coverage. Settled coverage is a
  verified gap-free prefix; a later missing page does not erase an earlier
  settled prefix. Observed taint is separate from recomputed uncertainty.
- Trusted time receives wall and monotonic readings from the adapter. A fresh
  authenticated Date requires its receipt-time wall baseline, acknowledges
  prior rollback and advances without going below the persisted floor. A new
  backward step latches rollback again. Equal policy sequences with different
  IDs fail closed until a higher verified policy. Repo globs use `path.Match`;
  malformed restrictive globs fail closed.
- Supplied operation IDs use the authenticated installed-client credential
  namespace across scope changes/reconnect. First tool and redacted argument
  hash are bound permanently. Eligibility and render freshness are reevaluated
  before replay; no mutation repeats. Confirmed-delivery dedup is generation
  bound and separate from conservative exposure.
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
