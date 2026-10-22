# Open questions on the contract

Places where the specification (`mnc/1.x`) is ambiguous, silent or, as far as
this implementation can tell, wrong. Each entry states the reading this
module implements. Where a choice was needed, the more conservative reading
was taken: reject rather than accept, fail closed rather than open.

## Canonical JSON

**Q1. Own canonicalizer instead of importing an upstream one.** The
specification says the strict gate runs and then calls an existing RFC 8785
encoder from another module. Importing that module would bring three
third-party dependencies into this one, and its strictness fixes are not yet
released. This module therefore carries its own RFC 8785 encoder (package
`jcs`). It was cross-checked byte for byte against the upstream encoder on
16,000 generated documents, and the shared V1 vectors keep the two in step.

**Q2. Noncharacters.** I-JSON (RFC 7493 §2.1) forbids Unicode noncharacters
(U+FDD0-U+FDEF and every U+xxFFFE, U+xxFFFF). The specification lists invalid
UTF-8, lone surrogates, duplicate keys and trailing data, but asks for a
"valid I-JSON value". The gate rejects noncharacters too. A producer must
replace them before sealing.

**Q3. Nesting depth.** Not specified. The gate rejects nesting deeper than 64
arrays or objects.

**Q4. Number underflow.** A nonzero literal that rounds to zero (`1e-400`) is
rejected as out of range, the same as overflow. Records allow only integers,
so this matters only for the general gate.

**Q5. Trailing whitespace.** "Reject trailing data" is read as: JSON
whitespace after the value is allowed, anything else is rejected. A byte
order mark is rejected.

## Record envelope

**Q6. Empty structs in the header.** The specification's Go sketch writes
`subj` and `trust` without `omitempty` and `links` with it, while the prose
says "empty optional fields are omitted, never null". Go never omits a
struct for `omitempty`. This module omits every empty optional field,
including empty `subj`, `trust` and `links` objects. Parse re-encodes the
decoded header and requires the same bytes, so a header that writes an empty
object or a zero value (`"findings":0`) is rejected as non-canonical.

**Q7. Member-name case.** Go's decoder matches member names without regard
to case. Parse rejects any header or body member whose spelling differs from
the defined name, so no reader sees a field the author's bytes do not
literally carry.

**Q8. Redaction profile per kind.** Not stated per kind. This module requires
`push-metadata` exactly for the `session` and `task` export variants
(`prov: derived`) and `local` for every other record, including control
records and policies.

**Q9. Call reference alphabet.** "base32" is read as the RFC 4648 alphabet,
lowercased: `m1.` followed by ten characters of `[a-z2-7]`.

**Q10. Event id anchor.** The anchor object always carries every field of its
form (`native_item_id`, `inner`, `part`, or `path`, `line`, `block`, `inner`,
`part`), zero values included, so two implementations cannot disagree about
omission. `line`, `block`, `inner` and `part` are integers.

**Q11. Header-only kinds.** The specification mentions header-only kinds,
but every kind in the union names a body type. This module requires a body
reference on every record; "header-only" is read as a record whose body
bytes are absent (never received, or purged). Its id is unchanged.

**Q12. Request conclusion LID.** The LID uses `request_key`, but the
conclusion body's `request` field is described as the redacted prompt text
(at most 1000 bytes), not the request key. The receiver therefore cannot
recompute this LID and does not check it. A body field carrying the request
key would close this.

**Q13. Provenance of key operations.** The matrix gives `key_op` no
provenance. This module requires `prov: user` for key operations from every
signer role.

**Q14. Owner-scoped LIDs at admission.** The owner comes from the verified
signer, so `Parse` cannot recompute task, checkpoint, pause, explicit
conclusion and rollup LIDs. The signature verifier recomputes and checks
them once it knows the signer.

**Q15. Machine id of service-signed records.** Service-signed (`gateway`)
checkpoints have no machine, yet the checkpoint LID includes
`author.machine_id`. This module allows an empty machine id for service
signers and hashes the empty string.

**Q16. Control records carry no links.** Control records are "never
versioned"; this module rejects any `links` on them.

**Q17. Ruleset behaviour encoding.** The behaviour hash is over "the JCS list
of outputs of Redact, Argument and each profile over the corpus". This
module fixes the list as `[entry id, function, output]` triples: one per
entry in corpus order (`redact` for text entries, `argument` for argument
entries), then one per (profile, entry) with profiles sorted by name and
function `profile:<name>`. The real engine lives in another module whose
epoch API is not yet released, so the golden test over the real engine runs
in the node; this module tests the measurement with a stand-in engine.

**Q18. Revoke reasons.** The enum is not listed. This module accepts
`compromised` (which cascades), `lost` and `user_request`; `conflict` is
reserved for the key-state fold.

**Q19. Session end consistency.** `end` and `ended_at` are required to be
set together.

**Q20. zstd bodies.** Bodies travel zstd-compressed, but zstd is not in the
Go standard library. The contract module takes decompressed body bytes; the
transport layer decompresses and must stop at 1 MiB + 1 byte.

## Signing and keys

**Q21. Tenant key roots.** `Parents` is "empty only for genesis", but a
`tenant_key` op is pinned from the login response and has no keyring
history either. This module allows empty parents exactly for `genesis` and
`tenant_key`; `tenant_key_rotate` names the op it rotates from as a parent.

**Q22. Compromise cascade depth.** "A `compromised` revoke of K also revokes
every key whose `device_add` was authorized only by K." This module applies
the cascade transitively (a key revoked by cascade cascades in turn) and only
through `device_add`, not through rotations authorized by K.

**Q23. Revocation time.** §4.4 compares a receipt's `accepted_at` with
`revoked_at`, which is not defined. This module uses the smallest header
`at` among the ops that revoke the key, and for the admission-order test the
smallest local admission sequence among those ops. A revoke op's `at` is
author-asserted.

**Q24. Signature count on key operations.** Exactly the required signatures
are accepted: one for `genesis`, `device_revoke`, `tenant_key` and
`tenant_key_rotate`, two for `device_add` and `device_rotate`. Extra
signatures are rejected.

**Q25. Machine on service-signed records.** The machine check applies to
device keys. This module also requires service and policy signed records
(and key ops authored by them) to carry no machine id.

**Q26. Device revocation by a service key.** "OR TSK" is read as any active
service key of a tenant the node has pinned at login.

**Q27. Genesis pinning order.** With no pinned genesis the first genesis op
added pins itself, as specified. That choice depends on arrival order; it is
a local trust decision, and a node that already pins a genesis is
order-independent.

## Invalidation

**Q28. "Its own records" for retraction.** Read as records whose verified
signer has the same owner (the same genesis for devices, the same tenant for
service keys), so a rotated device can still retract what it wrote before
the rotation. This grants nothing an erasure by the same identity could not
already do.

**Q29. Ids listed before the record arrives.** Retraction and withdrawal
list exact ids. This module applies a listed id whenever the record arrives,
not only if it was present when the control was applied, so the outcome does
not depend on arrival order. The authority check runs when the record is
known.

**Q30. Withdrawal with `all`.** Applied to the records present when the
withdrawal was applied. Records that arrive later with the same grant are
re-issued content and stay live (no lift in v1). This is the one input whose
effect depends on local order, by design.

**Q31. One id, several controls.** When several controls invalidate the same
id, the tomb keeps the strongest kind (erased, then withdrawn, then
retracted) and, among equals, the smallest control id as the cause, so the
tomb row is the same on every replica.

**Q32. TSK closure bound.** R5.4 says a TSK-signed control never purges a
record whose grants lack its tenant. This module applies that bound to the
whole closure of a TSK-signed erasure or withdrawal, not only to its direct
targets.

**Q33. Lineage-hold boundaries.** "Covering seq after that event" is read as
a record whose highest covered session seq is strictly greater than the seq
of the event that recalled the invalidated id. For delivered sets, "admitted
after" compares local admission sequence numbers.

## Tenant policy

**Q34. Equal-sequence tamper.** "Equal `Seq` with a different id is a tamper
event" does not say which policy applies. Keeping the first one seen would
make the outcome depend on arrival order. This module marks the chain
tampered and fails closed (as stale) until a policy with a higher sequence
arrives.

**Q35. Blocked-repo globs.** The glob syntax of `remote_glob` and
`allow_repos` is not specified. This module uses Go `path.Match` syntax over
the normalized remote. A malformed blocked-repo glob blocks everything; a
malformed allow glob allows nothing.

**Q36. "Invalid" policy state.** "If none is valid, the node behaves as
stale." This module reports `invalid` (fail closed) only when a policy was
offered and none verified; a node that never received a policy has no tenant
restrictions.

**Q37. Monotonic input.** Trusted time takes the monotonic reading as a
millisecond count supplied by the caller, since Go does not expose its
monotonic clock as a number.
