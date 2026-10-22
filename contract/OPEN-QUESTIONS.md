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
