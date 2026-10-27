# Security

Hilo stores records of your agent sessions on your machine, signs
them, and can erase them. Its canonical encoding, record signatures, key
enrollment, erasure rules and policy checks are security boundaries.

## Reporting a vulnerability

Email security@telara.dev. Do not open a public issue. Include the version
or commit you ran, what you did, what happened, and what you expected to be
refused. We acknowledge reports within three business days.

## In scope

- Two different byte strings accepted as the same canonical record, or one
  record accepted under two ids.
- A record, key operation or policy accepted without a valid signature from
  a key allowed to sign it.
- Erased, retracted or withdrawn content that stays readable, or comes back
  through a late or reordered arrival.
- A policy that is expired, rolled back or tampered with being enforced as
  current.
- Anything leaving the machine without the user turning on sync.
