# telara-memory

A local memory node for coding agents. It captures the sessions of the agent
clients you run, keeps them as signed, content-addressed records on your own
machine, and serves them back to any of your clients.

It works standalone, with no account and no telemetry. Sync to a hosted
service is optional and off until you turn it on.

## Layout

| Path | What it is |
|---|---|
| `contract/` | The record contract as a small Go module with no third-party dependencies. Canonical JSON, the record envelope and its kinds, signing and key operations, head selection, erasure and its invalidation closure, the signed policy document, and the conformance vectors. |

The `contract` module is versioned separately so that other implementations,
including a sync server, can import it and run the same conformance vectors.

## Status

Early development. The record format is versioned as `mnc/1.1` and may still
change before the first tagged release.

## License

Apache License 2.0. See [LICENSE](LICENSE).
