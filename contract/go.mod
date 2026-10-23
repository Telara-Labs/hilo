module github.com/Telara-Labs/telara-memory/contract

// Kept small and on an older Go on purpose: other implementations import this
// module to read and verify records, and must not inherit the node's
// dependencies by doing so.
go 1.25.0

require (
	github.com/Telara-Labs/TAP-Runtime/contract v0.0.0-20261023010347-cd7b481855de
	github.com/Telara-Labs/TAP-Runtime/discover v0.0.0-20261023010347-cd7b481855de
)
