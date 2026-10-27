module github.com/Telara-Labs/hilo/contract

// The pure contract has an independent module boundary. C1 preserves the exact
// direct pins; an actual Go 1.25 resolution must establish its selected indirect
// closure before readonly validation or a publication-readiness claim.
go 1.25.0

require (
	github.com/Telara-Labs/TAP-Runtime/contract v0.0.0-20261023010347-cd7b481855de
	github.com/Telara-Labs/TAP-Runtime/discover v0.0.0-20261027173628-b60687139cee
)

require gopkg.in/yaml.v3 v3.0.1 // indirect
