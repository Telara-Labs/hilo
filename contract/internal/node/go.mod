module github.com/Telara-Labs/hilo/contract/internal/node

// The runtime consumes the independently published private C1 pure contract.
// Source acceptance and actual full runtime validation remain separate gates.
go 1.26.0

require (
	filippo.io/age v1.3.2
	github.com/Telara-Labs/TAP-Runtime/discover v0.0.0-20261027173628-b60687139cee
	github.com/godbus/dbus/v5 v5.2.4
	golang.org/x/sys v0.48.0
	golang.org/x/text v0.43.0
	modernc.org/sqlite v1.60.1
)

require github.com/Telara-Labs/TAP-Runtime/contract v0.0.0-20261023010347-cd7b481855de // indirect

require (
	filippo.io/hpke v0.4.0 // indirect
	github.com/Telara-Labs/hilo/contract v0.0.0-20261103163840-2fe5f3e2b944
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.55.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
