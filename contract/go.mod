module github.com/Telara-Labs/telara-memory/contract

// Private development temporarily includes the node adapter. Before publication,
// move runtime dependencies into a separate module and verify pure consumers
// with the older supported toolchain.
go 1.26.0

require (
	github.com/Telara-Labs/TAP-Runtime/contract v0.0.0-20261023010347-cd7b481855de
	github.com/Telara-Labs/TAP-Runtime/discover v0.0.0-20261023010347-cd7b481855de
	github.com/godbus/dbus/v5 v5.2.4
	golang.org/x/sys v0.48.0
	golang.org/x/text v0.43.0
	modernc.org/sqlite v1.60.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
