//go:build race

package capture

// raceDetector reports a -race build, whose instrumentation inflates
// runtime.MemStats allocation totals.
const raceDetector = true
