//go:build !linux && !darwin

package capture

import "time"

// Capture's source opener is unavailable on these platforms as well. Never
// replace Windows DACL/handle checks with Unix-style chmod assumptions.
type signalDirectory struct{}

func openSignalDirectory(string, string) (*signalDirectory, error) {
	return nil, hold("unsupported_platform")
}
func (*signalDirectory) close()                      {}
func (*signalDirectory) names() ([]string, error)    { return nil, hold("unsupported_platform") }
func (*signalDirectory) read(string) ([]byte, error) { return nil, hold("unsupported_platform") }
func (*signalDirectory) remove(string) error         { return hold("unsupported_platform") }
func (*signalDirectory) abandon(string, time.Time) (bool, error) {
	return false, hold("unsupported_platform")
}
