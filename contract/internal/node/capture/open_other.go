//go:build !linux && !darwin

package capture

import (
	"os"
	"time"
)

type openedUnitHandle struct {
	file    *os.File
	initial os.FileInfo
}

func openUnit(string, string) (*openedUnitHandle, error) { return nil, hold("unsupported_platform") }
func (*openedUnitHandle) close()                         {}
func (*openedUnitHandle) bound() bool                    { return false }
func (*openedUnitHandle) stable() bool                   { return false }
func (*openedUnitHandle) quiet(time.Time) bool           { return false }
