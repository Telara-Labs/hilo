//go:build !windows

package store

import "os"

func testPrivacyMode(path string, mode os.FileMode) error { return os.Chmod(path, mode) }
