//go:build !darwin && !linux

package doctor

import "testing"

// mainStoreSupported reports that a real main store opens on this platform.
// The store refuses to open where it cannot make its files private.
const mainStoreSupported = false

// stoppedStore has no main store to initialize on this platform.
func stoppedStore(*testing.T, string) {}
