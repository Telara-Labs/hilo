package peer

import (
	"fmt"
	"os"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/install/installtest"
)

// Install fixtures live under the temporary directory, so it must be a root
// the installer trusts (the shared Linux /tmp is not).
func TestMain(m *testing.M) {
	cleanup, err := installtest.UsePrivateTempRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}
