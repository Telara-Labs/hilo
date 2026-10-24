package clients

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A private TMPDIR does not make its 0777-created TempDir leaves private.
// Model the loose leaf explicitly without changing the process-global umask.
func TestLinuxLooseTemporaryHomeRejected(t *testing.T) {
	o := options(t, Claude)
	if e := os.Chmod(o.Home, 0775); e != nil {
		t.Fatal(e)
	}
	put(t, filepath.Join(o.Home, ".claude.json"), []byte(`{"mcpServers":{}}`))
	if _, e := Install(context.Background(), o); !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), o.Home) || !strings.Contains(e.Error(), "mode") {
		t.Fatal(e)
	}
	if e := os.Chmod(o.Home, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
}
