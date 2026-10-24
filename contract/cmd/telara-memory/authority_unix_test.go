//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"path/filepath"
	"testing"
	"time"
)

func TestAdmittedUninstallCannotBypassSettlement(t *testing.T) {
	r, p := installedFixture(t)
	// No daemon ever wrote a settlement receipt. An admitted marker must never
	// select the never-started shortcut or report success without deleting keys.
	if e := writePending(p.Data, pendingProfile{Version: 1, Handle: "3123456789abcdef0123456789abcdef", Phase: "admitted"}); e != nil {
		t.Fatal(e)
	}
	ctx, c := context.WithTimeout(context.Background(), time.Second)
	defer c()
	e := runService(ctx, []string{"uninstall", "--install-dir", r.Dir}, &bytes.Buffer{}, bytes.NewReader(nil))
	if e == nil {
		t.Fatal("admitted uninstall bypassed settlement")
	}
	if !errors.Is(e, daemon.ErrSettlement) {
		t.Log("safe refusal before manager mutation", e)
	}
	if got, e := readPending(filepath.Clean(p.Data)); e != nil || got.Phase != "admitted" {
		t.Fatal("admission evidence removed", e)
	}
}
