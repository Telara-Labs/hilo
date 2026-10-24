//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/vault"
	"os"
	"path/filepath"
	"strings"
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

func TestInstallationBindingRefusesChangedCreatorAndPreservesPending(t *testing.T) {
	r, p := installedFixture(t)
	// Stopped intent makes receipt verification independent of manager availability.
	writeJSONFixture(t, filepath.Join(r.Dir, "intent.json"), map[string]string{"mode": "stop", "sha256": r.SHA256, "version": r.Version, "session": ""})
	v := installationVault{vault.New(), r.Dir, p.Data}
	ctx := context.Background()
	if e := writePending(p.Data, pendingProfile{Version: 1}); e != nil {
		t.Fatal(e)
	}
	bound, e := v.bound(ctx)
	if e != nil || bound.Record != r {
		t.Fatal("installed target not selected", e)
	}
	creator := r
	creator.SHA256 = strings.Repeat("a", 64)
	creator.Executable = filepath.Join(r.Dir, "bin", creator.SHA256, "telara-memory")
	h := strings.Repeat("b", 32)
	if e = writePending(p.Data, pendingProfile{Version: 1, Handle: h, Creator: &creator}); e != nil {
		t.Fatal(e)
	}
	if _, e = v.bound(ctx); !errors.Is(e, install.ErrUnverified) {
		t.Fatal("changed creator selected", e)
	}
	before, e := os.ReadFile(filepath.Join(p.Data, pendingAuthority))
	if e != nil {
		t.Fatal(e)
	}
	if e = deleteNeverAdmittedAuthority(ctx, p.Data, installedDeletionVault{vault.New(), r}); !errors.Is(e, install.ErrUnverified) {
		t.Fatal("deleted without verified creator", e)
	}
	after, e := os.ReadFile(filepath.Join(p.Data, pendingAuthority))
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("failed cleanup discarded creator evidence", e)
	}
}

func TestReadinessRejectsActualDiagnosticDaemon(t *testing.T) {
	p := testPaths(t)
	process := launch(t, binary, "daemon", "--data-dir", p.Data, "--run-dir", p.Run)
	_ = process
	live := waitReady(t, p)
	if authorityReady(live) {
		t.Fatal("diagnostic daemon wired a store")
	}
	ctx, c := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer c()
	var out bytes.Buffer
	if e := waitReadiness(ctx, p, &out); e == nil || out.Len() != 0 {
		t.Fatal("diagnostic process accepted as installed readiness", e, out.String())
	}
}
