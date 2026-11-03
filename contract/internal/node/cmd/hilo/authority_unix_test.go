//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/vault"
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
	if e != nil || bound != r {
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

func TestInstallationVaultRecoversTruncatedManifestThroughProductionWrappers(t *testing.T) {
	for _, action := range []string{"retry", "uninstall"} {
		t.Run(action, func(t *testing.T) {
			r, p := installedFixture(t)
			canonical, e := filepath.EvalSymlinks(p.Data)
			if e != nil {
				t.Fatal(e)
			}
			p.Data, r.DataDir = canonical, canonical
			writeJSONFixture(t, filepath.Join(r.Dir, "install.json"), r)
			writeJSONFixture(t, filepath.Join(r.Dir, "intent.json"), map[string]string{"mode": "stop", "sha256": r.SHA256, "version": r.Version, "session": ""})
			native := &deletionTestCustody{}
			v := installationVault{native, r.Dir, p.Data}
			if e := writePending(p.Data, pendingProfile{Version: 1}); e != nil {
				t.Fatal(e)
			}
			h := strings.Repeat("e", 32)
			if e := (provisioningVault{SecretVault: v, data: p.Data}).Put(context.Background(), h, bytes.Repeat([]byte{5}, 96)); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(p.Data, "installed-authority.json"), []byte("{"), 0600); e != nil {
				t.Fatal(e)
			}
			if action == "retry" {
				e = recoverPending(context.Background(), p.Data, v)
			} else {
				e = deleteNeverAdmittedAuthority(context.Background(), p.Data, installedDeletionVault{native, r})
			}
			if e != nil {
				t.Fatal(e)
			}
			if native.created != 1 || native.installed != 0 || len(native.values) != 0 {
				t.Fatal("production wrapper stranded custody")
			}
			if _, e = readPending(p.Data); !os.IsNotExist(e) {
				t.Fatal("pending retained", e)
			}
		})
	}
}

func TestInstallationCustodySelectionFailureDoesNotPublishHandle(t *testing.T) {
	r, p := installedFixture(t)
	writeJSONFixture(t, filepath.Join(r.Dir, "intent.json"), map[string]string{"mode": "stop", "sha256": r.SHA256, "version": r.Version, "session": ""})
	if e := writePending(p.Data, pendingProfile{Version: 1}); e != nil {
		t.Fatal(e)
	}
	native := &deletionTestCustody{refusePreparation: true}
	v := installationVault{native, r.Dir, p.Data}
	if e := (provisioningVault{SecretVault: v, data: p.Data}).Put(context.Background(), strings.Repeat("a", 32), []byte("probe")); !errors.Is(e, vault.ErrUnavailable) {
		t.Fatal(e)
	}
	pending, e := readPending(p.Data)
	if e != nil || pending.Handle != "" || len(native.values) != 0 {
		t.Fatal("selection failure left unknown custody", e)
	}
	// No Put was attempted, so ordinary provisioning recovery needs no deletion.
	if e = recoverPending(context.Background(), p.Data, v); e != nil {
		t.Fatal(e)
	}
	if native.created != 0 || native.installed != 0 {
		t.Fatal("failed selection attempted native deletion")
	}
}
