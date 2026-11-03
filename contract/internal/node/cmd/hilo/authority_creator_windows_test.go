//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/vault"
)

// Real installer receipt and native Credential Manager operations. Cancelling
// manager discovery prevents service registration in this native unit fixture.
func TestWindowsInstallerCreatorBindingAndBootstrapCustody(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	if e := ipc.ValidateDir(root, true); e != nil {
		t.Fatal(e)
	}
	source := filepath.Join(root, "source.exe")
	raw := []byte("installer-authenticated Windows fixture")
	if e := os.WriteFile(source, raw, 0700); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	data := filepath.Join(root, "data")
	if e := ipc.ValidateDir(data, true); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "install")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, e := install.Install(ctx, install.Config{Dir: dir, Home: root, Executable: source, SHA256: digest, Version: "1", DataDir: data, RunDir: filepath.Join(root, "run"), Label: "dev.memory.windows.fixture"})
	if !errors.Is(e, install.ErrUnavailable) {
		t.Fatal(e)
	}
	if !validAuthorityCreator(report.Record, data) || filepath.Base(report.Record.Executable) != "telara-memory.exe" {
		t.Fatal("installer receipt refused")
	}
	// Stop intent bypasses manager access without weakening receipt verification.
	intent, _ := json.Marshal(map[string]string{"mode": "stop", "sha256": report.Record.SHA256, "version": report.Record.Version, "session": ""})
	if e = os.WriteFile(filepath.Join(dir, "intent.json"), intent, 0600); e != nil {
		t.Fatal(e)
	}
	if e = writePending(data, pendingProfile{Version: 1}); e != nil {
		t.Fatal(e)
	}
	v := installationVault{vault.New(), dir, data}
	ctx = context.Background()
	handleSum := sha256.Sum256([]byte(data))
	handle := hex.EncodeToString(handleSum[:16])
	secret := bytes.Repeat([]byte{4}, 96)
	if e = (provisioningVault{SecretVault: v, data: data}).Put(ctx, handle, secret); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = v.Delete(context.Background(), handle) })
	pending, e := readPending(data)
	if e != nil || pending.Creator == nil || *pending.Creator != report.Record {
		t.Fatal("creator not durable", e)
	}
	got, e := v.Get(ctx, handle)
	defer clear(got)
	if e != nil || !bytes.Equal(got, secret) {
		t.Fatal("native readback", e)
	}
	if e = v.Delete(ctx, handle); e != nil {
		t.Fatal(e)
	}
}
