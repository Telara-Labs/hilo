//go:build linux || darwin

package mcp

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

func TestInstalledCapturePreloadUsesOnlyProvisionedVault(t *testing.T) {
	ctx := context.Background()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ipc.Resolve(filepath.Join(home, "data"), filepath.Join(home, "run"))
	if err != nil {
		t.Fatal(err)
	}
	vault := &adapterVault{}
	if err = disclosure.BootstrapInstalled(ctx, paths.Data, "Capture preload test", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{}, vault); err != nil {
		t.Fatal(err)
	}
	provider := InstalledRuntimeProvider{Provider: disclosure.InstalledProvider{Dir: paths.Data, Vault: vault, Peers: adapterPeer{}}, CaptureHome: home}
	r, err := provider.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Material.Clear()
	defer r.CaptureKeys.Clear()
	if r.CaptureConfig == nil || r.CaptureConfig.Home != home || len(r.CaptureConfig.Roots) != 4 {
		t.Fatal("capture roots not provisioned")
	}
	if r.CaptureConfig.OwnerGenesis != r.Config.OwnerGenesis || r.CaptureConfig.MachineID != r.Config.MachineID {
		t.Fatal("capture authority differs")
	}
	backend, err := Open(ctx, paths.Data, provider)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if !backend.StoreWired() {
		t.Fatal("capture preload not wired")
	}
	stats := backend.CaptureStats()
	if len(stats) != 3 || stats["spool_done"] != 0 {
		t.Fatal("missing diagnostic counters")
	}
	if _, ok := backend.disclosure.source.(captureProofSource); !ok {
		t.Fatal("collector omitted")
	}
	// Loading did not mutate or re-bootstrap the installed authority.
	vault.mu.Lock()
	for _, secret := range vault.values {
		if len(secret) != 96 {
			t.Error("vault record changed")
		}
	}
	vault.mu.Unlock()
}
