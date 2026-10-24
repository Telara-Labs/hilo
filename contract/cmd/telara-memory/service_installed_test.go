package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp"
)

// Disposable test vault, not installed OS credential custody. Production must
// receive a concrete trusted vault and peer verifier from the installer.
type serviceVault struct{ values map[string][]byte }

func (v *serviceVault) Put(_ context.Context, k string, b []byte) error {
	if v.values == nil {
		v.values = map[string][]byte{}
	}
	if v.values[k] != nil {
		return errors.New("exists")
	}
	v.values[k] = append([]byte(nil), b...)
	return nil
}
func (v *serviceVault) Get(_ context.Context, k string) ([]byte, error) {
	if v.values[k] == nil {
		return nil, errors.New("absent")
	}
	return append([]byte(nil), v.values[k]...), nil
}
func (v *serviceVault) Delete(_ context.Context, k string) error {
	clear(v.values[k])
	delete(v.values, k)
	return nil
}

type servicePeer struct{}

func (servicePeer) VerifyAndDrain(context.Context, ipc.Hello, string) error {
	return errors.New("no test transport authority")
}
func TestProductionOpenerUsesInstalledRuntime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite privacy has no Windows runtime proof")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(base, "data")
	vault := &serviceVault{}
	t.Cleanup(func() {
		for k, b := range vault.values {
			clear(b)
			delete(vault.values, k)
		}
	})
	if err = disclosure.BootstrapInstalled(context.Background(), data, "Production opener unit", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{}, vault); err != nil {
		t.Fatal(err)
	}
	provider := mcp.InstalledRuntimeProvider{Provider: disclosure.InstalledProvider{Dir: data, Vault: vault, Peers: servicePeer{}}}
	b, err := existingOpener(data, provider)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wired, ok := b.(interface{ StoreWired() bool })
	if !ok || !wired.StoreWired() {
		b.Close()
		t.Fatal("installed real store not wired")
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	// An unavailable installed authority is a diagnostic backend and never
	// creates or silently reinitializes a database.
	absent := filepath.Join(base, "absent")
	b, err = existingOpener(absent, nil)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.(interface{ StoreWired() bool }).StoreWired() {
		t.Fatal("missing authority claimed readiness")
	}
	if _, err = os.Stat(absent); !os.IsNotExist(err) {
		t.Fatal("missing authority created profile", err)
	}
}
