//go:build darwin || linux

package mcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

// Disposable unit authority. All storage, disclosure and transport below are
// real implementations. This is not an OS-keystore or installer proof.
type adapterVault struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (v *adapterVault) Put(_ context.Context, key string, b []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.values == nil {
		v.values = map[string][]byte{}
	}
	if v.values[key] != nil {
		return errors.New("exists")
	}
	v.values[key] = append([]byte(nil), b...)
	return nil
}
func (v *adapterVault) Get(_ context.Context, key string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.values[key] == nil {
		return nil, errors.New("missing")
	}
	return append([]byte(nil), v.values[key]...), nil
}
func (v *adapterVault) Delete(_ context.Context, key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	clear(v.values[key])
	delete(v.values, key)
	return nil
}

type adapterPeer struct{ deny bool }

func (p adapterPeer) VerifyAndDrain(ctx context.Context, h ipc.Hello, _ string) error {
	if p.deny || h.PID != os.Getpid() || daemon.AuthenticatedPeerPID(ctx) != h.PID {
		return errors.New("peer denied")
	}
	return nil
}

func TestInstalledRuntimeProviderRealDaemonShim(t *testing.T) {
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p, err := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if err != nil {
		t.Fatal(err)
	}
	vault := &adapterVault{}
	if err = disclosure.BootstrapInstalled(ctx, p.Data, "Installed adapter test", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{Repos: disclosure.AllLocalRepos(), AllowUnscoped: true, Actions: []disclosure.TaskMutation{disclosure.Create}}, vault); err != nil {
		t.Fatal(err)
	}
	provider := InstalledRuntimeProvider{Provider: disclosure.InstalledProvider{Dir: p.Data, Vault: vault, Peers: adapterPeer{}}}
	loaded, err := provider.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Material.Clear()
	if loaded.Credentials == nil {
		t.Fatal("installed credentials absent")
	}
	if proof, err := loaded.Credentials.Proof(ctx, ipc.Hello{PID: os.Getpid()}); err == nil {
		clear(proof.Token)
		t.Fatal("claimed peer bypassed transport")
	}
	w := &adapterWorld{t: t, paths: p}
	runCtx, cancel := context.WithCancel(ctx)
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(runCtx, daemon.Config{Paths: p, Ready: func() { close(ready) }, Open: func(ctx context.Context) (daemon.Backend, error) {
			b, e := Open(ctx, p.Data, provider)
			w.backend = b
			return b, e
		}})
	}()
	select {
	case <-ready:
	case e := <-done:
		cancel()
		t.Fatal(e)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("not ready")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			if e != nil && !errors.Is(e, context.Canceled) {
				t.Error(e)
			}
		case <-time.After(5 * time.Second):
			t.Error("shutdown timeout")
		}
	})
	s := w.session()
	created := goodText(t, s.call("telara_task_create", map[string]any{"goal": "installed provider round trip"}, "", "installed-conversation"))
	if !taskUUIDPattern.MatchString(created) {
		t.Fatal("released task UUID absent", created)
	}
	// The service never bootstraps a replacement authority on missing vault data.
	vault.mu.Lock()
	for key, b := range vault.values {
		clear(b)
		delete(vault.values, key)
	}
	vault.mu.Unlock()
	denied := s.call("telara_task_create", map[string]any{"goal": "must not persist"}, "", "installed-conversation")
	if !denied.IsError || textOf(t, denied) != "identity_unavailable" {
		t.Fatal(denied)
	}
}
func TestInstalledRuntimeProviderFailsClosed(t *testing.T) {
	p := InstalledRuntimeProvider{Provider: disclosure.InstalledProvider{Dir: t.TempDir()}}
	r, err := p.Load(context.Background())
	defer r.Material.Clear()
	if err == nil || err.Error() != "runtime_authority_unavailable" || r.Credentials != nil {
		t.Fatal(err)
	}
	// No key or database may be invented merely by an attempted Open.
	dir := t.TempDir()
	_, err = Open(context.Background(), dir, p)
	if err == nil || err.Error() != "runtime_authority_unavailable" {
		t.Fatal(err)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		t.Fatal("unprovisioned opener wrote files", entries, e)
	}
}
