package disclosure_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
)

// This unit vault owns disposable test buffers. It does not mock a Telara
// service or claim OS-keystore acceptance. SQLite, daemon, adapter and IPC below
// are the actual implementations.
type unitVault struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (v *unitVault) Put(_ context.Context, id string, b []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.values == nil {
		v.values = map[string][]byte{}
	}
	if v.values[id] != nil {
		return errors.New("exists")
	}
	v.values[id] = append([]byte(nil), b...)
	return nil
}
func (v *unitVault) Get(_ context.Context, id string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.values[id] == nil {
		return nil, errors.New("missing")
	}
	return append([]byte(nil), v.values[id]...), nil
}
func (v *unitVault) Delete(_ context.Context, id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	clear(v.values[id])
	delete(v.values, id)
	return nil
}

type unitPeer struct{}

func (unitPeer) VerifyAndDrain(ctx context.Context, h ipc.Hello, _ string) error {
	if daemon.AuthenticatedPeerPID(ctx) != os.Getpid() || h.PID != os.Getpid() {
		return errors.New("peer")
	}
	return nil
}

type installedAdapter struct{ provider disclosure.InstalledProvider }

func (p installedAdapter) Load(ctx context.Context) (mcp.Runtime, error) {
	r, err := p.provider.Load(ctx)
	if err != nil {
		return mcp.Runtime{}, err
	}
	return mcp.Runtime{Config: r.Config, Material: r.Material, Credentials: r.Credentials}, nil
}

func TestInstalledBootstrapOwnerOnlyPinsVaultAndRealIPCAuthentication(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite privacy adapter has no Windows runtime acceptance")
	}
	ctx := context.Background()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "data")
	vault := &unitVault{}
	if err = disclosure.BootstrapInstalled(ctx, data, "Installed test", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{Actions: []disclosure.TaskMutation{disclosure.Create}, Repos: disclosure.AllLocalRepos(), AllowUnscoped: true}, vault); err != nil {
		t.Fatal(err)
	}
	if err = disclosure.BootstrapInstalled(ctx, data, "again", disclosure.Grant{}, disclosure.TaskWriteGrant{}, vault); err == nil {
		t.Fatal("bootstrap overwrote profile")
	}
	before, err := store.ReadInstalledRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range vault.values {
		if bytes.Contains(before, secret) || bytes.Contains(before, secret[:32]) {
			t.Fatal("private material in public pin record")
		}
	}
	provider := disclosure.InstalledProvider{Dir: data, Vault: vault, Peers: unitPeer{}}
	loaded, err := provider.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Material.Clear()
	if _, err = loaded.Credentials.Proof(ctx, ipc.Hello{PID: os.Getpid(), Client: "trusted-looking"}); err == nil {
		t.Fatal("Hello authenticated outside kernel IPC")
	}
	if err = os.Chmod(filepath.Join(data, "installed-authority.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Load(ctx); err == nil {
		t.Fatal("public authority record accepted")
	}
	if err = os.Chmod(filepath.Join(data, "installed-authority.json"), 0600); err != nil {
		t.Fatal(err)
	}
	paths, err := ipc.Resolve(data, filepath.Join(dir, "run"))
	if err != nil {
		t.Fatal(err)
	}
	live, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	ready := make(chan struct{})
	go func() {
		done <- daemon.Run(live, daemon.Config{Paths: paths, Open: func(ctx context.Context) (daemon.Backend, error) {
			return mcp.Open(ctx, data, installedAdapter{provider})
		}, Ready: func() { close(ready) }})
	}()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		case <-time.After(15 * time.Second):
			t.Error("daemon did not settle")
		}
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(15 * time.Second):
		t.Fatal("daemon not ready")
	}
	conn, err := ipc.Dial(ctx, paths)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	hello := ipc.Hello{T: "hello", V: ipc.WireVersion, Kind: "mcp", PID: os.Getpid(), Client: "untrusted-client-hint"}
	if ipc.WriteFrame(conn, hello) != nil {
		t.Fatal("hello")
	}
	reader := bufio.NewReader(conn)
	if _, err = ipc.ReadFrame(reader); err != nil {
		t.Fatal(err)
	}
	request := daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: json.RawMessage(`{"name":"telara_task_create","arguments":{"goal":"installed credential path"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`)}
	if err = ipc.WriteFrame(conn, request); err != nil {
		t.Fatal(err)
	}
	raw, err := ipc.ReadFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("installed credential path")) || !bytes.Contains(raw, []byte("task_id")) {
		t.Fatalf("installed seam did not authenticate actual adapter %s", raw)
	}
	// Closing the actual transport runs facade retirement after the call settles.
	conn.Close()
	if !strings.Contains(string(before), "vault_handle") {
		t.Fatal("no opaque vault reference")
	}
}
