package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/capture"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

type nilVault struct{}

func (nilVault) Put(context.Context, string, []byte) error   { return fmt.Errorf("unavailable") }
func (nilVault) Get(context.Context, string) ([]byte, error) { return nil, fmt.Errorf("unavailable") }
func (nilVault) Delete(context.Context, string) error        { return fmt.Errorf("unavailable") }

// The sync worker runs under the backend and stops, clearing its key copy,
// before the store closes. Without installed custody no worker starts.
func TestSyncWorkerLifecycleUnderBackend(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "data")
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	st, err := store.Open(context.Background(), store.Options{Dir: dir, PinnedGenesisID: sig.KeyID(key.Public().(ed25519.PublicKey)), LocalMachineID: "11111111-1111-4111-8111-111111111111"})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capture.PreloadKeys(make([]byte, 32), key)
	if err != nil {
		t.Fatal(err)
	}
	closed := 0
	closeStore := func() error { closed++; return st.Close() }
	runtime := Runtime{CaptureConfig: &capture.Config{}, CaptureKeys: keys}
	if f := startSync(context.Background(), dir, st, runtime, closeStore); fmt.Sprintf("%p", f) != fmt.Sprintf("%p", closeStore) {
		t.Fatal("worker started without installed custody")
	}
	runtime.SyncVault = nilVault{}
	closeAll := startSync(context.Background(), dir, st, runtime, closeStore)
	if err := closeAll(); err != nil || closed != 1 {
		t.Fatalf("close %v %d", err, closed)
	}
	if err := closeAll(); err != nil || closed != 2 {
		t.Fatal("close not retry safe")
	}
}
