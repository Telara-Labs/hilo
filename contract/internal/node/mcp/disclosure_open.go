package mcp

import (
	"context"
	"errors"
	"sync"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/capture"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/syncnode"
)

// Runtime is preloaded by installed authority outside SQLite's writer. Neither
// Open nor the transport bootstraps keys, registers clients or expands grants.
// Material contains a copy; callers remain responsible for their own buffers.
type Runtime struct {
	Config        disclosure.Config
	Material      disclosure.RuntimeMaterial
	Credentials   ProofSource
	CaptureConfig *capture.Config
	CaptureKeys   capture.PreloadedKeyMaterial
	// SyncVault is the installed native vault. Hosted metadata sync runs only
	// with it and an explicitly enabled, enrolled sync profile.
	SyncVault disclosure.SecretVault
}

type RuntimeProvider interface {
	Load(context.Context) (Runtime, error)
}

// InstalledRuntimeProvider adapts the installed authority boundary without
// copying authority into transport hints or bootstrapping a fresh identity.
// The trusted installer must supply its OS vault and verified peer authority.
type InstalledRuntimeProvider struct {
	Provider disclosure.InstalledProvider
	// CaptureHome optionally selects a disposable or explicitly configured home.
	// It never comes from a client's hello or MCP request metadata.
	CaptureHome string
}

func (p InstalledRuntimeProvider) Load(ctx context.Context) (Runtime, error) {
	return p.loadCaptureRuntime(ctx)
}

// Open opens the actual store only with explicitly provisioned runtime authority.
// A missing installed provider leaves discovery/lifecycle available, but all
// memory calls fail closed and readiness reports StoreWired=false.
func Open(ctx context.Context, dir string, provider RuntimeProvider) (*Backend, error) {
	if provider == nil {
		backend := NewDisclosure(nil, nil, nil)
		backend.disclosure.unavailable = "runtime_authority_unavailable"
		return backend, nil
	}
	runtime, err := provider.Load(ctx)
	defer runtime.Material.Clear()
	defer runtime.CaptureKeys.Clear()
	if err != nil {
		return nil, errors.New("runtime_authority_unavailable")
	}
	if runtime.Credentials == nil {
		return nil, errors.New("runtime_authority_unavailable")
	}
	st, err := store.Open(ctx, store.Options{Dir: dir, PinnedGenesisID: runtime.Config.OwnerGenesis, LocalMachineID: runtime.Config.MachineID})
	if err != nil {
		return nil, err
	}
	service, err := disclosure.New(ctx, st, runtime.Config, runtime.Material)
	if err != nil {
		st.Close()
		return nil, err
	}
	source, closeStore, err := openCapture(ctx, dir, st, runtime)
	if err != nil {
		_ = service.Close()
		_ = st.Close()
		return nil, err
	}
	return NewDisclosure(service, source, startSync(ctx, dir, st, runtime, closeStore)), nil
}

// startSync runs the hosted metadata sync worker under this backend. Sync is a
// separate optional boundary: if its state cannot open, local memory still
// serves. The worker stops, and its key copy is cleared, before the store closes.
func startSync(ctx context.Context, dir string, st *store.Store, runtime Runtime, closeStore func() error) func() error {
	if runtime.SyncVault == nil || runtime.CaptureConfig == nil || runtime.CaptureKeys.KeyID() == "" {
		return closeStore
	}
	signer := new(capture.PreloadedKeyMaterial)
	*signer = runtime.CaptureKeys
	worker, err := syncnode.NewWorker(ctx, syncnode.Config{Dir: dir, Store: st, Signer: signer, Vault: runtime.SyncVault})
	if err != nil {
		signer.Clear()
		return closeStore
	}
	worker.Start(context.Background())
	var once sync.Once
	return func() error {
		once.Do(func() {
			_ = worker.Stop()
			signer.Clear()
		})
		return closeStore()
	}
}
