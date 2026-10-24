package mcp

import (
	"context"
	"errors"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
)

// Runtime is preloaded by installed authority outside SQLite's writer. Neither
// Open nor the transport bootstraps keys, registers clients or expands grants.
// Material contains a copy; callers remain responsible for their own buffers.
type Runtime struct {
	Config      disclosure.Config
	Material    disclosure.RuntimeMaterial
	Credentials ProofSource
}

type RuntimeProvider interface {
	Load(context.Context) (Runtime, error)
}

// InstalledRuntimeProvider adapts the installed authority boundary without
// copying authority into transport hints or bootstrapping a fresh identity.
// The trusted installer must supply its OS vault and verified peer authority.
type InstalledRuntimeProvider struct{ Provider disclosure.InstalledProvider }

func (p InstalledRuntimeProvider) Load(ctx context.Context) (Runtime, error) {
	r, err := p.Provider.Load(ctx)
	if err != nil {
		return Runtime{}, err
	}
	return Runtime{Config: r.Config, Material: r.Material, Credentials: r.Credentials}, nil
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
	return NewDisclosure(service, runtime.Credentials, st.Close), nil
}
