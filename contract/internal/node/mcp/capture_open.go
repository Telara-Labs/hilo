package mcp

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	goruntime "runtime"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/capture"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
)

// preloadCaptureVault copies the installed key only during the normal provider
// Load, outside all SQLite writers. Credentials retain the ordinary upstream
// vault for subsequent proofs. No secret file, key export or second bootstrap.
type preloadCaptureVault struct {
	disclosure.SecretVault
	loading bool
	keys    capture.PreloadedKeyMaterial
}

func (v *preloadCaptureVault) Get(ctx context.Context, handle string) ([]byte, error) {
	secret, err := v.SecretVault.Get(ctx, handle)
	if err == nil && v.loading {
		if len(secret) != 96 {
			clear(secret)
			return nil, errors.New("runtime_authority_unavailable")
		}
		keys, e := capture.PreloadKeys(make([]byte, 32), ed25519.PrivateKey(secret[:64]))
		if e != nil {
			clear(secret)
			return nil, errors.New("runtime_authority_unavailable")
		}
		v.keys.Clear()
		v.keys = keys
		keys.Clear()
	}
	return secret, err
}

func (p InstalledRuntimeProvider) loadCaptureRuntime(ctx context.Context) (Runtime, error) {
	if ctx == nil || ctx.Err() != nil || p.Provider.Vault == nil {
		return Runtime{}, errors.New("runtime_authority_unavailable")
	}
	vault := &preloadCaptureVault{SecretVault: p.Provider.Vault, loading: true}
	defer vault.keys.Clear()
	provider := p.Provider
	provider.Vault = vault
	r, err := provider.Load(ctx)
	vault.loading = false
	if err != nil {
		r.Material.Clear()
		return Runtime{}, err
	}
	home := p.CaptureHome
	if home == "" {
		home, err = os.UserHomeDir()
	}
	if err != nil || home == "" {
		r.Material.Clear()
		return Runtime{}, errors.New("runtime_authority_unavailable")
	}
	cfg := capture.Config{Home: home, OwnerGenesis: r.Config.OwnerGenesis, MachineID: r.Config.MachineID, CaptureEnabled: true, Roots: map[string]capture.Root{}}
	for _, client := range []clients.Client{clients.Claude, clients.Codex, clients.Cursor, clients.Pi} {
		// Default discovery preserves existing vendor-root configuration variables.
		// An explicitly supplied home uses that home's default vendor roots only.
		options := clients.Options{Client: client}
		if p.CaptureHome != "" {
			options.Home = home
		}
		rules, e := clients.HookRules(options)
		if e != nil {
			r.Material.Clear()
			return Runtime{}, errors.New("runtime_authority_unavailable")
		}
		name := string(client)
		switch client {
		case clients.Claude:
			name = "claude-code"
		case clients.Cursor:
			name = "cursor-agent"
		}
		cfg.Roots[string(client)] = capture.Root{Client: name, AbsPath: rules.TranscriptRoot}
	}
	return Runtime{Config: r.Config, Material: r.Material, Credentials: r.Credentials, CaptureConfig: &cfg, CaptureKeys: vault.keys, SyncVault: p.Provider.Vault}, nil
}

func openCapture(ctx context.Context, dir string, st *store.Store, runtime Runtime) (ProofSource, func() error, error) {
	if runtime.CaptureConfig == nil || (goruntime.GOOS != "linux" && goruntime.GOOS != "darwin") {
		// No source/DACL opener is implemented on other platforms. Preserve
		// installed peer's safe empty-spool-only behavior rather than denying
		// every memory call even when there are no capture signals.
		return runtime.Credentials, st.Close, nil
	}
	p, err := capture.NewPipeline(ctx, st, *runtime.CaptureConfig, runtime.CaptureKeys)
	if err != nil {
		return nil, nil, err
	}
	collector, err := capture.NewCollector(p, dir)
	if err != nil {
		p.Close()
		return nil, nil, err
	}
	if err = collector.Recover(ctx); err != nil {
		collector.Close()
		return nil, nil, err
	}
	return captureProofSource{source: runtime.Credentials, collector: collector}, func() error {
		if err := collector.Close(); err != nil {
			return err
		}
		return st.Close()
	}, nil
}

type captureProofSource struct {
	source    ProofSource
	collector *capture.Collector
}

func (s captureProofSource) Proof(ctx context.Context, h ipc.Hello) (disclosure.CredentialProof, error) {
	if ctx == nil || ctx.Err() != nil || s.source == nil || s.collector == nil {
		return disclosure.CredentialProof{}, errors.New("capture_unavailable")
	}
	// The peer calls this only after authenticating the installed process. Legacy
	// in-process proof providers still drain after their successful authentication.
	// Each invocation has independent state, never a global current credential.
	drained := false
	ctx = daemon.WithCaptureDrain(ctx, func(ctx context.Context, credential string) error {
		err := s.collector.Drain(ctx, credential)
		if err == nil {
			drained = true
		}
		return err
	})
	proof, err := s.source.Proof(ctx, h)
	if err == nil && !drained {
		err = s.collector.Drain(ctx, proof.CredentialID)
	}
	if err != nil {
		clear(proof.Token)
		return disclosure.CredentialProof{}, errors.New("capture_unavailable")
	}
	return proof, nil
}

// CaptureStats is a lock-free diagnostic snapshot. A health request never waits
// for an active source read, capture writer, or adapter release transaction.
func (b *Backend) CaptureStats() map[string]uint64 {
	if b == nil || b.disclosure == nil {
		return nil
	}
	source, ok := b.disclosure.source.(captureProofSource)
	if !ok || source.collector == nil {
		return nil
	}
	stats := source.collector.Stats()
	return map[string]uint64{"spool_done": stats.Done, "spool_dropped": stats.Dropped, "spool_abandoned": stats.Abandoned, "spool_gap": stats.Gap}
}
