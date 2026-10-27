package peer

import (
	"context"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
)

type secretVault interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}
type guardedVault struct{ secretVault }

// GuardVault keeps the connection's pinned kernel identity checked across native
// custody access immediately before proof creation. Startup has no client PID.
func GuardVault(v secretVault) secretVault { return guardedVault{v} }
func (v guardedVault) Get(ctx context.Context, h string) ([]byte, error) {
	if ctx == nil || v.secretVault == nil {
		return nil, ErrAuthority
	}
	pid := daemon.AuthenticatedPeerPID(ctx)
	var b processBinding
	if pid != 0 {
		b, _ = ctx.Value(bindingKey{}).(processBinding)
		if b == nil || b.check(pid) != nil {
			return nil, ErrAuthority
		}
	}
	secret, e := v.secretVault.Get(ctx, h)
	if e != nil || ctx.Err() != nil || (b != nil && b.check(pid) != nil) {
		clear(secret)
		if e != nil {
			return nil, e
		}
		return nil, ErrAuthority
	}
	return secret, nil
}

// AbandonPlanned preserves the same connection binding around the narrower
// pending-slot recovery operation. A vault without creator evidence refuses.
func (v guardedVault) AbandonPlanned(ctx context.Context, h string) error {
	if ctx == nil || v.secretVault == nil {
		return ErrAuthority
	}
	pid := daemon.AuthenticatedPeerPID(ctx)
	var b processBinding
	if pid != 0 {
		b, _ = ctx.Value(bindingKey{}).(processBinding)
		if b == nil || b.check(pid) != nil {
			return ErrAuthority
		}
	}
	owner, ok := v.secretVault.(interface {
		AbandonPlanned(context.Context, string) error
	})
	if !ok {
		return ErrAuthority
	}
	err := owner.AbandonPlanned(ctx, h)
	if err != nil {
		return err
	}
	if ctx.Err() != nil || (b != nil && b.check(pid) != nil) {
		return ErrAuthority
	}
	return nil
}
