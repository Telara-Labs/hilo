//go:build !darwin || !cgo

package vault

import (
	"context"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
)

// Other native vaults retain their OS identity across executable changes.
func (*Vault) PrepareUpgrade(context.Context, install.Record, string) error { return nil }
func (*Vault) RecoverUpgrade(context.Context, install.Record) error         { return nil }

func UpgradeHandoffRequired() bool { return false }

func (*Vault) ResumeUpgrade(context.Context, install.Record, string) error { return nil }

func (v *Vault) DeleteForInstall(ctx context.Context, _ install.Record, handle string) error {
	return v.Delete(ctx, handle)
}
