package vault

import (
	"context"
	"errors"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
)

// Installed routes custody operations through the verified receipt-owning image
// on platforms where the executable identity determines the native namespace.
// Each operation revalidates the receipt. The caller holds db.lock.
type Installed struct {
	Vault  *Vault
	Record install.Record
}

func (v Installed) validate(ctx context.Context, handle string) error {
	if e := valid(ctx, handle); e != nil {
		return e
	}
	if v.Vault == nil || v.Vault.closed {
		return ErrUnavailable
	}
	r, e := install.Status(ctx, v.Record.Dir)
	if (e != nil && !errors.Is(e, install.ErrUnavailable)) || r.Record != v.Record {
		return install.ErrUnverified
	}
	return nil
}
func (v Installed) Put(ctx context.Context, handle string, secret []byte) error {
	if len(secret) == 0 || len(secret) > maxSecret {
		return ErrInvalid
	}
	if e := v.validate(ctx, handle); e != nil {
		return e
	}
	return v.put(ctx, handle, secret)
}
func (v Installed) Get(ctx context.Context, handle string) ([]byte, error) {
	if e := v.validate(ctx, handle); e != nil {
		return nil, e
	}
	return v.get(ctx, handle)
}
func (v Installed) Delete(ctx context.Context, handle string) error {
	if e := v.validate(ctx, handle); e != nil {
		return e
	}
	return v.delete(ctx, handle)
}

// DeleteCreatedForInstall handles a provision interrupted before its manifest
// exists. The caller validated the durable creator/handle under db.lock.
func (v *Vault) DeleteCreatedForInstall(ctx context.Context, r install.Record, handle string) error {
	return (Installed{Vault: v, Record: r}).Delete(ctx, handle)
}

// ReadForInstall proves that a legacy bootstrap's receipt image actually has
// custody before its previously unrecorded creator is accepted for deletion.
func (v *Vault) ReadForInstall(ctx context.Context, r install.Record, handle string) ([]byte, error) {
	return (Installed{Vault: v, Record: r}).Get(ctx, handle)
}
