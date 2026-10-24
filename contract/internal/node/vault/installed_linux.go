//go:build linux

package vault

import "context"

func (v Installed) put(ctx context.Context, h string, b []byte) error {
	v.Vault.mu.Lock()
	defer v.Vault.mu.Unlock()
	if e := v.Vault.bindCustody(ctx, v.Record.DataDir, false); e != nil {
		return e
	}
	return v.Vault.put(ctx, h, b)
}
func (v Installed) get(ctx context.Context, h string) ([]byte, error) {
	v.Vault.mu.Lock()
	defer v.Vault.mu.Unlock()
	if e := v.Vault.bindCustody(ctx, v.Record.DataDir, false); e != nil {
		return nil, e
	}
	return v.Vault.get(ctx, h)
}
func (v Installed) delete(ctx context.Context, h string) error {
	v.Vault.mu.Lock()
	defer v.Vault.mu.Unlock()
	if e := v.Vault.bindCustody(ctx, v.Record.DataDir, false); e != nil {
		return e
	}
	return v.Vault.delete(ctx, h)
}
