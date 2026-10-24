//go:build darwin && cgo

package vault

import "context"

func (v Installed) put(ctx context.Context, h string, b []byte) error {
	v.Vault.mu.Lock()
	defer v.Vault.mu.Unlock()
	if e := v.Vault.bindCustody(ctx, v.Record.DataDir, true); e != nil {
		return e
	}
	_, e := v.Vault.imageOperation(ctx, v.Record.Executable, v.Record.SHA256, 1, h, b)
	return e
}
func (v Installed) get(ctx context.Context, h string) ([]byte, error) {
	v.Vault.mu.Lock()
	defer v.Vault.mu.Unlock()
	if e := v.Vault.bindCustody(ctx, v.Record.DataDir, false); e != nil {
		return nil, e
	}
	return v.Vault.imageOperation(ctx, v.Record.Executable, v.Record.SHA256, 9, h, nil)
}
func (v Installed) delete(ctx context.Context, h string) error {
	v.Vault.mu.Lock()
	defer v.Vault.mu.Unlock()
	if e := v.Vault.bindCustody(ctx, v.Record.DataDir, false); e != nil {
		return e
	}
	_, e := v.Vault.imageOperation(ctx, v.Record.Executable, v.Record.SHA256, 3, h, nil)
	return e
}
