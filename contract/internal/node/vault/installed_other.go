//go:build (!darwin || !cgo) && !linux

package vault

import "context"

func (v Installed) put(ctx context.Context, h string, b []byte) error { return v.Vault.Put(ctx, h, b) }
func (v Installed) get(ctx context.Context, h string) ([]byte, error) { return v.Vault.Get(ctx, h) }
func (v Installed) delete(ctx context.Context, h string) error        { return v.Vault.Delete(ctx, h) }
