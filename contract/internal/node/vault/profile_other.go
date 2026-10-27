//go:build !windows && (!darwin || !cgo)

package vault

import "context"

func (v *Vault) putProfile(ctx context.Context, h string, b []byte) error { return v.put(ctx, h, b) }
func (v *Vault) getProfile(ctx context.Context, h string) ([]byte, error) { return v.get(ctx, h) }
func (v *Vault) deleteProfile(ctx context.Context, h string) error        { return v.delete(ctx, h) }
