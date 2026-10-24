//go:build darwin && !cgo

package vault

import "context"

// Security.framework requires the native bridge in cgo builds. Static builds
// remain useful for diagnostics but explicitly refuse installed key custody.
func (*Vault) put(context.Context, string, []byte) error   { return ErrUnavailable }
func (*Vault) get(context.Context, string) ([]byte, error) { return nil, ErrUnavailable }
func (*Vault) delete(context.Context, string) error        { return ErrUnavailable }
