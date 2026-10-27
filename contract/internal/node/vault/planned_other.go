//go:build !linux && !windows && (!darwin || !cgo)

package vault

import "context"

func (*Vault) AbandonPlanned(context.Context, string) error { return ErrUnavailable }
