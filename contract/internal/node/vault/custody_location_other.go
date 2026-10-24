//go:build !darwin || !cgo

package vault

import "context"

func (*Vault) bindCustody(context.Context, string, bool) error { return nil }
