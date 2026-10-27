//go:build linux

package vault

import "context"

// AbandonPlanned is restricted by its caller to a validated v2 pending context.
// Linux already persists a random creation generation before CreateItem and an
// exact item path before SetSecret. No record means no native creation attempt;
// it never authorizes a same-name search or deletion of an unrelated item.
func (v *Vault) AbandonPlanned(ctx context.Context, handle string) error {
	if v == nil || ctx == nil || valid(ctx, handle) != nil || v.profile == "" {
		return ErrInvalid
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || v.bindCustody(ctx, v.profile, false) != nil {
		return ErrUnavailable
	}
	m, slot, err := v.linuxEntry(handle)
	if err != nil {
		return err
	}
	if slot == slotNone {
		return nil
	}
	if m.Creation == "" && m.State != "deleted" {
		return ErrUnavailable
	}
	return v.delete(ctx, handle)
}
