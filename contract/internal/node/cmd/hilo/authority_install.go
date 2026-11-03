package main

import (
	"context"
	"errors"
	"os"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/vault"
)

// Bootstrap runs with writer admission held. Native operations execute in the
// authenticated installed target, including when the invoking CLI is another
// ad hoc build. No secret enters the invoking build's native namespace.
type installationNative interface {
	installationCustody
	PutForInstall(context.Context, install.Record, string, []byte) error
	PrepareForInstall(context.Context, install.Record) error
}

type installationVault struct {
	native    installationNative
	dir, data string
}

func (v installationVault) Custodian(ctx context.Context) (install.Record, error) {
	r, e := install.Status(ctx, v.dir)
	if (e != nil && !errors.Is(e, install.ErrUnavailable)) || !validAuthorityCreator(r.Record, v.data) {
		return install.Record{}, install.ErrUnverified
	}
	return r.Record, nil
}
func (v installationVault) bound(ctx context.Context) (install.Record, error) {
	r, e := v.Custodian(ctx)
	if e != nil {
		return install.Record{}, e
	}
	p, e := readPending(v.data)
	if e != nil && !os.IsNotExist(e) {
		return install.Record{}, e
	}
	if e == nil && p.Handle != "" {
		if p.Creator != nil && *p.Creator != r {
			return install.Record{}, install.ErrUnverified
		}
		// An old interrupted provision lacks proof of the creator's code identity.
		if p.Phase == "provisioning" && p.Creator == nil && vault.UpgradeHandoffRequired() {
			return install.Record{}, install.ErrUnverified
		}
	}
	return r, nil
}
func (v installationVault) PrepareCustody(ctx context.Context) error {
	r, e := v.Custodian(ctx)
	if e != nil {
		return e
	}
	return v.native.PrepareForInstall(ctx, r)
}

func (v installationVault) Put(ctx context.Context, h string, b []byte) error {
	target, e := v.bound(ctx)
	if e != nil {
		return e
	}
	return v.native.PutForInstall(ctx, target, h, b)
}
func (v installationVault) Get(ctx context.Context, h string) ([]byte, error) {
	target, e := v.bound(ctx)
	if e != nil {
		return nil, e
	}
	return v.native.ReadForInstall(ctx, target, h)
}
func (v installationVault) Delete(ctx context.Context, h string) error {
	target, e := v.bound(ctx)
	if e != nil {
		return e
	}
	// Recovery as well as uninstall must retire an interrupted staging slot
	// before clearing bootstrap evidence or rebuilding a never-opened profile.
	return (installedDeletionVault{v.native, target}).Delete(ctx, h)
}

func authorityReady(live daemon.Response) bool {
	fields, ok := live.Result.(map[string]any)
	return ok && live.Error == nil && fields["state"] == "running" && fields["store_wired"] == true
}

var _ disclosure.SecretVault = installationVault{}
