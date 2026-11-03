package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/peer"
)

func provisionAuthority(ctx context.Context, data string, native disclosure.SecretVault, install func() error) error {
	if ipc.ValidateDir(data, true) != nil {
		return errors.New("runtime_authority_unavailable")
	}
	// Serialize with the daemon's writer admission. Installation never opens a
	// live profile, repairs an old database or manufactures authority at startup.
	lock, err := ipc.Lock(filepath.Join(data, "db.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := recoverPending(ctx, data, native); errors.Is(err, errAuthorityReady) {
		if install != nil {
			return install()
		}
		return nil
	} else if err != nil {
		return err
	}
	for _, name := range []string{"memory.sqlite", "installed-authority.json"} {
		if _, err := os.Lstat(filepath.Join(data, name)); !os.IsNotExist(err) {
			return errors.New("runtime_authority_unavailable")
		}
	}
	if err := writePending(data, pendingProfile{Version: 1}); err != nil {
		return err
	}
	// The installer authenticates and persists the image/receipt before any
	// once-only profile authority is committed. Keep db.lock throughout so a
	// manager-started or unmanaged daemon cannot open an incomplete profile.
	if install != nil {
		if err := install(); err != nil {
			return err
		}
	}
	// Prove custody is available before creating a new database. This disposable
	// OS-vault entry contains random probe bytes, never a device or client key.
	var id [16]byte
	var probe [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	if _, err := rand.Read(probe[:]); err != nil {
		return err
	}
	defer clear(probe[:])
	handle := hex.EncodeToString(id[:])
	if err := (provisioningVault{SecretVault: native, data: data}).Put(ctx, handle, probe[:]); err != nil {
		return err
	}
	if err := native.Delete(ctx, handle); err != nil {
		return err
	}
	pending, err := readPending(data)
	if err != nil {
		return err
	}
	pending.Handle = ""
	if err = writePending(data, pending); err != nil {
		return err
	}
	err = disclosure.BootstrapInstalled(ctx, data, "Installed local clients",
		disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S, disclosure.P, disclosure.E}},
		disclosure.TaskWriteGrant{Repos: disclosure.AllLocalRepos(), AllowUnscoped: true,
			Actions: []disclosure.TaskMutation{disclosure.Create, disclosure.Checkpoint, disclosure.Pause, disclosure.Complete}}, provisioningVault{SecretVault: native, data: data})
	if err != nil {
		return err
	}
	p, err := readPending(data)
	if err != nil {
		return err
	}
	// Read authority back through the same installed target before publishing
	// completion. A successful Put in another image's namespace is insufficient.
	loaded, err := (disclosure.InstalledProvider{Dir: data, Vault: native, Peers: peer.Authority{}}).Load(ctx)
	if err != nil {
		return err
	}
	loaded.Material.Clear()
	return completePending(data, p)
}

func deleteAuthority(ctx context.Context, data string, native disclosure.SecretVault) error {
	lock, err := ipc.Lock(filepath.Join(data, "db.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := readPending(data); err == nil {
		return deletePending(ctx, data, native)
	} else if !os.IsNotExist(err) {
		return err
	}
	return disclosure.DeleteInstalledSecret(ctx, data, native)
}

var errAuthorityAdmitted = errors.New("authority_already_admitted")

// Recheck the shortcut predicate under writer admission. A daemon can have
// opened or crashed between the lifecycle caller's first read and this lock.
func deleteNeverAdmittedAuthority(ctx context.Context, data string, native disclosure.SecretVault) error {
	lock, err := ipc.Lock(filepath.Join(data, "db.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	p, err := readPending(data)
	if err != nil {
		return err
	}
	if p.Phase == "admitted" {
		return errAuthorityAdmitted
	}
	return deletePending(ctx, data, native)
}
