package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/peer"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

const pendingAuthority = "authority-bootstrap.json"

var errAuthorityReady = errors.New("authority_bootstrap_already_complete")

type pendingProfile struct {
	Version int    `json:"version"`
	Handle  string `json:"vault_handle"`
	Phase   string `json:"phase"`
}

func readPending(data string) (pendingProfile, error) {
	var p pendingProfile
	b, err := readAuthorityRecord(data)
	if err != nil {
		return p, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Version != 1 || (p.Handle != "" && !record.IsKeyID(p.Handle)) || (p.Phase != "provisioning" && p.Phase != "complete" && p.Phase != "admitted") {
		return pendingProfile{}, errors.New("runtime_authority_unavailable")
	}
	return p, nil
}

func writePending(data string, p pendingProfile) error {
	if p.Phase == "" {
		p.Phase = "provisioning"
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return writeAuthorityRecord(data, b)
}

// The record is created only while a fresh profile is held behind db.lock.
// Provisioning refuses startup; complete transitions to admitted before opening.
// Recovery is limited to profiles that could never have admitted a backend.
func recoverPending(ctx context.Context, data string, native disclosure.SecretVault) error {
	p, err := readPending(data)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if p.Phase == "admitted" {
		return errors.New("runtime_authority_unavailable")
	}
	if _, err := os.Lstat(filepath.Join(data, "installed-authority.json")); err == nil {
		// Bootstrap writes this manifest last. If its key/identity validates,
		// complete the interrupted setup without deleting any database state.
		// The complete phase remains durable until first daemon admission.
		runtime, loadErr := (disclosure.InstalledProvider{Dir: data, Vault: native, Peers: peer.Authority{}}).Load(ctx)
		if loadErr == nil {
			runtime.Material.Clear()
			if err = completePending(data, p); err != nil {
				return err
			}
			return errAuthorityReady
		}
		if p.Phase == "complete" {
			return loadErr
		}
	} else if !os.IsNotExist(err) {
		return err
	} else if p.Phase == "complete" {
		return errors.New("runtime_authority_unavailable")
	}
	if p.Handle != "" {
		if err = native.Delete(ctx, p.Handle); err != nil {
			return err
		}
	}
	for _, name := range []string{"installed-authority.json", "memory.sqlite", "memory.sqlite-wal", "memory.sqlite-shm", "memory.sqlite-journal"} {
		path := filepath.Join(data, name)
		st, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !safeAuthorityFile(path, st) {
			return errors.New("runtime_authority_unavailable")
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	if err = syncAuthorityDir(data); err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(data, pendingAuthority)); err != nil {
		return err
	}
	return syncAuthorityDir(data)
}

func completePending(data string, p pendingProfile) error {
	// Keep durable never-admitted evidence until the first daemon opener,
	// under db.lock, durably transitions it before opening any backend.
	p.Phase = "complete"
	return writePending(data, p)
}

func deletePending(ctx context.Context, data string, native disclosure.SecretVault) error {
	p, err := readPending(data)
	if err != nil {
		return err
	}
	if p.Phase == "admitted" {
		return disclosure.DeleteInstalledSecret(ctx, data, native)
	}
	if p.Handle != "" {
		if err = native.Delete(ctx, p.Handle); err != nil {
			return err
		}
	}
	// Uninstall retains data even for an unfinished profile. Only an explicit
	// install retry recovers never-opened bootstrap files.
	if err = os.Remove(filepath.Join(data, pendingAuthority)); err != nil {
		return err
	}
	return syncAuthorityDir(data)
}

type provisioningVault struct {
	disclosure.SecretVault
	data string
}

func (v provisioningVault) Put(ctx context.Context, handle string, secret []byte) error {
	p, err := readPending(v.data)
	if err != nil || p.Handle != "" {
		return errors.New("runtime_authority_unavailable")
	}
	p.Handle = handle
	// Persist the opaque recovery handle before the key can enter native custody.
	if err = writePending(v.data, p); err != nil {
		return err
	}
	return v.SecretVault.Put(ctx, handle, secret)
}
