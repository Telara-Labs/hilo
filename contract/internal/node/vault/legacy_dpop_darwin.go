//go:build darwin && cgo

package vault

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/custodyguard"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/syncnode"
)

const legacyMaintenanceFile = "custody-maintenance.json"
const legacyMaintenanceComplete = "custody-maintenance-complete.json"

type legacyDPoPRecovery struct {
	Version    int             `json:"version"`
	Source     install.Record  `json:"source"`
	Current    install.Record  `json:"current"`
	JKT        string          `json:"jkt"`
	Generation string          `json:"profile_sha256"`
	Entry      profileTransfer `json:"entry"`
}

func rawDPoPThumbprint(secret []byte) (string, error) {
	if len(secret) != 32 {
		return "", ErrUnavailable
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), secret)
	if err != nil {
		return "", ErrUnavailable
	}
	defer key.D.SetInt64(0)
	return nodesync.Thumbprint(&key.PublicKey)
}

func legacyKeyOnlyProfile(dir string) (syncnode.Profile, string, error) {
	p, err := syncnode.LoadProfile(dir)
	if err != nil || p.Enabled || p.Enrolled() || p.Refresh != "" || len(p.Retired) != 0 {
		return syncnode.Profile{}, "", ErrUnavailable
	}
	genesis, machine, err := store.InstalledIdentity(dir)
	if err != nil || genesis != p.Genesis || machine != p.Device {
		return syncnode.Profile{}, "", ErrUnavailable
	}
	b, err := privateReadLimit(filepath.Join(dir, store.SyncProfileName), 65536)
	if err != nil {
		return syncnode.Profile{}, "", err
	}
	h := sha256.Sum256(b)
	return p, hex.EncodeToString(h[:]), nil
}

func maintenanceRecords(source, current install.Record) bool {
	if source.Platform != "darwin" || source.SHA256 == current.SHA256 || !digestValid(source.SHA256) || !digestValid(current.SHA256) || source.Executable != handoffTarget(source, source.SHA256) || current.Executable != handoffTarget(current, current.SHA256) {
		return false
	}
	r := source
	r.Executable, r.SHA256, r.Version = current.Executable, current.SHA256, current.Version
	return r == current
}

func (m legacyDPoPRecovery) validate() bool {
	e := m.Entry
	return m.Version == 1 && maintenanceRecords(m.Source, m.Current) && digestValid(m.Generation) && len(m.JKT) == 43 &&
		e.Reference.Purpose == "sync-dpop" && e.Source.valid(e.Reference.Handle) && e.Target.valid(e.Reference.Handle) &&
		e.Source.Image == m.Source.Executable && e.Source.Digest == m.Source.SHA256 && e.Target.Image == m.Current.Executable && e.Target.Digest == m.Current.SHA256 &&
		e.Source.Keychain == e.Target.Keychain && e.Source.Expected == e.Target.Expected && e.Source.Phase == "bound" && e.Target.Phase == "bound" &&
		(e.Stage == "planned" || e.Stage == "creating" || e.Stage == "copied" || e.Stage == "collision") && (!e.Retired || e.RetirementPending)
}

func readLegacyRecovery(dir, name string) (legacyDPoPRecovery, error) {
	var m legacyDPoPRecovery
	b, err := privateReadLimit(filepath.Join(dir, name), 32768)
	if err != nil {
		return m, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || !m.validate() || m.Current.DataDir != dir {
		return legacyDPoPRecovery{}, ErrUnavailable
	}
	return m, nil
}

func writeLegacyRecovery(m legacyDPoPRecovery) error {
	if !m.validate() {
		return ErrUnavailable
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(m.Current.DataDir, ".custody-maintenance-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	if err := os.Rename(f.Name(), filepath.Join(m.Current.DataDir, legacyMaintenanceFile)); err != nil {
		return err
	}
	return syncHandoffDir(m.Current.DataDir)
}

// RecoverLegacyDPoP is explicit maintenance for the reviewed owned key-only
// fixture. The owner must first stop its exact legacy daemon and exclude legacy
// writers. Its locks fence v2 participants, not noncooperating old binaries.
// It never changes an install receipt, generates a key or widens a profile.
func (v *Vault) RecoverLegacyDPoP(ctx context.Context, source, current install.Record, expectedJKT string) error {
	if v == nil || ctx == nil || !maintenanceRecords(source, current) || len(expectedJKT) != 43 {
		return ErrInvalid
	}
	lease, err := custodyguard.BeginUpgrade(ctx, current.DataDir)
	if err != nil {
		return err
	}
	defer lease.Close()
	unlock, err := syncnode.LockCustodyProfile(ctx, current.DataDir)
	if err != nil {
		return err
	}
	defer unlock()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || v.bindCustody(ctx, current.DataDir, false) != nil {
		return ErrUnavailable
	}
	var expectedBootstrap []byte
	check := func(generation string) (syncnode.Profile, error) {
		r, err := install.Status(ctx, current.Dir)
		if (err != nil && !errors.Is(err, install.ErrUnavailable)) || r.Record != current {
			return syncnode.Profile{}, install.ErrUnverified
		}
		p, got, err := legacyKeyOnlyProfile(current.DataDir)
		if err != nil || (generation != "" && generation != got) {
			return syncnode.Profile{}, ErrUnavailable
		}
		if expectedBootstrap != nil {
			b, err := privateReadLimit(filepath.Join(current.DataDir, "authority-bootstrap.json"), 32768)
			if err != nil || !bytes.Equal(b, expectedBootstrap) {
				return syncnode.Profile{}, ErrUnavailable
			}
		}
		return p, nil
	}
	p, err := check("")
	if err != nil {
		return err
	}
	_, generation, err := legacyKeyOnlyProfile(current.DataDir)
	if err != nil {
		return err
	}
	bootstrap, err := privateReadLimit(filepath.Join(current.DataDir, "authority-bootstrap.json"), 32768)
	if err != nil {
		return err
	}
	var owner struct {
		Version int             `json:"version"`
		Handle  string          `json:"vault_handle"`
		Phase   string          `json:"phase"`
		Creator *install.Record `json:"creator,omitempty"`
	}
	d := json.NewDecoder(bytes.NewReader(bootstrap))
	d.DisallowUnknownFields()
	installed, err := installedHandle(current.DataDir)
	if err != nil || d.Decode(&owner) != nil || d.Decode(new(any)) != io.EOF || owner.Version != 1 || owner.Phase != "admitted" || owner.Handle != installed || owner.Creator == nil || *owner.Creator != source {
		return ErrUnavailable
	}
	expectedBootstrap = bootstrap
	matching := func(m legacyDPoPRecovery) bool {
		return m.Source == source && m.Current == current && m.JKT == expectedJKT && m.Generation == generation && m.Entry.Reference.Handle == p.Credential && m.Entry.Source.Keychain == v.keychainPath
	}
	m, err := readLegacyRecovery(current.DataDir, legacyMaintenanceFile)
	if os.IsNotExist(err) {
		if completed, read := readLegacyRecovery(current.DataDir, legacyMaintenanceComplete); read == nil {
			if !matching(completed) || !completed.Entry.Retired {
				return ErrUnavailable
			}
			return v.verifyLegacyTarget(ctx, completed)
		} else if !os.IsNotExist(read) {
			return read
		}
		secret, read := v.imageOperation(ctx, source.Executable, source.SHA256, 9, p.Credential, nil)
		defer clear(secret)
		jkt, proof := rawDPoPThumbprint(secret)
		if read != nil || proof != nil || jkt != expectedJKT {
			return ErrUnavailable
		}
		old, proof := v.creatorForImage(ctx, p.Credential, secret, source.Executable, source.SHA256)
		if proof != nil {
			return proof
		}
		next, proof := v.creatorForImage(ctx, p.Credential, secret, current.Executable, current.SHA256)
		if proof != nil {
			return proof
		}
		old.Phase, next.Phase = "bound", "bound"
		m = legacyDPoPRecovery{1, source, current, expectedJKT, generation, profileTransfer{Reference: custodyguard.Handle{Handle: p.Credential, Purpose: "sync-dpop"}, Source: old, Target: next, Stage: "planned"}}
		if err = writeLegacyRecovery(m); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if !matching(m) || m.Entry.Stage == "collision" {
		return ErrUnavailable
	}
	e := &m.Entry
	if !e.RetirementPending {
		// The maintenance journal, not the automatic-upgrade journal, must be
		// persisted before create. Copy inline to keep that ownership explicit.
		secret, read := v.creatorOperation(ctx, e.Source, 9, nil)
		defer clear(secret)
		if read != nil || !creatorMatches(e.Source, secret) {
			return ErrUnavailable
		}
		target, read := v.creatorOperation(ctx, e.Target, 9, nil)
		defer clear(target)
		if read == nil {
			if (e.Stage != "creating" && e.Stage != "copied") || !creatorMatches(e.Target, target) {
				e.Stage = "collision"
				_ = writeLegacyRecovery(m)
				return ErrUnavailable
			}
		} else if errors.Is(read, ErrNotFound) {
			e.Stage = "creating"
			if err = writeLegacyRecovery(m); err != nil {
				return err
			}
			if _, err = v.creatorOperation(ctx, e.Target, 1, secret); err != nil {
				if errors.Is(err, ErrExists) {
					e.Stage = "collision"
					_ = writeLegacyRecovery(m)
				}
				return err
			}
		} else {
			return read
		}
		if err = v.verifyLegacyTarget(ctx, m); err != nil {
			return err
		}
		e.Stage = "copied"
		if _, err = check(m.Generation); err != nil {
			return err
		}
		prior, read := readCreator(current.DataDir, e.Reference.Handle)
		if os.IsNotExist(read) {
			err = writeCreator(current.DataDir, nil, e.Target)
		} else if read != nil || prior != e.Target {
			return ErrUnavailable
		}
		if err != nil {
			return err
		}
		e.RetirementPending = true
		if err = writeLegacyRecovery(m); err != nil {
			return err
		}
	}
	if _, err = check(m.Generation); err != nil {
		return err
	}
	if err = v.verifyLegacyTarget(ctx, m); err != nil {
		return err
	}
	creator, err := readCreator(current.DataDir, e.Reference.Handle)
	if err != nil || creator != e.Target {
		return ErrUnavailable
	}
	if e.Source.Namespace != e.Target.Namespace && !e.Retired {
		secret, read := v.creatorOperation(ctx, e.Source, 9, nil)
		matched := creatorMatches(e.Source, secret)
		clear(secret)
		if read == nil {
			if !matched {
				return ErrUnavailable
			}
			if _, err = v.creatorOperation(ctx, e.Source, 6, nil); err != nil {
				return err
			}
		} else if !errors.Is(read, ErrNotFound) {
			return read
		}
	}
	e.Retired = true
	if err = writeLegacyRecovery(m); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err = writeExclusivePublicReceipt(filepath.Join(current.DataDir, legacyMaintenanceComplete), b); err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(current.DataDir, legacyMaintenanceFile)); err != nil {
		return err
	}
	return syncHandoffDir(current.DataDir)
}

func (v *Vault) verifyLegacyTarget(ctx context.Context, m legacyDPoPRecovery) error {
	secret, err := v.creatorOperation(ctx, m.Entry.Target, 9, nil)
	defer clear(secret)
	jkt, proof := rawDPoPThumbprint(secret)
	if err != nil || proof != nil || !creatorMatches(m.Entry.Target, secret) || jkt != m.JKT {
		return ErrUnavailable
	}
	return nil
}
