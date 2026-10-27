//go:build darwin && cgo

package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/bundle"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/custodyguard"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/syncnode"
)

type profileTransfer struct {
	Reference         custodyguard.Handle `json:"reference"`
	Source            creatorReceipt      `json:"source_creator"`
	Target            creatorReceipt      `json:"target_creator"`
	Stage             string              `json:"stage"`
	RetirementPending bool                `json:"retirement_pending,omitempty"`
	Retired           bool                `json:"retired,omitempty"`
}

type profileHandoff struct {
	Version    int               `json:"version"`
	Source     install.Record    `json:"source"`
	Target     string            `json:"target_sha256"`
	Generation string            `json:"metadata_sha256"`
	Phase      string            `json:"phase"`
	Entries    []profileTransfer `json:"entries"`
}

func inventory(dir string) ([]custodyguard.Handle, string, error) {
	h, err := installedHandle(dir)
	if err != nil {
		return nil, "", err
	}
	out := []custodyguard.Handle{{Handle: h, Purpose: "installed-authority"}}
	for _, get := range []func(string) ([]custodyguard.Handle, error){syncnode.OwnedCredentialHandles, bundle.OwnedCredentialHandles, disclosure.OwnedCredentialHandles} {
		refs, err := get(dir)
		if err != nil {
			return nil, "", err
		}
		out = append(out, refs...)
	}
	if len(out) > 64 {
		return nil, "", ErrUnavailable
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Handle < out[j].Handle })
	seen := map[string]bool{}
	for _, r := range out {
		if valid(context.Background(), r.Handle) != nil || seen[r.Handle] || !profilePurpose(r.Purpose) {
			return nil, "", ErrUnavailable
		}
		seen[r.Handle] = true
	}
	// Fixed typed metadata only. Creator records have their own exact journal
	// identities and change during retirement, so they are not this generation.
	files := []string{"installed-authority.json", store.DeviceJoinName, store.JoinPendingName, store.ExportKeyName, store.SyncProfileName, store.RepositoryContextsName}
	hash := sha256.New()
	for _, name := range files {
		hash.Write([]byte(name))
		hash.Write([]byte{0})
		limit := int64(16384)
		if name == store.SyncProfileName {
			limit = 65536
		}
		b, err := privateReadLimit(filepath.Join(dir, name), limit)
		if os.IsNotExist(err) {
			hash.Write([]byte{0})
			continue
		}
		if err != nil {
			return nil, "", err
		}
		hash.Write([]byte{1})
		sum := sha256.Sum256(b)
		hash.Write(sum[:])
	}
	return out, hex.EncodeToString(hash.Sum(nil)), nil
}

func profilePurpose(p string) bool {
	switch p {
	case "installed-authority", "sync-dpop", "sync-refresh", "sync-retired", "bundle-export", "bundle-pending-join", "repository-context", "repository-context-retired":
		return true
	}
	return false
}
func cleanupPurpose(p string) bool { return strings.HasSuffix(p, "-retired") }

func (m profileHandoff) validate() error {
	if m.Version != 2 || !filepath.IsAbs(m.Source.DataDir) || filepath.Clean(m.Source.DataDir) != m.Source.DataDir || !filepath.IsAbs(m.Source.Dir) || filepath.Clean(m.Source.Dir) != m.Source.Dir || !digestValid(m.Target) || !digestValid(m.Generation) || !digestValid(m.Source.SHA256) || m.Source.Executable != handoffTarget(m.Source, m.Source.SHA256) || len(m.Entries) == 0 || len(m.Entries) > 64 || (m.Phase != "preparing" && m.Phase != "ready" && m.Phase != "retiring") {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	installed := 0
	for _, e := range m.Entries {
		h := e.Reference.Handle
		if !profilePurpose(e.Reference.Purpose) || seen[h] || !e.Source.valid(h) || !e.Target.valid(h) || e.Target.Image != handoffTarget(m.Source, m.Target) || e.Target.Digest != m.Target || e.Target.Keychain != e.Source.Keychain || e.Target.Expected != e.Source.Expected {
			return ErrUnavailable
		}
		seen[h] = true
		if e.Reference.Purpose == "installed-authority" {
			installed++
		}
		switch e.Stage {
		case "planned", "creating", "copied", "cleaned", "collision":
		default:
			return ErrUnavailable
		}
		if m.Phase != "preparing" && ((cleanupPurpose(e.Reference.Purpose) && e.Stage != "cleaned") || (!cleanupPurpose(e.Reference.Purpose) && e.Stage != "copied")) {
			return ErrUnavailable
		}
		if e.Retired && !e.RetirementPending {
			return ErrUnavailable
		}
	}
	if installed != 1 {
		return ErrUnavailable
	}
	return nil
}

func readProfileHandoff(dir string) (profileHandoff, error) {
	var m profileHandoff
	b, err := privateReadLimit(filepath.Join(dir, custodyguard.ProfileJournal), 131072)
	if err != nil {
		return m, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || m.validate() != nil || m.Source.DataDir != dir {
		return profileHandoff{}, ErrUnavailable
	}
	return m, nil
}
func writeProfileHandoff(m profileHandoff) error {
	if m.validate() != nil {
		return ErrUnavailable
	}
	b, err := json.Marshal(m)
	if err != nil || len(b) > 131072 {
		return ErrUnavailable
	}
	f, err := os.CreateTemp(m.Source.DataDir, ".custody-profile-upgrade-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	if err = os.Rename(f.Name(), filepath.Join(m.Source.DataDir, custodyguard.ProfileJournal)); err != nil {
		return err
	}
	return syncHandoffDir(m.Source.DataDir)
}

func targetRecord(m profileHandoff, version string) install.Record {
	r := m.Source
	r.SHA256 = m.Target
	r.Executable = handoffTarget(m.Source, m.Target)
	r.Version = version
	return r
}

// CheckProfileUpgradeSource refuses legacy automatic upgrades before the
// lifecycle changes stop intent, stages an image or opens native custody.
func CheckProfileUpgradeSource(ctx context.Context, r install.Record) error {
	if checkTargetCapabilities(ctx, r.Executable, r.SHA256) != nil {
		return ErrLegacyCustody
	}
	return nil
}

func (v *Vault) prepareProfileInventory(ctx context.Context, source install.Record, target string) (profileHandoff, error) {
	refs, generation, err := inventory(source.DataDir)
	if err != nil {
		return profileHandoff{}, err
	}
	m, err := readProfileHandoff(source.DataDir)
	if err == nil {
		if m.Source != source || m.Target != target || m.Generation != generation || len(m.Entries) != len(refs) {
			return profileHandoff{}, ErrUnavailable
		}
		for i, r := range refs {
			if m.Entries[i].Reference != r {
				return profileHandoff{}, ErrUnavailable
			}
			if m.Entries[i].RetirementPending || m.Entries[i].Retired {
				return profileHandoff{}, ErrUnavailable
			}
		}
		if m.Phase == "retiring" {
			return profileHandoff{}, ErrUnavailable
		}
		if m.Phase == "ready" {
			// The still-current source may retry after a target slot was lost.
			// Persist this transition before any entry can become creating, so
			// a crash retains valid retry evidence and publication stays blocked
			// until every exact target has been read back again.
			m.Phase = "preparing"
			if err := writeProfileHandoff(m); err != nil {
				return profileHandoff{}, err
			}
		}
		return m, nil
	}
	if !os.IsNotExist(err) {
		return profileHandoff{}, err
	}
	m = profileHandoff{Version: 2, Source: source, Target: target, Generation: generation, Phase: "preparing"}
	for _, ref := range refs {
		creator, err := readCreator(source.DataDir, ref.Handle)
		if os.IsNotExist(err) && ref.Purpose == "installed-authority" {
			secret, e := v.imageOperation(ctx, source.Executable, source.SHA256, 9, ref.Handle, nil)
			if e != nil {
				return profileHandoff{}, e
			}
			creator, err = v.creatorForImage(ctx, ref.Handle, secret, source.Executable, source.SHA256)
			clear(secret)
			if creator.Image != source.Executable || creator.Digest != source.SHA256 {
				return profileHandoff{}, ErrUnavailable
			}
			creator.Phase = "bound"
		}
		if err != nil {
			return profileHandoff{}, ErrLegacyCustody
		}
		if creator.Phase == "collision" || creator.Keychain != v.keychainPath {
			return profileHandoff{}, ErrUnavailable
		}
		if creator.Phase == "deleted" && !cleanupPurpose(ref.Purpose) {
			return profileHandoff{}, ErrUnavailable
		}
		namespace, e := v.imageOperation(ctx, handoffTarget(source, target), target, 5, ref.Handle, nil)
		if e != nil {
			return profileHandoff{}, e
		}
		next := creator
		next.Image = handoffTarget(source, target)
		next.Digest = target
		next.Namespace = string(namespace)
		next.Phase = "bound"
		m.Entries = append(m.Entries, profileTransfer{Reference: ref, Source: creator, Target: next, Stage: "planned"})
	}
	if err := writeProfileHandoff(m); err != nil {
		return profileHandoff{}, err
	}
	return m, nil
}

func (v *Vault) copyProfileEntry(ctx context.Context, m *profileHandoff, i int) error {
	e := &m.Entries[i]
	if cleanupPurpose(e.Reference.Purpose) {
		if e.Stage == "cleaned" {
			return nil
		}
		if err := v.deleteProfile(ctx, e.Reference.Handle); err != nil {
			return err
		}
		e.Stage = "cleaned"
		return writeProfileHandoff(*m)
	}
	secret, err := v.creatorOperation(ctx, e.Source, 9, nil)
	defer clear(secret)
	if err != nil || !creatorMatches(e.Source, secret) {
		return ErrUnavailable
	}
	if e.Stage == "collision" {
		return ErrUnavailable
	}
	if e.Source.Namespace == e.Target.Namespace {
		readback, err := v.creatorOperation(ctx, e.Target, 9, nil)
		defer clear(readback)
		if err != nil || !creatorMatches(e.Target, readback) {
			return ErrUnavailable
		}
		e.Stage = "copied"
		return writeProfileHandoff(*m)
	}
	readback, probe := v.creatorOperation(ctx, e.Target, 9, nil)
	defer clear(readback)
	if probe == nil {
		allowed := e.Stage == "creating" || e.Stage == "copied"
		if !allowed || !creatorMatches(e.Target, readback) {
			e.Stage = "collision"
			_ = writeProfileHandoff(*m)
			return ErrUnavailable
		}
	} else {
		if !errors.Is(probe, ErrNotFound) {
			return probe
		}
		e.Stage = "creating"
		if err := writeProfileHandoff(*m); err != nil {
			return err
		}
		if _, err := v.creatorOperation(ctx, e.Target, 1, secret); err != nil {
			if errors.Is(err, ErrExists) {
				e.Stage = "collision"
				_ = writeProfileHandoff(*m)
			}
			return err
		}
		check, err := v.creatorOperation(ctx, e.Target, 9, nil)
		defer clear(check)
		if err != nil || !creatorMatches(e.Target, check) {
			return ErrUnavailable
		}
	}
	e.Stage = "copied"
	return writeProfileHandoff(*m)
}

// PrepareUpgrade runs in the authenticated standalone source helper. Its freeze
// refuses all cooperating credential writers after admission is released, until
// publication recovery has reconciled every target and old namespace.
func (v *Vault) PrepareUpgrade(ctx context.Context, source install.Record, target string) error {
	if ctx == nil || v == nil {
		return ErrInvalid
	}
	self, err := os.Executable()
	if err != nil || self != source.Executable {
		return install.ErrUnverified
	}
	if CheckProfileUpgradeSource(ctx, source) != nil {
		return ErrLegacyCustody
	}
	status, err := install.Status(ctx, source.Dir)
	if (err != nil && !errors.Is(err, install.ErrUnavailable)) || status.Record != source {
		return install.ErrUnverified
	}
	if err := checkTargetCapabilities(ctx, handoffTarget(source, target), target); err != nil {
		return err
	}
	lease, err := custodyguard.BeginUpgrade(ctx, source.DataDir)
	if err != nil {
		return err
	}
	defer lease.Close()
	unlock, err := syncnode.LockCustodyProfile(ctx, source.DataDir)
	if err != nil {
		return err
	}
	defer unlock()
	if err := v.bindCustody(ctx, source.DataDir, false); err != nil {
		return err
	}
	// A v2 preparation always persists the complete journal before its runtime
	// compatibility marker. Runtime-only state is historical or ambiguous and
	// cannot establish custody for every role. Refuse before writing a freeze.
	if _, runtimeErr := readHandoff(source.DataDir); runtimeErr == nil {
		if _, fullErr := readProfileHandoff(source.DataDir); os.IsNotExist(fullErr) {
			return ErrLegacyCustody
		} else if fullErr != nil {
			return fullErr
		}
	} else if !os.IsNotExist(runtimeErr) {
		return runtimeErr
	}
	if prior, err := readProfileHandoff(source.DataDir); err == nil && prior.Source == source && prior.Target != target {
		if err := v.abortProfileLocked(ctx, prior); err != nil {
			return err
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	m, err := v.prepareProfileInventory(ctx, source, target)
	if err != nil {
		return err
	}
	// Preserve the existing runtime marker for retained-image cleanup, but all
	// creation uses the complete profile journal's no-adoption state machine.
	var runtime custodyHandoff
	for _, e := range m.Entries {
		if e.Reference.Purpose == "installed-authority" {
			runtime = custodyHandoff{1, source, target, e.Reference.Handle, v.keychainPath, "prepared", e.Source.Namespace == service}
		}
	}
	if old, err := readHandoff(source.DataDir); err == nil {
		if old.Source != runtime.Source || old.Target != runtime.Target || old.Handle != runtime.Handle || old.Keychain != runtime.Keychain {
			return ErrUnavailable
		}
		runtime = old
	} else if !os.IsNotExist(err) {
		return err
	} else if err := writeHandoff(runtime); err != nil {
		return err
	}
	for i := range m.Entries {
		if err := v.copyProfileEntry(ctx, &m, i); err != nil {
			return err
		}
	}
	_, generation, err := inventory(source.DataDir)
	if err != nil || generation != m.Generation {
		return ErrUnavailable
	}
	runtime.Phase = "ready"
	if err := writeHandoff(runtime); err != nil {
		return err
	}
	m.Phase = "ready"
	return writeProfileHandoff(m)
}

func (v *Vault) abortProfileLocked(ctx context.Context, m profileHandoff) error {
	status, err := install.Status(ctx, m.Source.Dir)
	if (err != nil && !errors.Is(err, install.ErrUnavailable)) || status.Record != m.Source {
		return install.ErrUnverified
	}
	if m.validate() != nil {
		return ErrUnavailable
	}
	for _, e := range m.Entries {
		if cleanupPurpose(e.Reference.Purpose) {
			continue
		}
		secret, err := v.creatorOperation(ctx, e.Source, 9, nil)
		matched := creatorMatches(e.Source, secret)
		clear(secret)
		if err != nil || !matched {
			return ErrUnavailable
		}
	}
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Stage == "collision" {
			return ErrUnavailable
		} // Never delete an unowned target.
		if cleanupPurpose(e.Reference.Purpose) || e.Source.Namespace == e.Target.Namespace || e.Stage == "planned" {
			continue
		}
		secret, err := v.creatorOperation(ctx, e.Target, 9, nil)
		if err == nil && !creatorMatches(e.Target, secret) {
			clear(secret)
			return ErrUnavailable
		}
		clear(secret)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil {
			if _, err := v.creatorOperation(ctx, e.Target, 6, nil); err != nil {
				return err
			}
		}
		e.Stage = "planned"
		m.Phase = "preparing"
		if err := writeProfileHandoff(m); err != nil {
			return err
		}
	}
	if runtime, err := readHandoff(m.Source.DataDir); err == nil {
		if runtime.Source != m.Source || runtime.Target != m.Target {
			return ErrUnavailable
		}
		if err := os.Remove(filepath.Join(m.Source.DataDir, handoffFile)); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	// Retain the exact completed rollback evidence; only the freeze name goes.
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	commitment := sha256.Sum256(b)
	receipt := filepath.Join(m.Source.DataDir, "custody-profile-aborted-"+hex.EncodeToString(commitment[:])+".json")
	if err := writeExclusivePublicReceipt(receipt, b); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(m.Source.DataDir, custodyguard.ProfileJournal)); err != nil {
		return err
	}
	return syncHandoffDir(m.Source.DataDir)
}

func writeExclusivePublicReceipt(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		old, read := privateReadLimit(path, 131072)
		if read == nil && bytes.Equal(old, b) {
			return nil
		}
		return ErrUnavailable
	}
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	return syncHandoffDir(filepath.Dir(path))
}

// AbortProfileUpgrade restores only a still-current source and removes only
// journal-proven staging slots. A collision stays pending, never guessed clean.
func (v *Vault) AbortProfileUpgrade(ctx context.Context, current install.Record) error {
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
	lock, err := ipc.Lock(filepath.Join(current.DataDir, "custody-upgrade.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	m, err := readProfileHandoff(current.DataDir)
	if err != nil {
		return err
	}
	if m.Source != current {
		return install.ErrUnverified
	}
	if err := v.bindCustody(ctx, current.DataDir, false); err != nil {
		return err
	}
	return v.abortProfileLocked(ctx, m)
}

// PrepareProfileUninstall settles complete-profile staging before teardown can
// acquire db.lock. The source aborts only its authenticated unpublished targets;
// a published target completes verified recovery in its retained exact image.
func (v *Vault) PrepareProfileUninstall(ctx context.Context, current install.Record) error {
	m, err := readProfileHandoff(current.DataDir)
	if os.IsNotExist(err) {
		// V2 writes its full journal before the runtime compatibility marker
		// and removes that marker first. Runtime-only state is historical or
		// ambiguous. Retain every slot and refuse before teardown can quiesce
		// the daemon, acquire db.lock or mutate its service registration.
		if _, runtimeErr := readHandoff(current.DataDir); runtimeErr == nil {
			return ErrLegacyCustody
		} else if !os.IsNotExist(runtimeErr) {
			return runtimeErr
		}
		return nil
	}
	if err != nil {
		return err
	}
	if current == m.Source {
		return v.AbortProfileUpgrade(ctx, current)
	}
	if current != targetRecord(m, current.Version) {
		return install.ErrUnverified
	}
	return v.lifecycleImage(ctx, current, "", recoverArg)
}

func verifyPreparedProfile(ctx context.Context, v *Vault, m profileHandoff) error {
	if m.validate() != nil || m.Phase == "preparing" {
		return ErrUnavailable
	}
	refs, generation, err := inventory(m.Source.DataDir)
	if err != nil || generation != m.Generation || len(refs) != len(m.Entries) {
		return ErrUnavailable
	}
	for i, e := range m.Entries {
		if refs[i] != e.Reference {
			return ErrUnavailable
		}
		if cleanupPurpose(e.Reference.Purpose) {
			continue
		}
		secret, err := v.creatorOperation(ctx, e.Target, 9, nil)
		matched := creatorMatches(e.Target, secret)
		clear(secret)
		if err != nil || !matched {
			return ErrUnavailable
		}
	}
	return nil
}

// VerifyPreparedProfile is the final lifecycle check after quiescence and
// before the install package may publish its receipt. The durable freeze stays.
func VerifyPreparedProfile(ctx context.Context, source install.Record, target string) error {
	lease, err := custodyguard.BeginUpgrade(ctx, source.DataDir)
	if err != nil {
		return err
	}
	defer lease.Close()
	unlock, err := syncnode.LockCustodyProfile(ctx, source.DataDir)
	if err != nil {
		return err
	}
	defer unlock()
	m, err := readProfileHandoff(source.DataDir)
	if err != nil || m.Source != source || m.Target != target {
		return ErrUnavailable
	}
	v := New()
	if err := v.bindCustody(ctx, source.DataDir, false); err != nil {
		return err
	}
	return verifyPreparedProfile(ctx, v, m)
}

func (v *Vault) RecoverUpgrade(ctx context.Context, current install.Record) error {
	if ctx == nil || v == nil || v.closed {
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
	m, err := readProfileHandoff(current.DataDir)
	if os.IsNotExist(err) {
		return v.recoverRuntimeUpgrade(ctx, current)
	}
	if err != nil {
		return err
	}
	if current == m.Source {
		return nil
	} // Source custody is retained before publication.
	if current != targetRecord(m, current.Version) {
		return install.ErrUnverified
	}
	if err := v.bindCustody(ctx, current.DataDir, false); err != nil {
		return err
	}
	if err := verifyPreparedProfile(ctx, v, m); err != nil {
		return err
	}
	m.Phase = "retiring"
	if err := writeProfileHandoff(m); err != nil {
		return err
	}
	for i := range m.Entries {
		e := &m.Entries[i]
		if cleanupPurpose(e.Reference.Purpose) {
			continue
		}
		prior, err := readCreator(current.DataDir, e.Reference.Handle)
		if os.IsNotExist(err) && e.Reference.Purpose == "installed-authority" {
			if err := writeCreator(current.DataDir, nil, e.Target); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if prior != e.Target {
			if prior != e.Source {
				return ErrUnavailable
			}
			if err := writeCreator(current.DataDir, &prior, e.Target); err != nil {
				return err
			}
		}
		if !e.RetirementPending {
			e.RetirementPending = true
			if err := writeProfileHandoff(m); err != nil {
				return err
			}
		}
		if e.Retired {
			continue
		}
		if e.Source.Namespace != e.Target.Namespace {
			old, err := v.creatorOperation(ctx, e.Source, 9, nil)
			if err == nil && !creatorMatches(e.Source, old) {
				clear(old)
				return ErrUnavailable
			}
			clear(old)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if err == nil {
				if _, err := v.creatorOperation(ctx, e.Source, 6, nil); err != nil {
					return err
				}
			}
		}
		e.Retired = true
		if err := writeProfileHandoff(m); err != nil {
			return err
		}
	}
	if err := v.recoverRuntimeUpgrade(ctx, current); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(current.DataDir, custodyguard.ProfileJournal)); err != nil {
		return err
	}
	return syncHandoffDir(current.DataDir)
}

// CheckPublicationCustody blocks replay of a legacy publication journal by a
// new lifecycle caller. The install package still independently validates and
// serializes its own publication. A durable profile freeze prevents credential
// metadata changes while the lifecycle owner finishes that publication.
func CheckPublicationCustody(ctx context.Context, dir string) error {
	path := filepath.Join(dir, "upgrade-publication.json")
	b, err := privateRead(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var p struct {
		Schema int            `json:"schema"`
		Source install.Record `json:"source"`
		Target install.Record `json:"target"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Schema != 1 || p.Source.Dir != dir || p.Target.Dir != dir {
		return ErrUnavailable
	}
	return VerifyPreparedProfile(ctx, p.Source, p.Target.SHA256)
}
