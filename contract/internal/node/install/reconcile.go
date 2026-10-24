package install

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

const upgradePublicationFile = "upgrade-publication.json"

type upgradePublication struct {
	Schema int    `json:"schema"`
	Source Record `json:"source"`
	Target Record `json:"target"`
}

func (p upgradePublication) validate(dir string) error {
	b, e := json.Marshal(p)
	if e != nil || len(b) >= 16384 {
		return ErrUnverified
	}
	if p.Schema != 1 || validateRecord(p.Source, dir) != nil || validateRecord(p.Target, dir) != nil {
		return ErrUnverified
	}
	expected := p.Source
	expected.SHA256, expected.Version, expected.Executable = p.Target.SHA256, p.Target.Version, p.Target.Executable
	if expected != p.Target || p.Source == p.Target {
		return ErrUnverified
	}
	for _, r := range []Record{p.Source, p.Target} {
		v, e := verify(r.Executable, r.SHA256)
		if e != nil {
			return e
		}
		v.Close()
	}
	return nil
}

// ReconcileUpgrade finishes only an owner-authenticated, settled transition.
// It runs before ordinary receipt/intent validation, under lifecycle and writer
// admission. It never infers an upgrade from mismatching files or relaxes
// VerifyRunning's executable self-path requirement.
func ReconcileUpgrade(ctx context.Context, dir string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if _, e := os.Lstat(filepath.Join(dir, upgradePublicationFile)); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	// A just-launched B waits for the publishing lifecycle owner to finish.
	// Native managers return on launch, without requiring daemon readiness.
	wait, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for {
		lock, e := lockInstall(dir)
		if e == nil {
			defer lock.Close()
			break
		}
		if !errors.Is(e, ipc.ErrBusy) {
			return e
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-wait.Done():
			timer.Stop()
			return wait.Err()
		case <-timer.C:
		}
	}

	return reconcileUpgrade(ctx, dir)
}

// Caller holds install.lock. A missing journal is the normal non-upgrade path.
func reconcileUpgrade(ctx context.Context, dir string) error {
	var p upgradePublication
	if e := readPrivate(filepath.Join(dir, upgradePublicationFile), &p); errors.Is(e, os.ErrNotExist) {
		return nil
	} else if e != nil {
		return e
	}
	if e := p.validate(dir); e != nil {
		return e
	}
	if e := ipc.ValidateDir(p.Source.DataDir, false); e != nil {
		return e
	}
	writer, e := ipc.Lock(filepath.Join(p.Source.DataDir, "db.lock"))
	if e != nil {
		return e
	}
	defer writer.Close()
	if e = publishUpgrade(ctx, p); e != nil {
		return e
	}
	// A manager-launched process must never observe a missing journal while the
	// publication owner still holds writer admission.
	if e = writer.Close(); e != nil {
		return e
	}
	return removeOwned(filepath.Join(dir, upgradePublicationFile))
}

// Publication is idempotent at each durable file boundary. The journal is written
// only after quiescence, before the first receipt change. Both executables and
// unchanged profile/manager pins authenticate before publication.
func publishUpgrade(ctx context.Context, p upgradePublication) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := p.validate(p.Source.Dir); e != nil {
		return e
	}
	r, e := readReceipt(p.Source.Dir)
	if e != nil || (r != p.Source && r != p.Target) {
		return ErrUnverified
	}
	var i intent
	if e = readPrivate(filepath.Join(r.Dir, "intent.json"), &i); e != nil {
		return e
	}
	sourceIntent := i.SHA256 == p.Source.SHA256 && i.Version == p.Source.Version && i.Mode == "stop"
	targetIntent := i.SHA256 == p.Target.SHA256 && i.Version == p.Target.Version && (i.Mode == "upgrade" || (i.Mode == "stop" && i.Session == ""))
	if !sourceIntent && !targetIntent {
		return ErrUnverified
	}
	if verifyDefinition(p.Source) != nil && verifyDefinition(p.Target) != nil {
		return ErrUnverified
	}
	if e = writeJSON(filepath.Join(r.Dir, "install.json"), p.Target); e != nil {
		return e
	}
	b, e := Definition(p.Target.Platform, p.Target)
	if e != nil {
		return e
	}
	if e = writeAtomic(definitionPath(p.Target), b, 0600); e != nil {
		return e
	}
	if e = writeIntent(r.Dir, p.Target, "upgrade", ""); e != nil {
		return e
	}
	// A manager may already have consumed B before the crash.
	if registered(ctx, p.Target) == nil {
		e = managerStart(ctx, p.Target)
	} else {
		e = managerReplace(ctx, p.Target, p.Source)
	}
	if e != nil {
		return e
	}
	return nil
}
