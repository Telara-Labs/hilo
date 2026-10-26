package syncnode

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// profileLockName is the owner-only lock file beside the profile. It holds no
// data and is never removed, so every process locks the same file.
const profileLockName = "sync-profile.lock"

// profileLockRetry is the wait between attempts on a lock another process
// holds.
const profileLockRetry = 10 * time.Millisecond

// profileLockWait bounds the wait of an operation that has no caller deadline.
const profileLockWait = 2 * time.Minute

// ErrProfileBusy reports a profile-changing operation that could not acquire
// the profile lock before its deadline.
var ErrProfileBusy = errors.New("sync_profile_busy")

// ErrProfileChanged reports a login whose profile another operation changed
// while it waited on the network. Nothing of the login is committed.
var ErrProfileChanged = errors.New("sync_profile_changed")

// lockContended is called when the lock is held elsewhere. It does nothing;
// tests replace it to observe that an operation is waiting.
var lockContended = func() {}

// lockProfile serializes every operation that changes the profile or the
// credential slots it names, across processes: key creation, enrollment,
// login, enable and disable, logout and retirement of replaced slots. The
// returned function releases it.
func lockProfile(ctx context.Context, dir string) (func(), error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, ErrProfile
	}
	path := filepath.Join(dir, profileLockName)
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, ErrProfile
	} else if err != nil && !os.IsNotExist(err) {
		return nil, ErrProfile
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, ErrProfile
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, ErrProfile
	}
	notified := false
	for {
		ok, err := tryLockFile(f)
		if err != nil {
			f.Close()
			return nil, ErrProfile
		}
		if ok {
			return func() { _ = f.Close() }, nil
		}
		if !notified {
			notified = true
			lockContended()
		}
		t := time.NewTimer(profileLockRetry)
		select {
		case <-ctx.Done():
			t.Stop()
			f.Close()
			return nil, errors.Join(ErrProfileBusy, ctx.Err())
		case <-t.C:
		}
	}
}

// withProfileLock runs f holding the profile lock, bounded by profileLockWait
// when ctx has no deadline of its own.
func withProfileLock(ctx context.Context, dir string, f func() error) error {
	wait := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		wait, cancel = context.WithTimeout(ctx, profileLockWait)
		defer cancel()
	}
	unlock, err := lockProfile(wait, dir)
	if err != nil {
		return err
	}
	defer unlock()
	return f()
}
