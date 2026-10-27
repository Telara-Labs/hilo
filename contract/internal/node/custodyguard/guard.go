// Package custodyguard serializes complete native credential mutations with
// installation handoff. The lock covers publication and failure cleanup as well
// as the native operation; a vault Put alone is not a committed credential.
package custodyguard

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

var ErrPending = errors.New("custody_upgrade_pending")

const LockName = "custody-writer.lock"
const ProfileJournal = "custody-profile-upgrade.json"

// Handle is an opaque slot obtained from a validated, typed profile descriptor.
// Purpose identifies the owning descriptor. It never contains secret bytes.
type Handle struct {
	Handle  string `json:"handle"`
	Purpose string `json:"purpose"`
}

type leaseKey struct{}

// Lease is admission held by an authenticated lifecycle owner. Preparation
// persists the durable writer freeze before releasing admission; final
// verification and recovery reacquire it before examining that frozen state.
type Lease struct {
	mu     sync.Mutex
	idle   *sync.Cond
	users  int
	file   io.Closer
	dir    string
	pid    int
	closed bool
}

func (l *Lease) enter(dir string) (func(), bool) {
	l.mu.Lock()
	if !l.closed && l.file != nil && l.dir == dir && l.pid == os.Getpid() {
		l.users++
		l.mu.Unlock()
		return func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.users--
			if l.users == 0 && l.idle != nil {
				l.idle.Broadcast()
			}
		}, true
	}
	l.mu.Unlock()
	return nil, false
}

func (l *Lease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	if l.idle == nil {
		l.idle = sync.NewCond(&l.mu)
	}
	for l.users != 0 {
		l.idle.Wait()
	}
	if l.closed {
		return nil
	}
	l.closed = true
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}

// Context permits nested typed mutations inside this exact live admission.
func (l *Lease) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, leaseKey{}, l)
}

// BeginUpgrade acquires exclusive admission even when recovery is pending.
// The caller must independently authenticate the install receipt and journal.
// Ordinary profile operations use With, which refuses either pending journal.
func BeginUpgrade(ctx context.Context, dir string) (*Lease, error) {
	if ctx == nil || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, ipc.ErrUnsafe
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
	}
	if err := ipc.ValidateDir(dir, false); err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f, err := ipc.Lock(filepath.Join(dir, LockName))
		if err == nil {
			return &Lease{file: f, dir: dir, pid: os.Getpid()}, nil
		}
		if !errors.Is(err, ipc.ErrBusy) {
			return nil, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func pending(dir string) error {
	for _, name := range []string{ProfileJournal, "custody-upgrade.json", "custody-maintenance.json"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return ErrPending
		}
	}
	return nil
}

// With retains admission until the entire mutation and its rollback return.
// Nested calls must propagate the supplied callback context. No on-disk marker
// is accepted as a reentrancy token.
func With(ctx context.Context, dir string, fn func(context.Context) error) error {
	if ctx == nil || fn == nil {
		return ipc.ErrUnsafe
	}
	if l, ok := ctx.Value(leaseKey{}).(*Lease); ok {
		if leave, valid := l.enter(dir); valid {
			defer leave()
			return fn(ctx)
		}
	}
	wait := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		wait, cancel = context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
	}
	l, err := BeginUpgrade(wait, dir)
	if err != nil {
		return err
	}
	defer l.Close()
	if err := pending(dir); err != nil {
		return err
	}
	return fn(l.Context(ctx))
}
