// Package install manages an owner-scope daemon installation. The caller supplies
// a digest authenticated through its release-verification channel. A local digest
// receipt detects substitution; it is not a substitute for a release signature.
package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

var (
	ErrUnsafe      = errors.New("unsafe_install")
	ErrUnverified  = errors.New("autostart_unverified_install")
	ErrUnavailable = errors.New("autostart_unavailable")
	ErrStopped     = errors.New("autostart_stopped")
	ErrUpgrade     = errors.New("upgrade_pending")
)

// Executable holds an open, verified image. Do not reopen Path to launch it.
// Start retains the verification handles until process creation has completed.
// Same-user modification is outside the node's security boundary.
type Executable struct {
	Path    string
	SHA256  string
	mu      sync.Mutex
	file    *os.File
	release func()
}

func validDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == sha256.Size && s == strings.ToLower(s)
}

func verify(path, digest string) (*Executable, error) {
	if !validDigest(digest) {
		return nil, ErrUnverified
	}
	f, release, e := openTrusted(path, false)
	if e != nil {
		return nil, ErrUnsafe
	}
	fail := func() (*Executable, error) { f.Close(); release(); return nil, ErrUnverified }
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, 512<<20+1)); e != nil {
		return fail()
	}
	st, e := f.Stat()
	if e != nil || st.Size() > 512<<20 || hex.EncodeToString(h.Sum(nil)) != digest {
		return fail()
	}
	if _, e = f.Seek(0, 0); e != nil {
		return fail()
	}
	return &Executable{Path: path, SHA256: digest, file: f, release: release}, nil
}

func (v *Executable) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.file == nil {
		return nil
	}
	e := v.file.Close()
	v.file = nil
	v.release()
	return e
}

func (v *Executable) Start(ctx context.Context, args ...string) (*exec.Cmd, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if v.file == nil {
		return nil, ErrUnverified
	}
	// Recheck digest and identity as well as the pinned ancestor chain. Windows
	// retains no-write/no-delete-sharing handles. Unix forbids every ancestor
	// writable by another principal, including sticky directories and ACL grants.
	other, e := verify(v.Path, v.SHA256)
	if e != nil {
		return nil, e
	}
	defer other.Close()
	a, e := v.file.Stat()
	if e != nil {
		return nil, ErrUnverified
	}
	b, e := other.file.Stat()
	if e != nil || !os.SameFile(a, b) {
		return nil, ErrUnverified
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	// Context bounds launch admission, never daemon lifetime. CommandContext
	// would SIGKILL a writer when a short-lived shim's deadline expires.
	cmd := exec.Command(v.Path, args...)
	if e = cmd.Start(); e != nil {
		return nil, e
	}
	return cmd, nil
}

// VerifiedExecutable checks the recorded image, versioned target and lifecycle
// intent. Managed callers should use Start, which asks the service manager to
// launch the installed managed-daemon entrypoint, rather than detach a process.
func VerifiedExecutable(dir string) (*Executable, error) {
	r, e := readReceipt(dir)
	if e != nil {
		return nil, e
	}
	if e = checkIntent(dir, r); e != nil {
		return nil, e
	}
	return verify(r.Executable, r.SHA256)
}

// VerifyRunning is mandatory at managed-daemon entry before any store is opened.
// It prevents a copied/old binary from adopting a newer installation receipt.
func VerifyRunning(dir string) (Record, error) {
	r, e := readReceipt(dir)
	if e != nil {
		return Record{}, e
	}
	v, e := VerifiedExecutable(dir)
	if e != nil {
		return Record{}, e
	}
	defer v.Close()
	path, e := os.Executable()
	if e != nil {
		return Record{}, ErrUnverified
	}
	path, e = filepath.Abs(path)
	if e != nil || path != r.Executable {
		return Record{}, ErrUnverified
	}
	f, release, e := openTrusted(path, false)
	if e != nil {
		return Record{}, ErrUnverified
	}
	defer release()
	defer f.Close()
	a, e := f.Stat()
	if e != nil {
		return Record{}, ErrUnverified
	}
	b, e := v.file.Stat()
	if e != nil || !os.SameFile(a, b) {
		return Record{}, ErrUnverified
	}
	return r, nil
}
