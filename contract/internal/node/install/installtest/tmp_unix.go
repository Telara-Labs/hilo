//go:build darwin || linux

// Package installtest gives test binaries a temporary root that the
// installer's trusted-directory walk can accept.
package installtest

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// UsePrivateTempRoot points the process temporary directory at a fresh
// owner-only directory under the user cache directory when the current
// temporary root has an ancestor the installer refuses. The stock Linux /tmp
// is sticky and world-writable, so fixtures created under it can never verify;
// the macOS per-user temporary directory is already trusted and is kept. The
// returned function removes the directory it created.
func UsePrivateTempRoot() (func(), error) {
	if trusted(os.TempDir()) {
		return func() {}, nil
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(cache, 0700); err != nil {
		return nil, err
	}
	if !trusted(cache) {
		return nil, fmt.Errorf("no trusted temporary root: %s and %s have an ancestor that is not owner or root controlled", os.TempDir(), cache)
	}
	dir, err := os.MkdirTemp(cache, "telara-memory-test-")
	if err != nil {
		return nil, err
	}
	if err = os.Setenv("TMPDIR", dir); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	return func() { os.RemoveAll(dir) }, nil
}

// trusted mirrors the installer's ancestor rule: every directory from the root
// down is owned by the current user or root, with no group/other write and no
// setuid, setgid or sticky bit.
func trusted(path string) bool {
	p, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	for {
		var st syscall.Stat_t
		if syscall.Lstat(p, &st) != nil {
			return false
		}
		if st.Uid != 0 && st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 || st.Mode&07000 != 0 {
			return false
		}
		parent := filepath.Dir(p)
		if parent == p {
			return true
		}
		p = parent
	}
}
