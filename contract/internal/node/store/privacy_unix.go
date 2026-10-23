//go:build linux || darwin

package store

import (
	"os"
	"path/filepath"
	"syscall"
)

func owned(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// The pathname stays under root/owner-controlled directories. A root/owner
// sticky temporary directory permits safe owned children; a writable nonsticky
// ancestor does not, even when the final directory itself is private.
func protectedChain(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e == nil {
			st, ok := i.Sys().(*syscall.Stat_t)
			if !ok || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) {
				return failure("unsafe_path")
			}
			if i.Mode().Perm()&0022 != 0 && i.Mode()&os.ModeSticky == 0 {
				return failure("unsafe_path")
			}
		} else if !os.IsNotExist(e) {
			return failure("unsafe_path")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
func privateDir(path string) error {
	if e := protectedChain(path); e != nil {
		return e
	}
	if e := os.MkdirAll(path, 0700); e != nil {
		return failure("unsafe_path")
	}
	if e := protectedChain(path); e != nil {
		return e
	}
	i, e := os.Lstat(path)
	if e != nil || !i.IsDir() || !owned(i) || i.Mode().Perm()&0077 != 0 {
		return failure("unsafe_path")
	}
	return nil
}
func privateFile(path string) error {
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || !owned(i) || i.Mode().Perm()&0077 != 0 {
		return failure("unsafe_path")
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		return failure("unsafe_path")
	}
	return nil
}
