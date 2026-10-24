//go:build darwin || linux

package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func trustedStat(st *unix.Stat_t, private, directory bool) bool {
	return trustedStatError(st, "metadata", private, directory) == nil
}

func trustedStatError(st *unix.Stat_t, path string, private, directory bool) error {
	fail := func(rule string) error {
		return unsafePath("validate metadata", path, fmt.Sprintf("%s (uid=%d mode=%#o nlink=%d)", rule, st.Uid, st.Mode, st.Nlink), nil)
	}
	if st.Uid != uint32(os.Geteuid()) && (private || st.Uid != 0) {
		return fail("owner must be current user, or root for non-private objects")
	}
	if st.Mode&0022 != 0 {
		return fail("mode forbids group/other writes")
	}
	if st.Mode&07000 != 0 {
		return fail("mode forbids setuid, setgid and sticky bits")
	}
	if private && st.Mode&0077 != 0 {
		return fail("private mode forbids group/other access")
	}
	if directory {
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return fail("type must be directory")
		}
	} else {
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return fail("type must be regular file")
		}
		if st.Mode&0111 == 0 {
			return fail("executable source must have an execute bit")
		}
		if st.Nlink != 1 {
			return fail("link count must be one")
		}
	}
	return nil
}

// No pathname symlink exceptions, including /tmp. Callers must use a canonical
// installation path rooted in a non-mutable owner/root directory.
func trustedDir(path string, create, private bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, unsafePath("trustedDir", path, "absolute clean non-root path required", nil)
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, unsafePath("open root", "/", "directory open required", e)
	}
	current := "/"
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range append([]string{"."}, parts...) {
		current = filepath.Join(current, part)
		last := i == len(parts)
		n, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(e, unix.ENOENT) && create {
			if e = unix.Mkdirat(fd, part, 0700); e == nil || errors.Is(e, unix.EEXIST) {
				n, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		unix.Close(fd)
		if e != nil {
			return -1, unsafePath("openat directory", current, "no symlink; directory open/create required", e)
		}
		fd = n
		var st unix.Stat_t
		if e = unix.Fstat(fd, &st); e == nil {
			e = trustedStatError(&st, current, private && last, true)
		}
		if e == nil {
			e = checkACL(fd, private && last)
		}
		if e != nil {
			unix.Close(fd)
			return -1, unsafePath("trustedDir", current, "directory metadata/ACL validation required", e)
		}
	}
	return fd, nil
}

func ensureDir(path string, private bool) error {
	fd, e := trustedDir(path, true, private)
	if e != nil {
		return e
	}
	return unix.Close(fd)
}
func checkDir(path string, private bool) error {
	fd, e := trustedDir(path, false, private)
	if e != nil {
		return e
	}
	return unix.Close(fd)
}

func openTrusted(path string, private bool) (*os.File, func(), error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nil, unsafePath("openTrusted", path, "absolute clean path required", nil)
	}
	d, e := trustedDir(filepath.Dir(path), false, false)
	if e != nil {
		return nil, nil, e
	}
	fd, e := unix.Openat(d, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		unix.Close(d)
		return nil, nil, e
	}
	var st unix.Stat_t
	e = unix.Fstat(fd, &st)
	if e == nil {
		if private {
			switch {
			case st.Mode&unix.S_IFMT != unix.S_IFREG:
				e = unsafePath("openTrusted", path, "type must be regular file", nil)
			case st.Uid != uint32(os.Geteuid()):
				e = unsafePath("openTrusted", path, "owner must be current user", nil)
			case st.Mode&0777 != 0600:
				e = unsafePath("openTrusted", path, "private mode must be 0600", nil)
			case st.Nlink != 1:
				e = unsafePath("openTrusted", path, "link count must be one", nil)
			}
		} else {
			e = trustedStatError(&st, path, false, false)
		}
	}
	if e == nil {
		e = checkACL(fd, private)
	}
	if e != nil {
		unix.Close(fd)
		unix.Close(d)
		return nil, nil, unsafePath("openTrusted", path, "file metadata/ACL validation required", e)
	}
	return os.NewFile(uintptr(fd), path), func() { unix.Close(d) }, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	d, e := trustedDir(filepath.Dir(path), false, false)
	if e != nil {
		return e
	}
	defer unix.Close(d)
	name, e := randomName()
	if e != nil {
		return e
	}
	fd, e := unix.Openat(d, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode))
	if e != nil {
		return e
	}
	defer unix.Unlinkat(d, name, 0)
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if e := checkACL(fd, true); e != nil {
		return unsafePath("writeAtomic", filepath.Join(filepath.Dir(path), name), "private ACL required", e)
	}
	if _, e = f.Write(data); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = unix.Renameat(d, name, d, filepath.Base(path)); e != nil {
		return e
	}
	return unix.Fsync(d)
}

func removeOwned(path string) error {
	f, release, e := openTrusted(path, true)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	f.Close()
	release()
	d, e := trustedDir(filepath.Dir(path), false, false)
	if e != nil {
		return e
	}
	defer unix.Close(d)
	if e = unix.Unlinkat(d, filepath.Base(path), 0); e != nil {
		return e
	}
	return unix.Fsync(d)
}
