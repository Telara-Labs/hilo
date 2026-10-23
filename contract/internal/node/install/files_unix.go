//go:build darwin || linux

package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func trustedStat(st *unix.Stat_t, private, directory bool) bool {
	if st.Uid != uint32(os.Geteuid()) && (private || st.Uid != 0) {
		return false
	}
	if st.Mode&0022 != 0 || st.Mode&07000 != 0 {
		return false
	}
	if private && st.Mode&0077 != 0 {
		return false
	}
	if directory {
		return st.Mode&unix.S_IFMT == unix.S_IFDIR
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0111 != 0 && st.Nlink == 1
}

// No pathname symlink exceptions, including /tmp. Callers must use a canonical
// installation path rooted in a non-mutable owner/root directory.
func trustedDir(path string, create, private bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, ErrUnsafe
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, ErrUnsafe
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range append([]string{"."}, parts...) {
		last := i == len(parts)
		n, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(e, unix.ENOENT) && create {
			if e = unix.Mkdirat(fd, part, 0700); e == nil || errors.Is(e, unix.EEXIST) {
				n, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		unix.Close(fd)
		if e != nil {
			return -1, ErrUnsafe
		}
		fd = n
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || !trustedStat(&st, private && last, true) || checkACL(fd, private && last) != nil {
			unix.Close(fd)
			return -1, ErrUnsafe
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
		return nil, nil, ErrUnsafe
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
	good := unix.Fstat(fd, &st) == nil
	if private {
		good = good && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == uint32(os.Geteuid()) && st.Mode&0777 == 0600 && st.Nlink == 1
	} else {
		good = good && trustedStat(&st, false, false)
	}
	if !good || checkACL(fd, private) != nil {
		unix.Close(fd)
		unix.Close(d)
		return nil, nil, ErrUnsafe
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
	if checkACL(fd, true) != nil {
		return ErrUnsafe
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
