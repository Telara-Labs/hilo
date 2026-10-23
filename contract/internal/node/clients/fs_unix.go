//go:build darwin || linux

package clients

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"golang.org/x/sys/unix"
)

type directory struct {
	fd      int
	private bool
}

func (d *directory) close() { unix.Close(d.fd) }
func alias(p string) string {
	if runtime.GOOS == "darwin" {
		for _, prefix := range []string{"/tmp", "/var", "/etc"} {
			if p == prefix || strings.HasPrefix(p, prefix+"/") {
				return "/private" + p
			}
		}
	}
	return p
}

// Pin every directory with no-follow openat. No operation below re-resolves the
// parent path, so a renamed parent cannot redirect publication outside the pin.
func openDir(path string, create, private bool) (*directory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnsafe
	}
	if private && create {
		if ipc.ValidateDir(path, true) != nil {
			return nil, ErrUnsafe
		}
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrUnsafe
	}
	parts := strings.Split(strings.TrimPrefix(alias(path), "/"), "/")
	for i, part := range parts {
		n, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(e, unix.ENOENT) && create {
			if e = unix.Mkdirat(fd, part, 0700); e == nil || errors.Is(e, unix.EEXIST) {
				n, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		unix.Close(fd)
		if e != nil {
			if errors.Is(e, unix.ENOENT) {
				return nil, os.ErrNotExist
			}
			return nil, ErrUnsafe
		}
		fd = n
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (st.Uid != uint32(os.Geteuid()) && st.Uid != 0) || (st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0) || (private && i == len(parts)-1 && (st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700)) {
			unix.Close(fd)
			return nil, ErrUnsafe
		}
	}
	if private {
		if e := ipc.ValidateDir(path, false); e != nil {
			unix.Close(fd)
			return nil, ErrUnsafe
		}
	}
	return &directory{fd: fd, private: private}, nil
}
func validName(n string) bool {
	return n != "" && n != "." && n != ".." && !strings.ContainsAny(n, "/\\:\x00")
}
func (d *directory) file(name string, flags int) (*os.File, error) {
	if !validName(name) {
		return nil, ErrUnsafe
	}
	var n int
	var e error
	// Darwin may return transient ENOENT during simultaneous O_CREAT opens.
	// Retry only creation lookup on this pinned descriptor, never unsafe paths.
	for attempt := 0; attempt < 16; attempt++ {
		n, e = unix.Openat(d.fd, name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
		if flags&unix.O_CREAT == 0 || (!errors.Is(e, unix.ENOENT) && !errors.Is(e, unix.EINTR)) {
			break
		}
	}
	if e != nil {
		if errors.Is(e, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		if errors.Is(e, unix.EEXIST) {
			return nil, os.ErrExist
		}
		return nil, ErrUnsafe
	}
	var st unix.Stat_t
	if unix.Fstat(n, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0022 != 0 || (d.private && st.Mode&0777 != 0600) {
		unix.Close(n)
		return nil, ErrUnsafe
	}
	return os.NewFile(uintptr(n), name), nil
}
func (d *directory) read(name string, max int64) ([]byte, error) {
	f, e := d.file(name, unix.O_RDONLY)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, ErrUnsafe
	}
	return b, nil
}
func (d *directory) create(name string, b []byte) error {
	f, e := d.file(name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			unix.Unlinkat(d.fd, name, 0)
		}
	}()
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	ok = true
	return nil
}
func (d *directory) lock() (func(), error) {
	f, e := d.file(".telara-memory.lock", unix.O_RDWR|unix.O_CREAT)
	if e != nil {
		return nil, e
	}
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, ErrBusy
	}
	return func() { f.Close() }, nil
}
func (d *directory) remove(name string) error {
	if !validName(name) {
		return ErrUnsafe
	}
	return unix.Unlinkat(d.fd, name, 0)
}
func (d *directory) sync() error { return unix.Fsync(d.fd) }
func checkSource(path string) error {
	d, e := openDir(filepath.Dir(path), false, false)
	if e != nil {
		return e
	}
	defer d.close()
	f, e := d.file(filepath.Base(path), unix.O_RDONLY)
	if e != nil {
		return e
	}
	f.Close()
	return nil
}
