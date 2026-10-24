//go:build linux || darwin

package capture

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type signalDirectory struct {
	file     *os.File
	dirs     []int
	bindings []directoryBinding
}

func openSignalDirectory(root, relative string) (*signalDirectory, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return nil, hold("unsafe_spool")
	}
	parts := strings.Split(strings.TrimPrefix(root, "/"), "/")
	children := strings.Split(relative, string(filepath.Separator))
	if len(parts)+len(children) > 128 {
		return nil, hold("unsafe_spool")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, hold("unsafe_spool")
	}
	d := &signalDirectory{dirs: []int{fd}}
	success := false
	defer func() {
		if !success {
			d.close()
		}
	}()
	for i, part := range append(parts, children...) {
		if part == "" || part == "." || part == ".." {
			return nil, hold("unsafe_spool")
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		if err != nil {
			return nil, hold("unsafe_spool")
		}
		d.dirs = append(d.dirs, next)
		var st unix.Stat_t
		if unix.Fstat(next, &st) != nil || uint32(st.Mode)&unix.S_IFMT != unix.S_IFDIR {
			return nil, hold("unsafe_spool")
		}
		privateRequired := i >= len(parts)-1
		if privateRequired && !private(&st, true) {
			return nil, hold("unsafe_spool")
		}
		if !privateRequired && ((st.Uid != 0 && st.Uid != uint32(os.Getuid())) || (st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0)) {
			return nil, hold("unsafe_spool")
		}
		d.bindings = append(d.bindings, directoryBinding{parent: fd, name: part, initial: st, requirePrivate: privateRequired})
		fd = next
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, hold("unsafe_spool")
	}
	unix.CloseOnExec(dup)
	d.file = os.NewFile(uintptr(dup), "capture-spool")
	success = true
	return d, nil
}
func (d *signalDirectory) close() {
	if d.file != nil {
		d.file.Close()
	}
	for _, fd := range d.dirs {
		unix.Close(fd)
	}
}
func (d *signalDirectory) check() error {
	for _, b := range d.bindings {
		var now unix.Stat_t
		if unix.Fstatat(b.parent, b.name, &now, unix.AT_SYMLINK_NOFOLLOW) != nil || now.Dev != b.initial.Dev || now.Ino != b.initial.Ino || now.Mode != b.initial.Mode || now.Uid != b.initial.Uid || now.Gid != b.initial.Gid {
			return hold("unsafe_spool")
		}
	}
	return nil
}
func (d *signalDirectory) names() ([]string, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	names, err := d.file.Readdirnames(65537)
	if err != nil && err != io.EOF || len(names) > 65536 {
		return nil, hold("spool_limit")
	}
	if err = d.check(); err != nil {
		return nil, err
	}
	return names, nil
}
func (d *signalDirectory) read(name string) ([]byte, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, hold("unsafe_spool")
	}
	f := os.NewFile(uintptr(fd), "capture-signal")
	defer f.Close()
	var initial unix.Stat_t
	if unix.Fstat(fd, &initial) != nil || !private(&initial, false) || initial.Nlink != 1 {
		return nil, hold("unsafe_spool")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	var now, path unix.Stat_t
	if err != nil || unix.Fstat(fd, &now) != nil || unix.Fstatat(int(d.file.Fd()), name, &path, unix.AT_SYMLINK_NOFOLLOW) != nil || now.Dev != initial.Dev || now.Ino != initial.Ino || now.Size != initial.Size || now.Mode != initial.Mode || changeTime(&now) != changeTime(&initial) || path.Dev != now.Dev || path.Ino != now.Ino || d.check() != nil {
		clear(raw)
		return nil, hold("unsafe_spool")
	}
	return raw, nil
}
func (d *signalDirectory) remove(name string) error {
	if name == "" || filepath.Base(name) != name {
		return hold("unsafe_spool")
	}
	if err := d.check(); err != nil {
		return err
	}
	if unix.Unlinkat(int(d.file.Fd()), name, 0) != nil {
		return hold("spool_unlink_failed")
	}
	if unix.Fsync(int(d.file.Fd())) != nil {
		return hold("spool_unlink_failed")
	}
	return nil
}
func (d *signalDirectory) abandon(name string, before time.Time) (bool, error) {
	if err := d.check(); err != nil {
		return false, err
	}
	var st unix.Stat_t
	if unix.Fstatat(int(d.file.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !private(&st, false) || st.Nlink != 1 {
		return false, hold("unsafe_spool")
	}
	if !time.Unix(st.Mtim.Sec, st.Mtim.Nsec).Before(before) {
		return false, nil
	}
	if err := d.remove(name); err != nil {
		return false, err
	}
	return true, nil
}
