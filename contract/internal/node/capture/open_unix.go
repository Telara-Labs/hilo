//go:build linux || darwin

package capture

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type openedUnitHandle struct {
	file          *os.File
	parent        int
	name          string
	initial       os.FileInfo
	initialChange int64
}

func changeTime(st *unix.Stat_t) int64 { return st.Ctim.Sec*1e9 + st.Ctim.Nsec }

func private(st *unix.Stat_t, dir bool) bool {
	want := uint32(unix.S_IFREG)
	if dir {
		want = unix.S_IFDIR
	}
	return uint32(st.Mode)&unix.S_IFMT == want && st.Uid == uint32(os.Getuid()) && st.Mode&0077 == 0
}
func openUnit(root, relative string) (*openedUnitHandle, error) {
	// Walk from a held / descriptor. No ancestor, configured root, child, or
	// final unit is resolved through a symlink, including during a rename race.
	d, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, hold("unsafe_path")
	}
	defer func() {
		if d >= 0 {
			_ = unix.Close(d)
		}
	}()
	parts := strings.Split(strings.TrimPrefix(root, "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, hold("unsafe_path")
		}
		next, e := unix.Openat(d, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			return nil, hold("unsafe_path")
		}
		_ = unix.Close(d)
		d = next
	}
	var st unix.Stat_t
	if unix.Fstat(d, &st) != nil || !private(&st, true) {
		return nil, hold("unsafe_permissions")
	}
	children := strings.Split(relative, string(filepath.Separator))
	for _, part := range children[:len(children)-1] {
		next, e := unix.Openat(d, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			return nil, hold("unsafe_path")
		}
		if unix.Fstat(next, &st) != nil || !private(&st, true) {
			_ = unix.Close(next)
			return nil, hold("unsafe_permissions")
		}
		_ = unix.Close(d)
		d = next
	}
	name := children[len(children)-1]
	fd, e := unix.Openat(d, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, hold("unsafe_file")
	}
	file := os.NewFile(uintptr(fd), "capture-unit")
	if file == nil {
		_ = unix.Close(fd)
		return nil, hold("unsafe_file")
	}
	if unix.Fstat(fd, &st) != nil || !private(&st, false) {
		_ = file.Close()
		return nil, hold("unsafe_permissions")
	}
	info, e := file.Stat()
	if e != nil || info.Size() > maxUnit {
		_ = file.Close()
		return nil, hold("unit_limit")
	}
	h := &openedUnitHandle{file: file, parent: d, name: name, initial: info}
	h.initialChange = changeTime(&st)
	d = -1
	return h, nil
}
func (h *openedUnitHandle) close() { _ = h.file.Close(); _ = unix.Close(h.parent) }
func (h *openedUnitHandle) stable() bool {
	info, err := h.file.Stat()
	if err != nil || !os.SameFile(info, h.initial) || info.Size() != h.initial.Size() || !info.ModTime().Equal(h.initial.ModTime()) || info.Mode() != h.initial.Mode() {
		return false
	}
	var fd, path unix.Stat_t
	if unix.Fstat(int(h.file.Fd()), &fd) != nil || !private(&fd, false) || changeTime(&fd) != h.initialChange || unix.Fstatat(h.parent, h.name, &path, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return false
	}
	return private(&path, false) && path.Dev == fd.Dev && path.Ino == fd.Ino && path.Size == fd.Size && path.Nlink == fd.Nlink
}
