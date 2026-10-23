//go:build linux || darwin

package capture

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type openedUnitHandle struct {
	file          *os.File
	parent        int
	name          string
	initial       os.FileInfo
	initialChange int64
	directories   []int
	bindings      []directoryBinding
}

func changeTime(st *unix.Stat_t) int64 { return st.Ctim.Sec*1e9 + st.Ctim.Nsec }

func private(st *unix.Stat_t, dir bool) bool {
	want := uint32(unix.S_IFREG)
	if dir {
		want = unix.S_IFDIR
	}
	return uint32(st.Mode)&unix.S_IFMT == want && st.Uid == uint32(os.Getuid()) && st.Mode&0077 == 0
}

type directoryBinding struct {
	parent         int
	name           string
	initial        unix.Stat_t
	requirePrivate bool
}

func openUnit(root, relative string) (*openedUnitHandle, error) {
	parts := strings.Split(strings.TrimPrefix(root, "/"), "/")
	children := strings.Split(relative, string(filepath.Separator))
	if len(parts)+len(children) > 128 {
		return nil, hold("path_depth")
	}
	for _, part := range append(append([]string(nil), parts...), children...) {
		if part == "" || part == "." || part == ".." {
			return nil, hold("unsafe_path")
		}
	}
	d, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, hold("unsafe_path")
	}
	dirs := []int{d}
	var bindings []directoryBinding
	transferred := false
	defer func() {
		if !transferred {
			for _, fd := range dirs {
				_ = unix.Close(fd)
			}
		}
	}()
	openDir := func(part string, requirePrivate bool) error {
		next, e := unix.Openat(d, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			return hold("unsafe_path")
		}
		var st unix.Stat_t
		if unix.Fstat(next, &st) != nil || uint32(st.Mode)&unix.S_IFMT != unix.S_IFDIR || (requirePrivate && !private(&st, true)) {
			_ = unix.Close(next)
			return hold("unsafe_permissions")
		}
		bindings = append(bindings, directoryBinding{parent: d, name: part, initial: st, requirePrivate: requirePrivate})
		dirs = append(dirs, next)
		d = next
		return nil
	}
	for i, part := range parts {
		if err := openDir(part, i == len(parts)-1); err != nil {
			return nil, err
		}
	}
	for _, part := range children[:len(children)-1] {
		if err := openDir(part, true); err != nil {
			return nil, err
		}
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
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !private(&st, false) {
		_ = file.Close()
		return nil, hold("unsafe_permissions")
	}
	info, e := file.Stat()
	if e != nil || info.Size() > maxUnit {
		_ = file.Close()
		return nil, hold("unit_limit")
	}
	h := &openedUnitHandle{file: file, parent: d, name: name, initial: info, initialChange: changeTime(&st), directories: dirs, bindings: bindings}
	transferred = true
	return h, nil
}
func (h *openedUnitHandle) close() {
	if h == nil {
		return
	}
	if h.file != nil {
		_ = h.file.Close()
		h.file = nil
	}
	for _, fd := range h.directories {
		_ = unix.Close(fd)
	}
	h.directories = nil
}
func (h *openedUnitHandle) stable() bool {
	if h == nil || h.file == nil {
		return false
	}
	for _, binding := range h.bindings {
		var current unix.Stat_t
		if unix.Fstatat(binding.parent, binding.name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return false
		}
		old := binding.initial
		if current.Dev != old.Dev || current.Ino != old.Ino || current.Mode != old.Mode || current.Uid != old.Uid || current.Gid != old.Gid || uint32(current.Mode)&unix.S_IFMT != unix.S_IFDIR {
			return false
		}
		if binding.requirePrivate && !private(&current, true) {
			return false
		}
	}

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

func (h *openedUnitHandle) quiet(now time.Time) bool {
	return h.stable() && !now.Before(h.initial.ModTime().Add(2*time.Second)) && !now.Before(time.Unix(0, h.initialChange).Add(2*time.Second))
}
