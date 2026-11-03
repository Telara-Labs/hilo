//go:build linux || darwin

package capture

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
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
	contained     bool
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
	requireOwned   bool
	fd             int
}

func openUnit(root, relative string) (*openedUnitHandle, error) {
	return openUnitPolicy(root, relative, "")
}

// Only trusted installed adapter configuration supplies home/root. A private
// configured client directory protects normal native 0755/0644 descendants.
func openNativeUnit(home, root, relative string) (*openedUnitHandle, error) {
	anchor := filepath.Dir(root)
	rel, err := filepath.Rel(home, anchor)
	if root == home || err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return openUnit(root, relative)
	}
	return openUnitPolicy(root, relative, anchor)
}
func ownedReadOnly(st *unix.Stat_t, dir bool) bool {
	want := uint32(unix.S_IFREG)
	if dir {
		want = unix.S_IFDIR
	}
	return uint32(st.Mode)&unix.S_IFMT == want && st.Uid == uint32(os.Getuid()) && st.Mode&0022 == 0
}
func safeSourceAncestor(st *unix.Stat_t) bool {
	return (st.Uid == 0 || st.Uid == uint32(os.Getuid())) && (st.Mode&0022 == 0 || st.Mode&unix.S_ISVTX != 0)
}
func sourceMode(st *unix.Stat_t, contained bool) bool {
	if st.Nlink != 1 {
		return false
	}
	if contained {
		return ownedReadOnly(st, false)
	}
	return private(st, false)
}
func openUnitPolicy(root, relative, anchor string) (*openedUnitHandle, error) {
	contained := anchor != ""
	anchorParts := len(strings.Split(strings.TrimPrefix(anchor, "/"), "/"))
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
	openDir := func(part string, requirePrivate, requireOwned bool) error {
		next, e := unix.Openat(d, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			if e == unix.ENOENT {
				return hold("source_absent")
			}
			return hold("unsafe_path")
		}
		var st unix.Stat_t
		if unix.Fstat(next, &st) != nil || uint32(st.Mode)&unix.S_IFMT != unix.S_IFDIR || (requirePrivate && !private(&st, true)) || (requireOwned && !ownedReadOnly(&st, true)) || (contained && !requireOwned && !safeSourceAncestor(&st)) || ipc.ValidateDescriptorACL(next, requirePrivate) != nil {
			_ = unix.Close(next)
			return hold("unsafe_permissions")
		}
		bindings = append(bindings, directoryBinding{parent: d, name: part, initial: st, requirePrivate: requirePrivate, requireOwned: requireOwned, fd: next})
		dirs = append(dirs, next)
		d = next
		return nil
	}
	for i, part := range parts {
		requirePrivate := i == len(parts)-1
		requireOwned := requirePrivate
		if contained {
			requirePrivate = i == anchorParts-1
			requireOwned = i >= anchorParts-1
		}
		if err := openDir(part, requirePrivate, requireOwned); err != nil {
			return nil, err
		}
	}
	for _, part := range children[:len(children)-1] {
		if err := openDir(part, !contained, true); err != nil {
			return nil, err
		}
	}
	name := children[len(children)-1]
	fd, e := unix.Openat(d, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		if e == unix.ENOENT {
			return nil, hold("source_absent")
		}
		return nil, hold("unsafe_file")
	}
	file := os.NewFile(uintptr(fd), "capture-unit")
	if file == nil {
		_ = unix.Close(fd)
		return nil, hold("unsafe_file")
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !sourceMode(&st, contained) || ipc.ValidateDescriptorACL(fd, !contained) != nil {
		_ = file.Close()
		return nil, hold("unsafe_permissions")
	}
	info, e := file.Stat()
	if e != nil || info.Size() > maxUnit {
		_ = file.Close()
		return nil, hold("unit_limit")
	}
	h := &openedUnitHandle{file: file, parent: d, name: name, initial: info, initialChange: changeTime(&st), directories: dirs, bindings: bindings, contained: contained}
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

// bound keeps filesystem identity/permissions separate from content settling.
// Content may change on a live bound source; a replaced path never qualifies.
func (h *openedUnitHandle) bound() bool {
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
		if binding.requirePrivate && !private(&current, true) || binding.requireOwned && !ownedReadOnly(&current, true) || ipc.ValidateDescriptorACL(binding.fd, binding.requirePrivate) != nil {
			return false
		}
	}

	info, err := h.file.Stat()
	if err != nil || !os.SameFile(info, h.initial) || info.Mode() != h.initial.Mode() {
		return false
	}
	var fd, path unix.Stat_t
	if unix.Fstat(int(h.file.Fd()), &fd) != nil || !sourceMode(&fd, h.contained) || ipc.ValidateDescriptorACL(int(h.file.Fd()), !h.contained) != nil || unix.Fstatat(h.parent, h.name, &path, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return false
	}
	return sourceMode(&path, h.contained) && path.Dev == fd.Dev && path.Ino == fd.Ino && path.Nlink == fd.Nlink && path.Mode == fd.Mode && path.Uid == fd.Uid && path.Gid == fd.Gid
}

// stable compares size, mtime and ctime after checking the filesystem binding.
// Linux ctime is coarse; same-tick rewrites with restored mtime can escape it.
func (h *openedUnitHandle) stable() bool {
	if !h.bound() {
		return false
	}
	info, err := h.file.Stat()
	var st unix.Stat_t
	return err == nil && info.Size() == h.initial.Size() && info.ModTime().Equal(h.initial.ModTime()) && unix.Fstat(int(h.file.Fd()), &st) == nil && changeTime(&st) == h.initialChange
}

func (h *openedUnitHandle) quiet(now time.Time) bool {
	return h.stable() && !now.Before(h.initial.ModTime().Add(2*time.Second)) && !now.Before(time.Unix(0, h.initialChange).Add(2*time.Second))
}
