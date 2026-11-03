//go:build linux || darwin

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"golang.org/x/sys/unix"
)

func repositoryACL(file *os.File) bool {
	return ipc.ValidateDescriptorACL(int(file.Fd()), false) == nil
}
func repositoryIdentity(info os.FileInfo) string {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d", s.Dev, s.Ino, s.Uid)
}
func repositoryMode(info os.FileInfo, root bool) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (s.Uid != 0 && int(s.Uid) != os.Geteuid()) || root && int(s.Uid) != os.Geteuid() {
		return false
	}
	if info.Mode().Perm()&0022 != 0 && !(info.IsDir() && info.Mode()&os.ModeSticky != 0 && s.Uid == 0) {
		return false
	}
	return info.IsDir() || info.Mode().IsRegular() && s.Nlink == 1
}
func openRepositoryPath(root string) (*repositoryPath, error) {
	p := &repositoryPath{root: root, config: filepath.Join(root, ".git", "config")}
	fail := func() (*repositoryPath, error) { p.close(); return nil, failure("unsafe_repository") }
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail()
	}
	current := os.NewFile(uintptr(fd), "/")
	info, err := current.Stat()
	if err != nil || !repositoryMode(info, false) || !repositoryACL(current) {
		current.Close()
		return fail()
	}
	p.held = append(p.held, heldRepositoryPath{"/", current, repositoryIdentity(info)})
	parts := append(strings.Split(strings.TrimPrefix(root, "/"), "/"), ".git", "config")
	if len(parts) > 64 {
		return fail()
	}
	name := "/"
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fail()
		}
		name = filepath.Join(name, part)
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(int(current.Fd()), part, flags, 0)
		if err != nil {
			return fail()
		}
		f := os.NewFile(uintptr(next), name)
		info, err := f.Stat()
		inside := name == root || strings.HasPrefix(name, root+string(filepath.Separator))
		if err != nil || !repositoryMode(info, inside) || !repositoryACL(f) || i == len(parts)-1 && !info.Mode().IsRegular() {
			f.Close()
			return fail()
		}
		p.held = append(p.held, heldRepositoryPath{name, f, repositoryIdentity(info)})
		current = f
	}
	if p.current() != nil {
		return fail()
	}
	return p, nil
}
