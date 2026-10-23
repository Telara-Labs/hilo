package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func Peer(c net.Conn) (int, error) {
	u, ok := c.(*net.UnixConn)
	if !ok {
		return 0, ErrPeer
	}
	raw, e := u.SyscallConn()
	if e != nil {
		return 0, ErrPeer
	}
	var cred *unix.Ucred
	var se error
	e = raw.Control(func(fd uintptr) { cred, se = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil || se != nil || cred == nil || cred.Uid != uint32(os.Geteuid()) {
		return 0, ErrPeer
	}
	return int(cred.Pid), nil
}

func checkACL(fd int, private bool) error {
	_, e := unix.Fgetxattr(fd, "system.posix_acl_access", nil)
	if errors.Is(e, unix.ENODATA) || errors.Is(e, unix.ENOTSUP) {
		return nil
	}
	return ErrUnsafe
}
func processIdentity(pid int) (string, error) {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(e, os.ErrNotExist) {
		return "", unix.ESRCH
	}
	if e != nil {
		return "", e
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return "", ErrUnsafe
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 20 {
		return "", ErrUnsafe
	}
	if _, e := strconv.ParseUint(fields[19], 10, 64); e != nil {
		return "", ErrUnsafe
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(string(boot)) + "/" + fields[19], nil
}
