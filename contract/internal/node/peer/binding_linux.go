//go:build linux

package peer

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
)

type linuxBinding struct {
	pid, fd  int
	identity string
	path     string
	image    *os.File
}

func bindProcess(c net.Conn) (processBinding, error) {
	conn, ok := c.(*net.UnixConn)
	if !ok {
		return nil, ErrAuthority
	}
	raw, e := conn.SyscallConn()
	if e != nil {
		return nil, e
	}
	var cred *unix.Ucred
	var ce error
	pinned := -1
	if e = raw.Control(func(fd uintptr) {
		cred, ce = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if ce == nil {
			pinned, ce = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
		}
	}); e != nil || ce != nil || cred == nil || cred.Uid != uint32(os.Geteuid()) {
		if pinned >= 0 {
			unix.Close(pinned)
		}
		return nil, ErrAuthority
	}
	// Obtain the socket creator's pidfd atomically. A PID lookup followed by
	// PidfdOpen could instead pin a replacement process before accept.
	unix.CloseOnExec(pinned)
	pid := int(cred.Pid)
	b := &linuxBinding{pid: pid, fd: pinned}
	b.path, b.identity, e = executable(pid)
	if e == nil {
		b.image, e = openImage(pid, "")
	}
	if e != nil || b.check(pid) != nil {
		b.close()
		return nil, ErrAuthority
	}
	return b, nil
}
func (b *linuxBinding) check(pid int) error {
	if pid != b.pid || b.fd < 0 || b.image == nil {
		return ErrAuthority
	}
	p := []unix.PollFd{{Fd: int32(b.fd), Events: unix.POLLIN}}
	n, e := unix.Poll(p, 0)
	if e != nil || n != 0 {
		return ErrAuthority
	}
	path, id, e := executable(pid)
	if e != nil || id != b.identity || path != b.path {
		return ErrAuthority
	}
	current, e := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if e != nil {
		return ErrAuthority
	}
	old, e := b.image.Stat()
	if e != nil || !os.SameFile(current, old) {
		return ErrAuthority
	}
	installed, e := os.Stat(path)
	if e != nil || !os.SameFile(old, installed) {
		return ErrAuthority
	}
	return nil
}
func (b *linuxBinding) close() {
	if b.fd >= 0 {
		unix.Close(b.fd)
		b.fd = -1
	}
	if b.image != nil {
		b.image.Close()
		b.image = nil
	}
}
