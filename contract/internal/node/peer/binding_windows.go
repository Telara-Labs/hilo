//go:build windows

package peer

import (
	"golang.org/x/sys/windows"
	"net"
	"syscall"
)

type windowsBinding struct {
	pid            int
	handle         windows.Handle
	identity, path string
	conn           net.Conn
}

func pipePID(c net.Conn) (int, error) {
	s, ok := c.(syscall.Conn)
	if !ok {
		return 0, ErrAuthority
	}
	raw, e := s.SyscallConn()
	if e != nil {
		return 0, e
	}
	var pid uint32
	var ce error
	if e = raw.Control(func(fd uintptr) { ce = windows.GetNamedPipeClientProcessId(windows.Handle(fd), &pid) }); e != nil || ce != nil || pid == 0 {
		return 0, ErrAuthority
	}
	return int(pid), nil
}
func bindProcess(c net.Conn) (processBinding, error) {
	pid, e := pipePID(c)
	if e != nil {
		return nil, e
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if e != nil {
		return nil, ErrAuthority
	}
	b := &windowsBinding{pid: pid, handle: h, conn: c}
	b.path, b.identity, e = executable(pid)
	if e != nil || b.check(pid) != nil {
		b.close()
		return nil, ErrAuthority
	}
	return b, nil
}
func (b *windowsBinding) check(pid int) error {
	if b.handle == 0 || b.pid != pid {
		return ErrAuthority
	}
	if result, e := windows.WaitForSingleObject(b.handle, 0); e != nil || result != uint32(windows.WAIT_TIMEOUT) {
		return ErrAuthority
	}
	connected, e := pipePID(b.conn)
	if e != nil || connected != pid {
		return ErrAuthority
	}
	id, e := windows.GetProcessId(b.handle)
	if e != nil || int(id) != pid {
		return ErrAuthority
	}
	path, identity, e := executable(pid)
	if e != nil || path != b.path || identity != b.identity {
		return ErrAuthority
	}
	return nil
}
func (b *windowsBinding) close() {
	if b.handle != 0 {
		windows.CloseHandle(b.handle)
		b.handle = 0
	}
}
