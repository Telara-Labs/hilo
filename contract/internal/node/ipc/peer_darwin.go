package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"unsafe"

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
	var uid uint32
	var pid int
	var se error
	e = raw.Control(func(fd uintptr) {
		cred, ce := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if ce != nil {
			se = ce
			return
		}
		uid = cred.Uid
		pid, se = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if e != nil || se != nil || uid != uint32(os.Geteuid()) || pid <= 0 {
		return 0, ErrPeer
	}
	return pid, nil
}

// fgetattrlist returns an attrreference to kauth_filesec (Darwin sys/attr.h,
// sys/kauth.h). Read from the already pinned descriptor, never a pathname.
func checkACL(fd int, private bool) error {
	attrs := unix.Attrlist{Bitmapcount: 5, Commonattr: 0x00400000}
	var buf [4096]byte
	_, _, errno := unix.Syscall6(unix.SYS_FGETATTRLIST, uintptr(fd), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if errno != 0 {
		return unsafePath("fgetattrlist", fmt.Sprintf("fd=%d", fd), "ACL metadata query required", errno)
	}
	return checkDarwinACL(buf[:], private)
}
func processIdentity(pid int) (string, error) {
	p, e := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if e != nil {
		// A nonexistent PID yields a zero-length sysctl result, mapped to EIO
		// by x/sys. Only an independent ESRCH proves absence.
		if errors.Is(unix.Kill(pid, 0), unix.ESRCH) {
			return "", unix.ESRCH
		}
		return "", e
	}
	if p == nil || p.Proc.P_pid != int32(pid) {
		return "", unix.ESRCH
	}
	return fmt.Sprintf("%d.%d", p.Proc.P_starttime.Sec, p.Proc.P_starttime.Usec), nil
}
