//go:build darwin && cgo

package peer

/*
#include <libproc.h>
static int imagePath(int pid, void *b, int n) { return proc_pidpath(pid, b, n); }
*/
import "C"

import (
	"bytes"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func openImage(_ int, path string) (*os.File, error) { return os.Open(path) }

func executable(pid int) (string, string, error) {
	if pid <= 0 {
		return "", "", ErrAuthority
	}
	p, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || p == nil || p.Proc.P_pid != int32(pid) || p.Eproc.Ucred.Uid != uint32(os.Geteuid()) {
		return "", "", ErrAuthority
	}
	b := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n := C.imagePath(C.int(pid), unsafe.Pointer(&b[0]), C.int(len(b)))
	if n <= 0 {
		return "", "", ErrAuthority
	}
	i := bytes.IndexByte(b, 0)
	if i <= 0 {
		return "", "", ErrAuthority
	}
	return string(b[:i]), fmt.Sprintf("%d.%d", p.Proc.P_starttime.Sec, p.Proc.P_starttime.Usec), nil
}
