package clients

import (
	"errors"
	"strings"

	"github.com/Telara-Labs/hilo/contract/transport"
	"golang.org/x/sys/unix"
)

func ancestry(pid int) ([]transport.Proc, error) {
	var out []transport.Proc
	for len(out) < 6 && pid > 0 {
		p, e := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if e != nil || p == nil || int(p.Proc.P_pid) != pid {
			return out, errors.New("ancestry_unavailable")
		}
		name := string(p.Proc.P_comm[:])
		name = strings.TrimRight(name, "\x00")
		ms := p.Proc.P_starttime.Sec*1000 + int64(p.Proc.P_starttime.Usec)/1000
		if ms <= 0 {
			return out, errors.New("ancestry_unavailable")
		}
		out = append(out, transport.Proc{PID: pid, StartMS: ms, Argv0: processName(name)})
		next := int(p.Eproc.Ppid)
		if next == pid {
			break
		}
		pid = next
	}
	return out, nil
}
