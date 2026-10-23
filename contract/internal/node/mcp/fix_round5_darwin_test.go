package mcp_test

import (
	"testing"

	"golang.org/x/sys/unix"
)

func ancestorStart5(t *testing.T, pid int) int64 {
	t.Helper()
	p, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || p == nil || p.Proc.P_pid != int32(pid) {
		t.Fatal("read shim ancestor start time", err)
	}
	start := p.Proc.P_starttime.Sec*1000 + int64(p.Proc.P_starttime.Usec)/1000
	if start <= 0 {
		t.Fatal("missing shim ancestor start time")
	}
	return start
}
