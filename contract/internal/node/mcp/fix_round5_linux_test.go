package mcp_test

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func ancestorStart5(t *testing.T, pid int) int64 {
	t.Helper()
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal("read shim ancestor start time", err)
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		t.Fatal("invalid shim ancestor stat")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		t.Fatal("missing shim ancestor start time")
	}
	ticks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil || ticks <= 0 {
		t.Fatal("invalid shim ancestor start time", err)
	}
	// Linux /proc stat uses USER_HZ=100. Boot-relative milliseconds suffice for
	// matching this live process incarnation in the injected hook source.
	return ticks * 10
}
