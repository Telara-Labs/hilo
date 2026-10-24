package peer

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func openImage(pid int, _ string) (*os.File, error) {
	return os.Open(fmt.Sprintf("/proc/%d/exe", pid))
}

func executable(pid int) (string, string, error) {
	if pid <= 0 {
		return "", "", ErrAuthority
	}
	var st unix.Stat_t
	if unix.Stat(fmt.Sprintf("/proc/%d", pid), &st) != nil || st.Uid != uint32(os.Geteuid()) {
		return "", "", ErrAuthority
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", "", ErrAuthority
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", "", ErrAuthority
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return "", "", ErrAuthority
	}
	f := strings.Fields(string(b[end+1:]))
	if len(f) < 20 {
		return "", "", ErrAuthority
	}
	return path, f[19], nil
}
