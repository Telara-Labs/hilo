package peer

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func openImage(_ int, path string) (*os.File, error) { return os.Open(path) }

func executable(pid int) (string, string, error) {
	if pid <= 0 {
		return "", "", ErrAuthority
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", "", ErrAuthority
	}
	defer windows.CloseHandle(h)
	var token windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) != nil {
		return "", "", ErrAuthority
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil {
		return "", "", ErrAuthority
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !windows.EqualSid(u.User.Sid, self.User.Sid) {
		return "", "", ErrAuthority
	}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil || exited.HighDateTime != 0 || exited.LowDateTime != 0 {
		return "", "", ErrAuthority
	}
	b := make([]uint16, 32768)
	n := uint32(len(b))
	if windows.QueryFullProcessImageName(h, 0, &b[0], &n) != nil {
		return "", "", ErrAuthority
	}
	return windows.UTF16ToString(b[:n]), fmt.Sprintf("%d.%d", created.HighDateTime, created.LowDateTime), nil
}
