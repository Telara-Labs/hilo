//go:build darwin || linux

package install

import (
	"context"
	"os"
	"runtime"
	"strconv"
)

func userID() string { return strconv.Itoa(os.Geteuid()) }
func managerTool(platform string) string {
	if platform == "darwin" {
		return "/bin/launchctl"
	}
	if platform == "linux-bus" {
		for _, p := range []string{"/usr/bin/busctl", "/bin/busctl"} {
			if st, e := os.Stat(p); e == nil && !st.IsDir() {
				return p
			}
		}
	}
	if platform == "linux" {
		for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
			if st, e := os.Stat(p); e == nil && !st.IsDir() {
				return p
			}
		}
	}
	return ""
}
func loginSession(ctx context.Context) (string, error) { return unixSession(ctx, runtime.GOOS) }
