package clients

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Telara-Labs/hilo/contract/transport"
)

func ancestry(pid int) ([]transport.Proc, error) {
	stat, e := os.ReadFile("/proc/stat")
	if e != nil {
		return nil, errors.New("ancestry_unavailable")
	}
	var boot int64
	for _, line := range strings.Split(string(stat), "\n") {
		if strings.HasPrefix(line, "btime ") {
			boot, _ = strconv.ParseInt(strings.TrimPrefix(line, "btime "), 10, 64)
			break
		}
	}
	if boot <= 0 {
		return nil, errors.New("ancestry_unavailable")
	}
	var out []transport.Proc
	for len(out) < 6 && pid > 0 {
		b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if e != nil {
			return out, errors.New("ancestry_unavailable")
		}
		parent, name, start, e := parseProcStat(string(b), boot)
		if e != nil {
			return out, e
		}
		out = append(out, transport.Proc{PID: pid, StartMS: start, Argv0: processName(name)})
		if parent == pid {
			break
		}
		pid = parent
	}
	return out, nil
}

// Linux exposes /proc/PID/stat starttime in USER_HZ, which is 100 on the two
// supported Linux architectures (amd64/arm64). Never use a guessed current time.
func parseProcStat(s string, boot int64) (int, string, int64, error) {
	a, z := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if a < 0 || z <= a {
		return 0, "", 0, errors.New("ancestry_unavailable")
	}
	f := strings.Fields(s[z+1:])
	if len(f) < 20 {
		return 0, "", 0, errors.New("ancestry_unavailable")
	}
	p, e := strconv.Atoi(f[1])
	ticks, te := strconv.ParseInt(f[19], 10, 64)
	if e != nil || te != nil || p < 0 || ticks < 0 || ticks > 1<<52 {
		return 0, "", 0, errors.New("ancestry_unavailable")
	}
	return p, s[a+1 : z], boot*1000 + ticks*10, nil
}
