package clients

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Detection struct {
	State       string
	Executables []string
}

// Detection is read-only. It does not execute discovered programs and does not
// infer installation from leftover config. An agent executable is ambiguous;
// Cursor requires a resolved vendor location, not merely a matching basename.
func detect(o Options) Detection {
	d := Detection{State: "not_found"}
	names := map[Client][]string{Claude: {"claude"}, Codex: {"codex"}, Cursor: {"cursor", "cursor-agent", "agent"}, Pi: {"pi"}}[o.Client]
	seen := map[string]bool{}
	add := func(p string) {
		resolved, e := filepath.EvalSymlinks(p)
		if e != nil {
			return
		}
		fi, e := os.Stat(resolved)
		if e != nil || !fi.Mode().IsRegular() || (runtime.GOOS != "windows" && fi.Mode()&0111 == 0) {
			return
		}
		if o.Client == Cursor {
			norm := strings.ToLower(filepath.ToSlash(resolved))
			if !strings.Contains(norm, "/cursor.app/") && !strings.Contains(norm, "/cursor-agent/") && !strings.Contains(norm, "/cursor/") {
				return
			}
		}
		if !seen[p] {
			seen[p] = true
			d.Executables = append(d.Executables, p)
			d.State = "executable_found_runtime_unverified"
		}
	}
	for _, n := range names {
		if p, e := exec.LookPath(n); e == nil {
			add(p)
		}
	}
	if runtime.GOOS == "darwin" && o.Client == Cursor {
		for _, p := range []string{"/Applications/Cursor.app/Contents/Resources/app/bin/cursor", filepath.Join(o.Home, "Applications/Cursor.app/Contents/Resources/app/bin/cursor")} {
			add(p)
		}
	}
	if o.Client == Claude {
		add(filepath.Join(o.Home, ".local", "bin", "claude"))
	}
	if o.Client == Cursor {
		add(filepath.Join(o.Home, ".local", "bin", "agent"))
		add(filepath.Join(o.Home, ".local", "bin", "cursor-agent"))
	}
	return d
}

func Detect(o Options) (Detection, error) {
	o, _, e := resolve(o)
	if e != nil {
		return Detection{}, e
	}
	if o.GOOS != runtime.GOOS {
		return Detection{State: "foreign_os_unverified"}, nil
	}
	return detect(o), nil
}
