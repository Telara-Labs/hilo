package ipc

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type Paths struct {
	Data, Run, Endpoint string
	requestedRun        string
}

func Resolve(data, run string) (Paths, error) {
	if data == "" {
		base, e := os.UserConfigDir()
		if e != nil {
			return Paths{}, e
		}
		data, e = privateDefault(base, "hilo", "telara-memory")
		if e != nil {
			return Paths{}, e
		}
	}
	data, e := filepath.Abs(data)
	if e != nil {
		return Paths{}, e
	}
	if run == "" {
		base, e := os.UserCacheDir()
		if e != nil {
			return Paths{}, e
		}
		if runtime.GOOS == "linux" && os.Getenv("XDG_RUNTIME_DIR") != "" {
			base = os.Getenv("XDG_RUNTIME_DIR")
			if e = ValidateDir(base, false); e != nil {
				return Paths{}, e
			}
		}
		sum := sha256.Sum256([]byte(data))
		// Immutable v1 IPC locator. Keep it for every explicit/custom profile,
		// including existing directories named hilo with an active old writer.
		// The Hilo data path already gives fresh default profiles a distinct hash.
		run = filepath.Join(base, fmt.Sprintf("telara-memory-%x", sum[:8]))
	}
	run, e = filepath.Abs(run)
	if e != nil {
		return Paths{}, e
	}
	p, e := platformPaths(data, run)
	p.requestedRun = run
	return p, e
}

// privateDefault discovers existing profiles without moving data or creating
// a second writer. Both names are checked with the native owner/ACL validator.
// Ambiguous installations require an explicit --data-dir or --run-dir.
func privateDefault(base, current, legacy string) (string, error) {
	chosen := ""
	for _, name := range []string{current, legacy} {
		p := filepath.Join(base, name)
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return "", err
		}
		if err := ValidateDir(p, false); err != nil {
			return "", err
		}
		if chosen != "" {
			return "", fmt.Errorf("ambiguous_memory_profile")
		}
		chosen = p
	}
	if chosen != "" {
		return chosen, nil
	}
	return filepath.Join(base, current), nil
}

func (p Paths) Prepare() error {
	if p.requestedRun != "" && p.requestedRun != p.Run {
		if e := ValidateDir(p.requestedRun, true); e != nil {
			return e
		}
		if e := ValidateDir(filepath.Dir(p.Run), true); e != nil {
			return e
		}
	}
	if e := ValidateDir(p.Data, true); e != nil {
		return e
	}
	return ValidateDir(p.Run, true)
}

// ValidateRuntime also checks the requested long path before using its fallback.
func (p Paths) ValidateRuntime() error {
	if p.requestedRun != "" && p.requestedRun != p.Run {
		if e := ValidateDir(p.requestedRun, false); e != nil {
			return e
		}
		if e := ValidateDir(filepath.Dir(p.Run), false); e != nil {
			return e
		}
	}
	return ValidateDir(p.Run, false)
}
