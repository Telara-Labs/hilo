package ipc

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func hiloPrivateBase(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		base = filepath.Join(base, "private")
	} else if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDir(base, true); err != nil {
		t.Fatal(err)
	}
	return base
}

func TestHiloProfileDiscoveryUsesFreshNameAndRefusesAmbiguity(t *testing.T) {
	base := hiloPrivateBase(t)
	current, legacy := filepath.Join(base, "hilo"), filepath.Join(base, "telara-memory")
	got, err := privateDefault(base, "hilo", "telara-memory")
	if err != nil || got != current {
		t.Fatalf("fresh choice %q %v", got, err)
	}
	if _, err := os.Lstat(current); !os.IsNotExist(err) {
		t.Fatal("discovery created a profile", err)
	}
	if err := ValidateDir(legacy, true); err != nil {
		t.Fatal(err)
	}
	marker := []byte("owned journal sentinel, no credential material\n")
	file := filepath.Join(legacy, "pending-scrub.fixture")
	if err := os.WriteFile(file, marker, 0600); err != nil {
		t.Fatal(err)
	}
	got, err = privateDefault(base, "hilo", "telara-memory")
	if err != nil || got != legacy {
		t.Fatalf("legacy choice %q %v", got, err)
	}
	if after, err := os.ReadFile(file); err != nil || !bytes.Equal(after, marker) {
		t.Fatal("discovery changed legacy journal", err)
	}
	if err := ValidateDir(current, true); err != nil {
		t.Fatal(err)
	}
	if got, err := privateDefault(base, "hilo", "telara-memory"); err == nil || got != "" {
		t.Fatal("ambiguous profiles accepted")
	}
	if after, err := os.ReadFile(file); err != nil || !bytes.Equal(after, marker) {
		t.Fatal("ambiguous discovery mutated legacy state", err)
	}
}

func TestHiloProfileDiscoveryRejectsUnsafeLegacy(t *testing.T) {
	for _, kind := range []string{"regular-file", "loose-mode", "symlink"} {
		if runtime.GOOS == "windows" && kind != "regular-file" {
			continue
		} // Native DACL cases remain in the Windows ACL suite.
		t.Run(kind, func(t *testing.T) {
			base := hiloPrivateBase(t)
			old := filepath.Join(base, "telara-memory")
			switch kind {
			case "regular-file":
				if err := os.WriteFile(old, []byte("not a profile"), 0600); err != nil {
					t.Fatal(err)
				}
			case "loose-mode":
				if err := os.Mkdir(old, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(old, 0777); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(base, "other")
				if err := ValidateDir(target, true); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, old); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := privateDefault(base, "hilo", "telara-memory"); err == nil || got != "" {
				t.Fatal("unsafe legacy accepted")
			}
			if _, err := os.Lstat(filepath.Join(base, "hilo")); !os.IsNotExist(err) {
				t.Fatal("refusal created a parallel profile", err)
			}
		})
	}
}

func TestHiloExplicitCustomProfileKeepsActiveV1Locator(t *testing.T) {
	base := hiloPrivateBase(t)
	data := filepath.Join(base, "hilo")
	if err := ValidateDir(data, true); err != nil {
		t.Fatal(err)
	}
	marker := []byte("pending disclosure, outbox and scrub identity fixture\n")
	journal := filepath.Join(data, "custody-journal.fixture")
	if err := os.WriteFile(journal, marker, 0600); err != nil {
		t.Fatal(err)
	}
	writer, err := Lock(filepath.Join(data, "db.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	// Resolve reads existing OS locations but creates no cache/runtime directory.
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" && os.Getenv("XDG_RUNTIME_DIR") != "" {
		cache = os.Getenv("XDG_RUNTIME_DIR")
	}
	sum := sha256.Sum256([]byte(data))
	old := filepath.Join(cache, fmt.Sprintf("telara-memory-%x", sum[:8]))
	want, err := platformPaths(data, old)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(data, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Data != want.Data || got.Run != want.Run || got.Endpoint != want.Endpoint {
		t.Fatalf("v1 locator moved %q to %q", want.Run, got.Run)
	}
	if chosen, err := privateDefault(base, "hilo", "telara-memory"); err != nil || chosen != data {
		t.Fatal("existing custom hilo profile not preserved", err)
	}
	second, err := Lock(filepath.Join(data, "db.lock"))
	if second != nil {
		second.Close()
	}
	if !errors.Is(err, ErrBusy) {
		t.Fatal("discovery released or replaced active writer", err)
	}
	if after, err := os.ReadFile(journal); err != nil || !bytes.Equal(after, marker) {
		t.Fatal("discovery altered custody state", err)
	}
	parallel := filepath.Join(cache, fmt.Sprintf("hilo-%x", sum[:8]))
	if _, err := os.Lstat(parallel); !os.IsNotExist(err) {
		t.Fatal("parallel Hilo locator exists", err)
	}
}
