package main

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/clients"
	"github.com/Telara-Labs/hilo/contract/internal/node/install"
)

func captureHomeRecord(t *testing.T) install.Record {
	t.Helper()
	root := t.TempDir()
	digest := strings.Repeat("a", 64)
	name := "hilo"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dir := filepath.Join(root, "install")
	return install.Record{Schema: 1, Platform: runtime.GOOS, Home: filepath.Join(root, "profile-home"), Dir: dir, DataDir: filepath.Join(root, "data"), RunDir: filepath.Join(root, "run"), SHA256: digest, Executable: filepath.Join(dir, "bin", digest, name)}
}

func TestManagedCaptureHomePreservesNormalConfiguredVendorRoot(t *testing.T) {
	r := captureHomeRecord(t)
	configured := filepath.Join(t.TempDir(), "configured-codex")
	// These are existing vendor/home variables, restored by the owning test.
	t.Setenv("HOME", r.Home)
	t.Setenv("USERPROFILE", r.Home)
	t.Setenv("CODEX_HOME", configured)
	p, err := managedCaptureProvider(r, func() (string, error) { return r.Home, nil })
	if err != nil || p.CaptureHome != "" {
		t.Fatal("normal home must retain default configured-root discovery")
	}
	rules, err := clients.HookRules(clients.Options{Client: clients.Codex, Home: p.CaptureHome})
	if err != nil || rules.TranscriptRoot != filepath.Join(configured, "sessions") {
		t.Fatal("normal-home configured vendor root changed")
	}
}

func TestManagedCaptureHomePinsDifferentVerifiedHome(t *testing.T) {
	r := captureHomeRecord(t)
	foreign := t.TempDir()
	t.Setenv("HOME", foreign)
	t.Setenv("USERPROFILE", foreign)
	t.Setenv("CODEX_HOME", filepath.Join(foreign, "unrelated-codex"))
	for _, test := range []struct {
		name string
		home string
		err  error
	}{
		{"different-manager-home", foreign, nil},
		{"missing-manager-home", "", nil},
		{"manager-home-error", foreign, errors.New("unavailable")},
		{"same-home-with-error", r.Home, errors.New("unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, err := managedCaptureProvider(r, func() (string, error) { return test.home, test.err })
			if err != nil || p.CaptureHome != r.Home {
				t.Fatal("verified managed home was not pinned")
			}
			rules, err := clients.HookRules(clients.Options{Client: clients.Codex, Home: p.CaptureHome})
			if err != nil || rules.TranscriptRoot != filepath.Join(r.Home, ".codex", "sessions") {
				t.Fatal("manager home or configured root escaped verified managed home")
			}
		})
	}
}

func TestManagedCaptureHomeRejectsInvalidRecord(t *testing.T) {
	for _, mode := range []string{"schema", "platform", "empty-home", "relative-home", "unclean-home", "control-home", "data", "run", "image"} {
		t.Run(mode, func(t *testing.T) {
			r := captureHomeRecord(t)
			switch mode {
			case "schema":
				r.Schema = 0
			case "platform":
				r.Platform = "unverified"
			case "empty-home":
				r.Home = ""
			case "relative-home":
				r.Home = "relative"
			case "unclean-home":
				r.Home += string(filepath.Separator) + ".."
			case "control-home":
				r.Home += "\n"
			case "data":
				r.DataDir = "relative"
			case "run":
				r.RunDir = ""
			case "image":
				r.Executable = filepath.Join(r.Dir, "unverified")
			}
			called := false
			_, err := managedCaptureProvider(r, func() (string, error) { called = true; return r.Home, nil })
			if !errors.Is(err, install.ErrUnverified) || called {
				t.Fatal("invalid record reached capture-home selection")
			}
		})
	}
}
