//go:build linux || darwin

package capture

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeCodexDefaultModesRequirePrivateContainment(t *testing.T) {
	for _, mode := range []string{"default", "no-private-anchor", "writable-root", "writable-child", "writable-file", "hardlink", "symlink", "replacement", "anchor-permissions"} {
		t.Run(mode, func(t *testing.T) {
			c, u := fixture(t, "codex", readFixture(t, "codex-0.161.0"))
			home := c.root
			config := filepath.Join(home, ".codex")
			root := filepath.Join(config, "sessions")
			relative := filepath.Join("2026", "10", "26", u.relative)
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, relative)), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(config, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, relative)
			if err := os.Rename(filepath.Join(home, u.relative), target); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, 0644); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "no-private-anchor":
				if err := os.Chmod(config, 0755); err != nil {
					t.Fatal(err)
				}
			case "writable-root":
				if err := os.Chmod(root, 0777); err != nil {
					t.Fatal(err)
				}
			case "writable-child":
				if err := os.Chmod(filepath.Dir(target), 0777); err != nil {
					t.Fatal(err)
				}
			case "writable-file":
				if err := os.Chmod(target, 0666); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(target, target+".link"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(target, target+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target+".real", target); err != nil {
					t.Fatal(err)
				}
			}
			h, err := openNativeUnit(home, root, relative)
			allowed := mode == "default" || mode == "replacement" || mode == "anchor-permissions"
			if !allowed {
				if err == nil {
					h.close()
					t.Fatal("unsafe native source accepted", mode)
				}
				return
			}
			if err != nil {
				t.Fatal("protected native default modes refused", err)
			}
			defer h.close()
			if mode == "replacement" {
				if err := os.Rename(target, target+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte("replacement"), 0644); err != nil {
					t.Fatal(err)
				}
				if h.bound() {
					t.Fatal("native replacement accepted")
				}
				return
			}
			if mode == "anchor-permissions" {
				if err := os.Chmod(config, 0755); err != nil {
					t.Fatal(err)
				}
				if h.bound() {
					t.Fatal("lost private containment accepted")
				}
				return
			}
			c.home, c.root, u.relative = home, root, relative
			bindIdentity(t, c, &u, syntheticSession)
			got, err := prepare(context.Background(), c, u, allow)
			if err != nil || len(got.observations) == 0 {
				t.Fatal("native rollout not decoded", err)
			}
			// The strict entrypoint still refuses these same readable native leaves.
			if strict, err := openUnit(root, relative); err == nil {
				strict.close()
				t.Fatal("generic source gained containment authority")
			}
		})
	}
	if ownedReadOnly(&unix.Stat_t{Uid: uint32(os.Getuid() + 1), Mode: unix.S_IFREG | 0644}, false) {
		t.Fatal("foreign native owner accepted")
	}
}
