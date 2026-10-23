//go:build linux || darwin

package capture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenerRefusesSymlinksPermissionsAndSpecialFiles(t *testing.T) {
	for _, which := range []string{"final_symlink", "child_symlink", "root_symlink", "ancestor_symlink", "public_file", "public_root", "public_child", "fifo", "directory", "missing"} {
		t.Run(which, func(t *testing.T) {
			c, u := fixture(t, "claude-code", readFixture(t, "claude"))
			path := filepath.Join(c.root, u.relative)
			switch which {
			case "final_symlink":
				if err := os.Rename(path, path+".target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".target", path); err != nil {
					t.Fatal(err)
				}
			case "child_symlink":
				if err := os.Symlink(c.root, filepath.Join(c.root, "child")); err != nil {
					t.Fatal(err)
				}
				u.relative = filepath.Join("child", u.relative)
			case "root_symlink":
				alias := c.root + "-alias"
				if err := os.Symlink(c.root, alias); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(alias) })
				c.root = alias
			case "ancestor_symlink":
				parent := filepath.Dir(c.root)
				alias := c.root + "-parent"
				if err := os.Symlink(parent, alias); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(alias) })
				c.root = filepath.Join(alias, filepath.Base(c.root))
			case "public_file":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "public_root":
				if err := os.Chmod(c.root, 0755); err != nil {
					t.Fatal(err)
				}
			case "public_child":
				child := filepath.Join(c.root, "child")
				if err := os.Mkdir(child, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, filepath.Join(child, u.relative)); err != nil {
					t.Fatal(err)
				}
				u.relative = filepath.Join("child", u.relative)
			case "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			c.home = c.root
			bindIdentity(t, c, &u, syntheticSession)
			b, err := prepare(context.Background(), c, u, allow)
			if err == nil || len(b.observations) != 0 || !strings.HasPrefix(err.Error(), "capture preparation held: ") || strings.Contains(err.Error(), c.root) {
				t.Fatalf("unsafe file exposed content/error: %v", err)
			}
		})
	}
	// Ownership validation is tested separately because unprivileged tests must
	// never chown a real directory or require elevated permissions.
	st := unix.Stat_t{Uid: uint32(os.Getuid() + 1), Mode: unix.S_IFREG | 0600}
	if private(&st, false) {
		t.Fatal("foreign owner accepted")
	}
}

func TestHeldDescriptorNeverFollowsReplacementAndRejectsChanges(t *testing.T) {
	for _, change := range []string{"replace", "symlink", "truncate", "append", "same_size_rewrite", "permissions", "delete"} {
		t.Run(change, func(t *testing.T) {
			data := readFixture(t, "claude")
			c, u := fixture(t, "claude-code", data)
			path := filepath.Join(c.root, u.relative)
			h, err := openUnit(c.root, u.relative)
			if err != nil {
				t.Fatal(err)
			}
			defer h.close()
			called := 0
			err = frameUnit(context.Background(), h, func(_ int, line []byte) error {
				called++
				if called != 1 {
					return nil
				}
				switch change {
				case "replace":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte("REPLACEMENT_MUST_NOT_BE_READ\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(path+".old", path); err != nil {
						t.Fatal(err)
					}
				case "truncate":
					if err := os.Truncate(path, 0); err != nil {
						t.Fatal(err)
					}
				case "append":
					f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
					if err != nil {
						t.Fatal(err)
					}
					_, err = f.Write([]byte("{}\n"))
					_ = f.Close()
					if err != nil {
						t.Fatal(err)
					}
				case "same_size_rewrite":
					initial := h.initial.ModTime()
					rewrite := append([]byte(nil), data...)
					rewrite[0] = '['
					if err := os.WriteFile(path, rewrite, 0600); err != nil {
						t.Fatal(err)
					}
					// Restoring mtime/size must not conceal a changed file. ctime is
					// checked as well, without hashing the unredacted source bytes.
					if err := os.Chtimes(path, initial, initial); err != nil {
						t.Fatal(err)
					}
				case "permissions":
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				case "delete":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				if strings.Contains(string(line), "REPLACEMENT_MUST_NOT_BE_READ") {
					t.Fatal("held descriptor followed replacement")
				}
				return nil
			})
			if err == nil || err.Error() != "capture preparation held: source_changed" {
				t.Fatalf("changed source not held: %v", err)
			}
		})
	}
}

func TestFramerLimitsAndCancellationAreAtomicForPreparation(t *testing.T) {
	good := `{"type":"user","message":{"content":"synthetic"}}` + "\n"
	c, u := fixture(t, "claude-code", []byte(good+strings.Repeat("x", maxFrame)+"\n"))
	b, err := prepare(context.Background(), c, u, allow)
	requireHeld(t, b, err, "frame_limit")
	c, u = fixture(t, "claude-code", []byte(strings.Repeat(good, maxObservations+1)))
	b, err = prepare(context.Background(), c, u, allow)
	requireHeld(t, b, err, "observation_limit")
	c, u = fixture(t, "claude-code", nil)
	if err := os.Truncate(filepath.Join(c.root, u.relative), maxUnit+1); err != nil {
		t.Fatal(err)
	}
	b, err = prepare(context.Background(), c, u, allow)
	requireHeld(t, b, err, "unit_limit")
	if err := os.Remove(filepath.Join(c.root, u.relative)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b, err = prepare(ctx, c, u, func(context.Context, sourceOccurrence) (bool, error) { cancel(); return false, nil })
	requireHeld(t, b, err, "cancelled")
	c, u = fixture(t, "claude-code", []byte(good+good))
	h, err := openUnit(c.root, u.relative)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	ctx, cancel = context.WithCancel(context.Background())
	n := 0
	err = frameUnit(ctx, h, func(int, []byte) error { n++; cancel(); return nil })
	if err == nil || err.Error() != "capture preparation held: cancelled" || n != 1 {
		t.Fatal("cancel did not stop bounded read", err, n)
	}
}
