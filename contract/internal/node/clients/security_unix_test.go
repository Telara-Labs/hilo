//go:build darwin || linux

package clients

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSymlinkAndHardlinkConfigRefused(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory"} {
		t.Run(kind, func(t *testing.T) {
			o := options(t, Claude)
			l, _ := Locations(o)
			outside := filepath.Join(o.Home, "untouched")
			put(t, outside, []byte(`{"mcpServers":{}}`))
			switch kind {
			case "symlink":
				if e := os.Symlink(outside, l.MCP); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(outside, l.MCP); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				if e := unix.Mkfifo(l.MCP, 0600); e != nil {
					t.Fatal(e)
				}
			case "directory":
				if e := os.Mkdir(l.MCP, 0700); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := Install(context.Background(), o); !errors.Is(e, ErrUnsafe) {
				t.Fatal(e)
			}
			if string(mustRead(t, outside)) != `{"mcpServers":{}}` {
				t.Fatal("outside bytes changed")
			}
		})
	}
	o := options(t, Claude)
	outside := filepath.Join(o.Home, "outside")
	put(t, filepath.Join(outside, "settings.json"), []byte(`{}`))
	if e := os.Symlink(outside, filepath.Join(o.Home, ".claude")); e != nil {
		t.Fatal(e)
	}
	if _, e := Install(context.Background(), o); !errors.Is(e, ErrUnsafe) {
		t.Fatal(e)
	}
}

func TestUnsafeSpoolAndExtensionRefused(t *testing.T) {
	o := options(t, Claude)
	outside := filepath.Join(o.Home, "outside")
	if e := os.Mkdir(outside, 0700); e != nil {
		t.Fatal(e)
	}
	put(t, filepath.Join(outside, "untouched"), []byte("unchanged"))
	base := filepath.Join(o.StateDir, "spool", string(o.Client))
	if e := os.MkdirAll(base, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(base, "new")); e != nil {
		t.Fatal(e)
	}
	r := RunHook(context.Background(), o, bytes.NewReader(encoded(payload(o, "Stop"))))
	if r.Published {
		t.Fatal(r)
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 1 {
		t.Fatal("wrote through symlink")
	}
	p := options(t, Pi)
	l, _ := Locations(p)
	put(t, filepath.Join(p.Home, "original"), []byte("original"))
	if e := os.MkdirAll(filepath.Dir(l.Extension), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(p.Home, "original"), l.Extension); e != nil {
		t.Fatal(e)
	}
	if _, e := Install(context.Background(), p); !errors.Is(e, ErrUnsafe) {
		t.Fatal(e)
	}
	if _, e := Uninstall(context.Background(), p); e == nil {
		t.Fatal("symlink removed")
	}
	if string(mustRead(t, filepath.Join(p.Home, "original"))) != "original" {
		t.Fatal("unrelated file changed")
	}
}

func TestPinnedParentCannotRedirectPublication(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "owned")
	d, e := openDir(target, true, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	saved := filepath.Join(root, "saved")
	if e = os.Rename(target, saved); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(root, "outside")
	if e = os.Mkdir(outside, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(outside, target); e != nil {
		t.Fatal(e)
	}
	if e = publishOwned(d, "fixture", []byte("complete")); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(outside, "fixture")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("TOCTOU redirected write")
	}
	if string(mustRead(t, filepath.Join(saved, "fixture"))) != "complete" {
		t.Fatal("pinned publication lost")
	}
}

func TestNoReplacePublicationPartialRecoveryAndLocks(t *testing.T) {
	o := options(t, Pi)
	l, _ := Locations(o)
	d, e := openDir(filepath.Dir(l.Extension), true, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	if e = d.create("existing", []byte("prior bytes")); e != nil {
		t.Fatal(e)
	}
	if e = publishOwned(d, "existing", []byte("replacement")); e == nil {
		t.Fatal("replaced existing file")
	}
	if string(mustRead(t, filepath.Join(filepath.Dir(l.Extension), "existing"))) != "prior bytes" {
		t.Fatal("clobber")
	}
	unlock, e := d.lock()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Install(context.Background(), o); !errors.Is(e, ErrBusy) {
		t.Fatal(e)
	}
	unlock()
	put(t, filepath.Join(filepath.Dir(l.Extension), receiptName), []byte(`{"version":1,`))
	if _, e = Install(context.Background(), o); !errors.Is(e, ErrUnsafe) {
		t.Fatal(e)
	}
	if _, e = os.Stat(l.Extension); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("published after partial receipt")
	}
	put(t, filepath.Join(filepath.Dir(l.Extension), receiptName), []byte(`{"version":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":"bad"}`))
	if _, e = Install(context.Background(), o); !errors.Is(e, ErrUnsafe) {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(filepath.Dir(l.Extension), receiptName)); e != nil {
		t.Fatal(e)
	}
	// A killed writer's arbitrary temporary prefix is never treated as installed.
	put(t, filepath.Join(filepath.Dir(l.Extension), ".telara-memory-abandoned"), []byte("partial"))
	if _, e = Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	if _, e = Uninstall(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	if string(mustRead(t, filepath.Join(filepath.Dir(l.Extension), ".telara-memory-abandoned"))) != "partial" {
		t.Fatal("unrelated temporary file removed")
	}
}

func TestUnsafePermissionsRefused(t *testing.T) {
	o := options(t, Pi)
	l, _ := Locations(o)
	if e := os.MkdirAll(filepath.Dir(l.Extension), 0755); e != nil {
		t.Fatal(e)
	}
	if _, e := Install(context.Background(), o); !errors.Is(e, ErrUnsafe) {
		t.Fatal(e)
	}
	o = options(t, Claude)
	l, _ = Locations(o)
	put(t, l.MCP, []byte(`{}`))
	if e := os.Chmod(l.MCP, 0666); e != nil {
		t.Fatal(e)
	}
	if _, e := Install(context.Background(), o); !errors.Is(e, ErrUnsafe) {
		t.Fatal(e)
	}
}

func TestUninstallPinsAndRechecksReplacedEntry(t *testing.T) {
	o := options(t, Pi)
	l, _ := Locations(o)
	d, e := openDir(filepath.Dir(l.Extension), true, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	put(t, l.Extension, []byte("owned bytes"))
	prior := mustRead(t, l.Extension)
	// Inject an unrelated edit after the first checksum and before removal.
	put(t, l.Extension, []byte("new unrelated bytes"))
	if e = removeOwned(d, extensionName, digest(prior)); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if string(mustRead(t, l.Extension)) != "new unrelated bytes" {
		t.Fatal("uninstall removed concurrent replacement")
	}
	if e = removeOwned(d, extensionName, digest([]byte("new unrelated bytes"))); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(l.Extension); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
}

// The writer opens before uninstall, then writes only after the parked-file hash
// and all uninstall operations have completed. Retaining the inode, rather than
// another checksum, preserves even this latest possible in-place edit.
func TestPiUninstallPreservesOpenDescriptorEdits(t *testing.T) {
	o := options(t, Pi)
	l, _ := Locations(o)
	if _, e := Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(l.Extension, os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		t.Fatal(e)
	}
	removed, edited := make(chan struct{}), make(chan error, 1)
	go func() {
		<-removed
		if _, e := f.WriteAt([]byte("// concurrent editor retained\n"), 0); e != nil {
			edited <- e
			return
		}
		edited <- f.Sync()
	}()
	r, e := Uninstall(context.Background(), o)
	close(removed)
	if editErr := <-edited; editErr != nil {
		t.Fatal(editErr)
	}
	if e != nil || r.MCP != "extension_removed_or_absent" {
		t.Fatalf("%+v %v", r, e)
	}
	paths, e := filepath.Glob(filepath.Join(filepath.Dir(l.Extension), ".hilo-remove-*"))
	if e != nil || len(paths) != 1 {
		t.Fatalf("recovery paths %v %v", paths, e)
	}
	after, e := os.Stat(paths[0])
	if e != nil || !os.SameFile(before, after) {
		t.Fatalf("inode lost %v", e)
	}
	if !bytes.HasPrefix(mustRead(t, paths[0]), []byte("// concurrent editor retained\n")) {
		t.Fatal("open descriptor edit discarded")
	}
	if _, e = os.Stat(l.Extension); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("extension still active %v", e)
	}
	// Reinstall and repeat uninstall must neither execute nor prune the recovery.
	if _, e = Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	if _, e = Uninstall(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	if !bytes.HasPrefix(mustRead(t, paths[0]), []byte("// concurrent editor retained\n")) {
		t.Fatal("reinstall pruned recovery")
	}
}
