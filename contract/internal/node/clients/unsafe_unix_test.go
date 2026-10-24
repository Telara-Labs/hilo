//go:build darwin || linux

package clients

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientMetadataDiagnostics(t *testing.T) {
	uid := uint32(os.Geteuid())
	for _, tc := range []struct {
		name, rule   string
		st           unix.Stat_t
		dir, private bool
	}{
		{"owner", "owner", unix.Stat_t{Uid: uid + 1, Mode: unix.S_IFREG | 0600, Nlink: 1}, false, false},
		{"directory-write", "mode", unix.Stat_t{Uid: uid, Mode: unix.S_IFDIR | 0777}, true, false},
		{"directory-private", "0700", unix.Stat_t{Uid: uid, Mode: unix.S_IFDIR | 0755}, true, true},
		{"type", "regular", unix.Stat_t{Uid: uid, Mode: unix.S_IFIFO | 0600, Nlink: 1}, false, false},
		{"links", "link count", unix.Stat_t{Uid: uid, Mode: unix.S_IFREG | 0600, Nlink: 2}, false, false},
		{"file-write", "mode", unix.Stat_t{Uid: uid, Mode: unix.S_IFREG | 0666, Nlink: 1}, false, false},
		{"file-private", "0600", unix.Stat_t{Uid: uid, Mode: unix.S_IFREG | 0644, Nlink: 1}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := clientStat(&tc.st, "/parent/component", tc.dir, tc.private)
			if !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), tc.rule) || !strings.Contains(e.Error(), "/parent/component") {
				t.Fatal(e)
			}
		})
	}
	for _, tc := range []struct {
		st           unix.Stat_t
		dir, private bool
	}{
		{unix.Stat_t{Uid: uid, Mode: unix.S_IFDIR | 0700, Nlink: 1}, true, true},
		{unix.Stat_t{Uid: uid, Mode: unix.S_IFDIR | unix.S_ISVTX | 0777, Nlink: 1}, true, false},
		{unix.Stat_t{Uid: uid, Mode: unix.S_IFREG | 0600, Nlink: 1}, false, true},
	} {
		if e := clientStat(&tc.st, "ok", tc.dir, tc.private); e != nil {
			t.Fatal(e)
		}
	}
}

func TestClientUnsafeComponentAndRules(t *testing.T) {
	root := t.TempDir()
	d, e := openDir(root, false, false)
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	if e = os.Symlink("missing", filepath.Join(root, "link")); e != nil {
		t.Fatal(e)
	}
	if _, e = d.file("link", unix.O_RDONLY); !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), filepath.Join(root, "link")) || !strings.Contains(e.Error(), "symlink") {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "large"), []byte("xx"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = d.read("large", 1); !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), "size limit") {
		t.Fatal(e)
	}
	for _, name := range []string{"../escape", "bad/name"} {
		if _, e = d.file(name, unix.O_RDONLY); !errors.Is(e, ErrUnsafe) {
			t.Fatal(e)
		}
		if e = d.remove(name); !errors.Is(e, ErrUnsafe) {
			t.Fatal(e)
		}
	}
	if _, e = openDir("relative", false, false); !errors.Is(e, ErrUnsafe) {
		t.Fatal(e)
	}
	if _, e = openDir(filepath.Join(root, "link"), false, false); !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), "link") {
		t.Fatal(e)
	}
	if e = os.Chmod(root, 0755); e != nil {
		t.Fatal(e)
	}
	if _, e = openDir(root, false, true); !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), "0700") {
		t.Fatal(e)
	}
}

func TestClientReceiptDiagnosticRules(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	d, e := openDir(root, false, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	for _, b := range []string{`[]`, `{"version":2,"digest":"x"}`, `{"version":1,"digest":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}`} {
		if e = os.WriteFile(filepath.Join(root, receiptName), []byte(b), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = readReceipt(d); !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), receiptName) {
			t.Fatal(e)
		}
	}
}
