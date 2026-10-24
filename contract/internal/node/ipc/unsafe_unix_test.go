//go:build darwin || linux

package ipc

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPCUnsafeComponentDiagnostics(t *testing.T) {
	root := t.TempDir()
	loose := filepath.Join(root, "loose")
	if e := os.Mkdir(loose, 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(loose, 0755); e != nil {
		t.Fatal(e)
	}
	if e := ValidateDir(loose, false); !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), loose) || !strings.Contains(e.Error(), "0700") {
		t.Fatal(e)
	}
	alias := filepath.Join(root, "alias")
	if e := os.Symlink(loose, alias); e != nil {
		t.Fatal(e)
	}
	if e := ValidateDir(alias, false); !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), alias) || !strings.Contains(e.Error(), "symlink") {
		t.Fatal(e)
	}
	if e := ValidateDir("relative", false); !errors.Is(e, ErrUnsafe) {
		t.Fatal(e)
	}
}

func TestIPCPrivateFileDiagnostics(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	if e := os.WriteFile(path, []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	var st unix.Stat_t
	if e = privateFile(int(f.Fd()), path, &st); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if e = privateFile(int(f.Fd()), path, &st); !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), "0600") {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Link(path, path+"-link"); e != nil {
		t.Fatal(e)
	}
	if e = privateFile(int(f.Fd()), path, &st); !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), "link count") {
		t.Fatal(e)
	}
	if e = privateFile(-1, path, &st); !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), unix.EBADF.Error()) {
		t.Fatal(e)
	}
}
