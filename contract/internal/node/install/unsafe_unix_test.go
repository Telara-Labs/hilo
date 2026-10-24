//go:build darwin || linux

package install

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallMetadataDiagnostics(t *testing.T) {
	uid := uint32(os.Geteuid())
	for _, tc := range []struct {
		name, rule   string
		st           unix.Stat_t
		private, dir bool
	}{
		{"owner", "owner", unix.Stat_t{Uid: uid + 1, Mode: unix.S_IFREG | 0700, Nlink: 1}, false, false},
		{"write", "group/other writes", unix.Stat_t{Uid: uid, Mode: unix.S_IFREG | 0777, Nlink: 1}, false, false},
		{"sticky", "sticky", unix.Stat_t{Uid: uid, Mode: unix.S_IFDIR | unix.S_ISVTX | 0700}, false, true},
		{"setuid", "setuid", unix.Stat_t{Uid: uid, Mode: unix.S_IFREG | unix.S_ISUID | 0700, Nlink: 1}, false, false},
		{"private", "private", unix.Stat_t{Uid: uid, Mode: unix.S_IFREG | 0755, Nlink: 1}, true, false},
		{"directory", "directory", unix.Stat_t{Uid: uid, Mode: unix.S_IFREG | 0700, Nlink: 1}, false, true},
		{"regular", "regular", unix.Stat_t{Uid: uid, Mode: unix.S_IFIFO | 0700, Nlink: 1}, false, false},
		{"execute", "execute", unix.Stat_t{Uid: uid, Mode: unix.S_IFREG | 0600, Nlink: 1}, false, false},
		{"links", "link count", unix.Stat_t{Uid: uid, Mode: unix.S_IFREG | 0700, Nlink: 2}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := trustedStatError(&tc.st, "/parent/component", tc.private, tc.dir)
			if !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), tc.rule) || !strings.Contains(e.Error(), "/parent/component") {
				t.Fatal(e)
			}
		})
	}
}

func TestInstallUnsafeDetailedSource(t *testing.T) {
	dir := testRoot(t)
	source := filepath.Join(dir, "not-executable")
	if e := os.WriteFile(source, []byte("image"), 0600); e != nil {
		t.Fatal(e)
	}
	_, e := verify(source, strings.Repeat("0", 64))
	if !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), "executable source") || !strings.Contains(e.Error(), source) {
		t.Fatal(e)
	}
	if _, e := trustedDir("relative", false, false); !errors.Is(e, ErrUnsafe) {
		t.Fatal(e)
	}
}
