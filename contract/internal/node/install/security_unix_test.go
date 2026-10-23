//go:build darwin || linux

package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMutableAncestorSymlinkAndModes(t *testing.T) {
	for _, kind := range []string{"ancestor", "sticky", "symlink-file", "symlink-dir", "hardlink", "loose-receipt", "fifo", "symlink-receipt"} {
		t.Run(kind, func(t *testing.T) {
			r, src := receiptFixture(t)
			switch kind {
			case "ancestor":
				os.Chmod(filepath.Dir(r.Executable), 0777)
			case "sticky":
				os.Chmod(filepath.Dir(r.Executable), os.ModeSticky|0777)
			case "symlink-file":
				os.Remove(r.Executable)
				os.Symlink(src, r.Executable)
			case "symlink-dir":
				old := filepath.Dir(r.Executable)
				os.Rename(old, old+"-real")
				os.Symlink(old+"-real", old)
			case "hardlink":
				os.Link(r.Executable, filepath.Join(r.Dir, "link"))
			case "loose-receipt":
				os.Chmod(filepath.Join(r.Dir, "install.json"), 0644)
			case "fifo":
				os.Remove(r.Executable)
				if e := unix.Mkfifo(r.Executable, 0700); e != nil {
					t.Fatal(e)
				}
			case "symlink-receipt":
				p := filepath.Join(r.Dir, "install.json")
				os.Rename(p, p+"-real")
				os.Symlink(p+"-real", p)
			}
			if v, e := VerifiedExecutable(r.Dir); e == nil {
				v.Close()
				t.Fatal("accepted unsafe install")
			}
		})
	}
}
func TestWrongOwnerPredicate(t *testing.T) {
	st := unix.Stat_t{Uid: uint32(os.Geteuid() + 1), Mode: unix.S_IFREG | 0700, Nlink: 1}
	if trustedStat(&st, false, false) {
		t.Fatal("foreign owner accepted")
	}
	st.Uid = 0
	if !trustedStat(&st, false, false) {
		t.Fatal("trusted root rejected")
	}
	if trustedStat(&st, true, false) && os.Geteuid() != 0 {
		t.Fatal("private root-owned file accepted")
	}
}
func TestPinnedExecutableReplacement(t *testing.T) {
	r, src := receiptFixture(t)
	v, e := VerifiedExecutable(r.Dir)
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	b, e := os.ReadFile(src)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeAtomic(r.Executable, b, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = v.Start(context.Background()); !errors.Is(e, ErrUnverified) {
		t.Fatalf("replaced inode accepted: %v", e)
	}
}
func TestReadNoSymlinkDirectory(t *testing.T) {
	r, _ := receiptFixture(t)
	alias := r.Dir + "-alias"
	if e := os.Symlink(r.Dir, alias); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(alias)
	if _, e := readReceipt(alias); e == nil {
		t.Fatal("symlink ancestor accepted")
	}
}
