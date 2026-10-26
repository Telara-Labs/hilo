package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const testMachine = "11111111-1111-4111-8111-111111111111"

func testOptions(t *testing.T) Options {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "private")
	return Options{Dir: dir, PinnedGenesisID: "11111111111111111111111111111111", LocalMachineID: testMachine}
}
func TestOpenPrivacySettingsAndIdentity(t *testing.T) {
	ctx := context.Background()
	o := testOptions(t)
	s, e := Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	other := o
	other.PinnedGenesisID = "22222222222222222222222222222222"
	if s, e = Open(ctx, other); e == nil {
		s.Close()
		t.Fatal("accepted wrong pin")
	}
	if e = testPrivacyMode(o.Dir, 0755); e != nil {
		t.Fatal(e)
	}
	if s, e = Open(ctx, o); e == nil {
		s.Close()
		t.Fatal("accepted public directory")
	}
}
func TestOpenRefusesSymlink(t *testing.T) {
	o := testOptions(t)
	target := filepath.Join(t.TempDir(), "target")
	os.Mkdir(target, 0700)
	os.Symlink(target, o.Dir)
	if s, e := Open(context.Background(), o); e == nil {
		s.Close()
		t.Fatal("symlink accepted")
	}
}
func TestOpenRefusesWritableAncestorAndHardlink(t *testing.T) {
	ctx := context.Background()
	o := testOptions(t)
	ancestor := filepath.Dir(o.Dir)
	if e := testPrivacyMode(ancestor, 0777); e != nil {
		t.Fatal(e)
	}
	if s, e := Open(ctx, o); Code(e) != "unsafe_path" {
		if s != nil {
			s.Close()
		}
		t.Fatal("writable ancestor accepted", e)
	}
	testPrivacyMode(ancestor, 0700)
	s, e := Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	if e = os.Link(filepath.Join(o.Dir, "memory.sqlite"), filepath.Join(ancestor, "linked.sqlite")); e != nil {
		t.Fatal(e)
	}
	if s, e = Open(ctx, o); Code(e) != "unsafe_path" {
		if s != nil {
			s.Close()
		}
		t.Fatal("hardlinked database accepted", e)
	}
}
func TestOpenRejectsExistingUnsafeSidecarsBeforeSQLite(t *testing.T) {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		t.Run(suffix, func(t *testing.T) {
			ctx := context.Background()
			o := testOptions(t)
			s, e := Open(ctx, o)
			if e != nil {
				t.Fatal(e)
			}
			s.Close()
			target := filepath.Join(filepath.Dir(o.Dir), "sentinel")
			if e = os.WriteFile(target, []byte("do-not-touch-sidecar-target"), 0600); e != nil {
				t.Fatal(e)
			}
			sidecar := filepath.Join(o.Dir, "memory.sqlite") + suffix
			if e = os.Symlink(target, sidecar); e != nil {
				t.Fatal(e)
			}
			if s, e = Open(ctx, o); Code(e) != "unsafe_path" {
				if s != nil {
					s.Close()
				}
				t.Fatal("unsafe sidecar accepted", e)
			}
			b, e := os.ReadFile(target)
			if e != nil || string(b) != "do-not-touch-sidecar-target" {
				t.Fatal("sqlite touched rejected sidecar target")
			}
		})
	}
}
