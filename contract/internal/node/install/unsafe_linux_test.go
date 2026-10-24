package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxGoBuildStyleSourceModes(t *testing.T) {
	root := testRoot(t)
	work := filepath.Join(root, "go-build", "b001")
	if e := os.MkdirAll(work, 0700); e != nil {
		t.Fatal(e)
	}
	source, digest := imageFixture(t, work)
	if e := os.Chmod(work, 0775); e != nil {
		t.Fatal(e)
	}
	if _, e := verify(source, digest); !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), work) || !strings.Contains(e.Error(), "mode") {
		t.Fatal(e)
	}
	if e := os.Chmod(work, 0700); e != nil {
		t.Fatal(e)
	}
	v, e := verify(source, digest)
	if e != nil {
		t.Fatal(e)
	}
	v.Close()
	if e := os.Chmod(work, os.ModeSticky|0700); e != nil {
		t.Fatal(e)
	}
	if _, e := verify(source, digest); !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), "sticky") {
		t.Fatal(e)
	}
}
