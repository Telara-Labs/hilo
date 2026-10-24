package install

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestUnsafeDiagnosticWrapping(t *testing.T) {
	for _, cause := range []error{nil, os.ErrPermission, os.ErrNotExist, os.ErrExist} {
		e := unsafePath("openat", "/parent/component", "symlink forbidden", cause)
		var detail *os.PathError
		if !errors.Is(e, ErrUnsafe) || !errors.As(e, &detail) || detail.Op != "openat" || detail.Path != "/parent/component" || !strings.Contains(e.Error(), "symlink forbidden") {
			t.Fatalf("missing diagnostic or sentinel: %v", e)
		}
		if cause != nil && (errors.Is(e, cause) || !strings.Contains(e.Error(), cause.Error())) {
			t.Fatalf("changed classification or lost cause text: %v", e)
		}
	}
}
