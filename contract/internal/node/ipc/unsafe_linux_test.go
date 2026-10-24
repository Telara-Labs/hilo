package ipc

import (
	"errors"
	"golang.org/x/sys/unix"
	"strings"
	"testing"
)

func TestLinuxACLQueryDiagnostic(t *testing.T) {
	e := checkACL(-1, true)
	if !errors.Is(e, ErrUnsafe) || !strings.Contains(e.Error(), "fd=-1") || !strings.Contains(e.Error(), "system.posix_acl_access") || !strings.Contains(e.Error(), unix.EBADF.Error()) {
		t.Fatal(e)
	}
}
