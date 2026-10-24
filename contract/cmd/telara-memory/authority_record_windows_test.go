//go:build windows

package main

import (
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsPendingRoundTripAndInterruptedBootstrap(t *testing.T) {
	data := filepath.Join(t.TempDir(), "profile")
	if e := ipc.ValidateDir(data, true); e != nil {
		t.Fatal(e)
	}
	for _, phase := range []string{"provisioning", "complete", "admitted"} {
		p := pendingProfile{Version: 1, Handle: "0123456789abcdef0123456789abcdef", Phase: phase}
		if e := writePending(data, p); e != nil {
			t.Fatal(e)
		}
		got, e := readPending(data)
		if e != nil || got != p {
			t.Fatal(got, e)
		}
	}
	// An interrupted temporary write never supersedes the durably published marker.
	if e := os.WriteFile(filepath.Join(data, ".authority-pending-interrupted"), []byte("{"), 0600); e != nil {
		t.Fatal(e)
	}
	if got, e := readPending(data); e != nil || got.Phase != "admitted" {
		t.Fatal(got, e)
	}
}
func TestWindowsPendingRejectsLooseDACLAndReparse(t *testing.T) {
	data := filepath.Join(t.TempDir(), "profile")
	if e := ipc.ValidateDir(data, true); e != nil {
		t.Fatal(e)
	}
	if e := writePending(data, pendingProfile{Version: 1}); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(data, pendingAuthority)
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if e != nil {
		t.Fatal(e)
	}
	acl, _, e := sd.DACL()
	if e != nil {
		t.Fatal(e)
	}
	if e = windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); e != nil {
		t.Fatal(e)
	}
	if _, e = readPending(data); e == nil {
		t.Fatal("loose ACL accepted")
	}
	os.Remove(p)
	target := filepath.Join(data, "target")
	if e = os.WriteFile(target, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(target, p); e != nil {
		t.Skip("reparse test requires Windows symlink privilege", e)
	}
	if _, e = readPending(data); e == nil {
		t.Fatal("reparse accepted")
	}
}
