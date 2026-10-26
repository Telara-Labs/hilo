//go:build windows

package store

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsStorePrivateFilesInheritOwnerOnlyACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := privateDir(dir); err != nil {
		t.Fatal("private directory", err)
	}
	for _, name := range []string{"memory.sqlite", "memory.sqlite-wal", "memory.sqlite-shm", "sync.sqlite", "sync-profile.json"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("synthetic private data"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := privateFile(path); err != nil {
			t.Fatal(name, "did not inherit owner-only ACL", err)
		}
	}
}

func TestWindowsStoreRefusesForeignACLAndHardlinks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := privateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "memory.sqlite")
	if err := os.WriteFile(path, []byte("synthetic private data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(dir, "alias")); err != nil {
		t.Fatal("NTFS hardlink fixture", err)
	}
	if err := privateFile(path); err == nil {
		t.Fatal("hardlinked private database accepted")
	}
	if err := os.Remove(filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	token, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + token.User.Sid.String() + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err := privateFile(path); err == nil {
		t.Fatal("world-readable private database accepted")
	}
}

// Unix chmod does not grant another principal access on Windows. Use a real
// native DACL so cross-platform privacy assertions exercise the same threat.
func testPrivacyMode(path string, mode os.FileMode) error {
	token, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	text := "D:P(A;OICI;FA;;;" + token.User.Sid.String() + ")"
	if mode.Perm() == 0755 {
		text += "(A;OICI;FR;;;WD)"
	}
	if mode.Perm() == 0777 {
		text += "(A;OICI;FA;;;WD)"
	}
	sd, err := windows.SecurityDescriptorFromString(text)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
