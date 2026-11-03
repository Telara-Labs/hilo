//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"unsafe"
)

func markerSecurity(h windows.Handle) error {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !windows.EqualSid(owner, u.User.Sid) {
		return errors.New("runtime_authority_unavailable")
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount != 1 {
		return errors.New("runtime_authority_unavailable")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(acl, 0, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || !windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), u.User.Sid) {
		return errors.New("runtime_authority_unavailable")
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return errors.New("runtime_authority_unavailable")
	}
	return nil
}
func openMarker(path string) (*os.File, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, &os.PathError{Op: "open marker", Path: path, Err: e}
	}
	if e = markerSecurity(h); e != nil {
		windows.CloseHandle(h)
		return nil, e
	}
	return os.NewFile(uintptr(h), path), nil
}
func safeAuthorityFile(path string, _ os.FileInfo) bool {
	f, e := openMarker(path)
	if e != nil {
		return false
	}
	f.Close()
	return true
}
func readAuthorityRecord(data string) ([]byte, error) {
	if _, e := os.Lstat(filepath.Join(data, pendingAuthority)); e != nil {
		return nil, e
	}
	if ipc.ValidateDir(data, false) != nil {
		return nil, errors.New("runtime_authority_unavailable")
	}
	f, e := openMarker(filepath.Join(data, pendingAuthority))
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxAuthorityRecord+1))
	if e != nil || len(b) > maxAuthorityRecord {
		return nil, errors.New("runtime_authority_unavailable")
	}
	return b, nil
}

// Windows publication uses MoveFileEx WRITE_THROUGH after FlushFileBuffers on
// the writable file. A read-only directory cannot be flushed on Windows.
func syncAuthorityDir(string) error { return nil }
func writeAuthorityRecord(data string, b []byte) error {
	if len(b) == 0 || len(b) > maxAuthorityRecord {
		return errors.New("runtime_authority_unavailable")
	}
	if ipc.ValidateDir(data, false) != nil {
		return errors.New("runtime_authority_unavailable")
	}
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("O:" + u.User.Sid.String() + "D:P(A;;FA;;;" + u.User.Sid.String() + ")")
	if e != nil {
		return e
	}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return e
	}
	name := filepath.Join(data, ".authority-pending-"+hex.EncodeToString(id[:]))
	p, _ := windows.UTF16PtrFromString(name)
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateFile(p, windows.GENERIC_WRITE|windows.READ_CONTROL, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(h), name)
	defer os.Remove(name)
	if e = markerSecurity(h); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	dst, _ := windows.UTF16PtrFromString(filepath.Join(data, pendingAuthority))
	// Refuse an existing reparse point or loose DACL before replacing it.
	old, e := openMarker(filepath.Join(data, pendingAuthority))
	if e == nil {
		old.Close()
	} else if !os.IsNotExist(e) {
		return e
	}
	return windows.MoveFileEx(p, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
