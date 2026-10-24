package clients

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"golang.org/x/sys/windows"
)

// Retain all ancestor handles without FILE_SHARE_DELETE. A reparse point is
// refused at every step, including the volume root, before any child is opened.
type directory struct {
	path    string
	handles []windows.Handle
	private bool
}

func (d *directory) close() {
	for i := len(d.handles) - 1; i >= 0; i-- {
		windows.CloseHandle(d.handles[i])
	}
}
func validName(n string) bool {
	return n != "" && n != "." && n != ".." && !strings.ContainsAny(n, "/\\:\x00")
}
func userSD() (*windows.SECURITY_DESCRIPTOR, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	return windows.SecurityDescriptorFromString("O:" + u.User.Sid.String() + "D:P(A;;FA;;;" + u.User.Sid.String() + ")")
}
func openDir(p string, create, private bool) (*directory, error) {
	if !absoluteOS("windows", p) || filepath.Clean(p) != p {
		return nil, unsafePath("openDir", p, "absolute clean local path required", nil)
	}
	if private && create {
		if e := ipc.ValidateDir(p, true); e != nil {
			return nil, unsafePath("openDir", p, "private directory validation required", e)
		}
	}
	d := &directory{path: p, private: private}
	ok := false
	defer func() {
		if !ok {
			d.close()
		}
	}()
	root := filepath.VolumeName(p) + `\`
	curr := root
	parts := strings.Split(strings.TrimPrefix(p, root), `\`)
	all := append([]string{""}, parts...)
	for i, part := range all {
		if i > 0 {
			if !validName(part) {
				return nil, unsafePath("openDir", part, "single component required", nil)
			}
			curr = filepath.Join(curr, part)
		}
		ptr, e := windows.UTF16PtrFromString(curr)
		if e != nil {
			return nil, unsafePath("UTF16 path", curr, "valid Windows string required", e)
		}
		if create && i > 0 {
			sd, e := userSD()
			if e != nil {
				return nil, e
			}
			sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
			e = windows.CreateDirectory(ptr, sa)
			if e != nil && !errors.Is(e, windows.ERROR_ALREADY_EXISTS) {
				return nil, unsafePath("CreateDirectory", curr, "owner-only directory creation required", e)
			}
		}
		h, e := windows.CreateFile(ptr, windows.FILE_LIST_DIRECTORY|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if e != nil {
			if errors.Is(e, windows.ERROR_PATH_NOT_FOUND) || errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
				return nil, os.ErrNotExist
			}
			return nil, unsafePath("CreateFile directory", curr, "directory open required", e)
		}
		d.handles = append(d.handles, h)
		var info windows.ByHandleFileInformation
		if e := windows.GetFileInformationByHandle(h, &info); e != nil {
			return nil, unsafePath("validate directory", curr, "metadata query required", e)
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return nil, unsafePath("validate directory", curr, "symlink/reparse forbidden", nil)
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return nil, unsafePath("validate directory", curr, "type must be directory", nil)
		}
	}
	if private {
		if e := ipc.ValidateDir(p, false); e != nil {
			return nil, unsafePath("openDir", p, "private directory validation required", e)
		}
	}
	ok = true
	return d, nil
}
func (d *directory) file(n string, create, write bool) (*os.File, error) {
	if !validName(n) {
		return nil, unsafePath("file", n, "single filename required", nil)
	}
	p, e := windows.UTF16PtrFromString(filepath.Join(d.path, n))
	if e != nil {
		return nil, unsafePath("UTF16 file", filepath.Join(d.path, n), "valid Windows string required", e)
	}
	access := uint32(windows.GENERIC_READ | windows.READ_CONTROL)
	disp := uint32(windows.OPEN_EXISTING)
	var sa *windows.SecurityAttributes
	if write {
		access |= windows.GENERIC_WRITE
	}
	if create {
		disp = windows.CREATE_NEW
		sd, e := userSD()
		if e != nil {
			return nil, e
		}
		sa = &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	}
	h, e := windows.CreateFile(p, access, windows.FILE_SHARE_READ, sa, disp, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
			return nil, os.ErrNotExist
		}
		if errors.Is(e, windows.ERROR_FILE_EXISTS) {
			return nil, os.ErrExist
		}
		if errors.Is(e, windows.ERROR_SHARING_VIOLATION) || errors.Is(e, windows.ERROR_LOCK_VIOLATION) {
			return nil, ErrBusy
		}
		return nil, unsafePath("CreateFile", filepath.Join(d.path, n), "no reparse; file open required", e)
	}
	f := os.NewFile(uintptr(h), n)
	var info windows.ByHandleFileInformation
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		f.Close()
		return nil, unsafePath("GetSecurityInfo", filepath.Join(d.path, n), "owner and ACL metadata required", e)
	}
	owner, _, e := sd.Owner()
	u, ue := windows.GetCurrentProcessToken().GetTokenUser()
	if e == nil {
		e = ue
	}
	if e != nil || owner == nil || !windows.EqualSid(owner, u.User.Sid) {
		f.Close()
		return nil, unsafePath("validate file", filepath.Join(d.path, n), "owner must be current user", e)
	}
	if e = windows.GetFileInformationByHandle(h, &info); e != nil {
		f.Close()
		return nil, unsafePath("validate file", filepath.Join(d.path, n), "metadata query required", e)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		f.Close()
		return nil, unsafePath("validate file", filepath.Join(d.path, n), "symlink/reparse forbidden", nil)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		f.Close()
		return nil, unsafePath("validate file", filepath.Join(d.path, n), "type must be regular file", nil)
	}
	if info.NumberOfLinks != 1 {
		f.Close()
		return nil, unsafePath("validate file", filepath.Join(d.path, n), "link count must be one", nil)
	}
	if d.private && !privateACL(sd, u.User.Sid) {
		f.Close()
		return nil, unsafePath("validate file", filepath.Join(d.path, n), "private ACL must grant only current user", nil)
	}
	return f, nil
}

func privateACL(sd *windows.SECURITY_DESCRIPTOR, sid *windows.SID) bool {
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount != 1 {
		return false
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	return windows.GetAce(acl, 0, &ace) == nil && ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 && windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), sid)
}
func (d *directory) read(n string, max int64) ([]byte, error) {
	f, e := d.file(n, false, false)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, unsafePath("read", filepath.Join(d.path, n), "read must succeed within size limit", e)
	}
	return b, nil
}
func (d *directory) create(n string, b []byte) error {
	f, e := d.file(n, true, true)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			d.remove(n)
		}
	}()
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	ok = true
	return nil
}
func (d *directory) lock() (func(), error) {
	f, e := d.file(".telara-memory.lock", true, true)
	if errors.Is(e, os.ErrExist) {
		f, e = d.file(".telara-memory.lock", false, true)
	}
	if e != nil {
		return nil, e
	}
	var ov windows.Overlapped
	if windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov) != nil {
		f.Close()
		return nil, ErrBusy
	}
	return func() { f.Close() }, nil
}
func (d *directory) remove(n string) error {
	if !validName(n) {
		return unsafePath("remove", n, "single filename required", nil)
	}
	return os.Remove(filepath.Join(d.path, n))
}
func (d *directory) sync() error                          { return nil } // publication is best effort, not crash-durable admission
func move(from *directory, n string, to *directory) error { return renameWindows(from, n, to, n) }
func renameOwned(d *directory, from, to string) error     { return renameWindows(d, from, d, to) }
func renameWindows(from *directory, a string, to *directory, b string) error {
	if !validName(a) || !validName(b) {
		return unsafePath("rename", a+" -> "+b, "single source and destination filenames required", nil)
	}
	src, e := windows.UTF16PtrFromString(filepath.Join(from.path, a))
	if e != nil {
		return e
	}
	dst, e := windows.UTF16PtrFromString(filepath.Join(to.path, b))
	if e != nil {
		return e
	}
	return windows.MoveFileEx(src, dst, 0) // deliberately no REPLACE_EXISTING
}
func checkSource(path string) error {
	d, e := openDir(filepath.Dir(path), false, false)
	if e != nil {
		return e
	}
	defer d.close()
	f, e := d.file(filepath.Base(path), false, false)
	if e != nil {
		return e
	}
	f.Close()
	return nil
}
