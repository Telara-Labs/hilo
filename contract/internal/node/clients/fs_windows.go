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
		return nil, ErrUnsafe
	}
	if private && create {
		if ipc.ValidateDir(p, true) != nil {
			return nil, ErrUnsafe
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
				return nil, ErrUnsafe
			}
			curr = filepath.Join(curr, part)
		}
		ptr, e := windows.UTF16PtrFromString(curr)
		if e != nil {
			return nil, ErrUnsafe
		}
		if create && i > 0 {
			sd, e := userSD()
			if e != nil {
				return nil, e
			}
			sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
			e = windows.CreateDirectory(ptr, sa)
			if e != nil && !errors.Is(e, windows.ERROR_ALREADY_EXISTS) {
				return nil, ErrUnsafe
			}
		}
		h, e := windows.CreateFile(ptr, windows.FILE_LIST_DIRECTORY|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if e != nil {
			if errors.Is(e, windows.ERROR_PATH_NOT_FOUND) || errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
				return nil, os.ErrNotExist
			}
			return nil, ErrUnsafe
		}
		d.handles = append(d.handles, h)
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return nil, ErrUnsafe
		}
	}
	if private {
		if ipc.ValidateDir(p, false) != nil {
			return nil, ErrUnsafe
		}
	}
	ok = true
	return d, nil
}
func (d *directory) file(n string, create, write bool) (*os.File, error) {
	if !validName(n) {
		return nil, ErrUnsafe
	}
	p, e := windows.UTF16PtrFromString(filepath.Join(d.path, n))
	if e != nil {
		return nil, ErrUnsafe
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
		return nil, ErrUnsafe
	}
	f := os.NewFile(uintptr(h), n)
	var info windows.ByHandleFileInformation
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		f.Close()
		return nil, ErrUnsafe
	}
	owner, _, e := sd.Owner()
	u, ue := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil || ue != nil || owner == nil || !windows.EqualSid(owner, u.User.Sid) || windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		f.Close()
		return nil, ErrUnsafe
	}
	if d.private && !privateACL(sd, u.User.Sid) {
		f.Close()
		return nil, ErrUnsafe
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
		return nil, ErrUnsafe
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
		return ErrUnsafe
	}
	return os.Remove(filepath.Join(d.path, n))
}
func (d *directory) sync() error                          { return nil } // publication is best effort, not crash-durable admission
func move(from *directory, n string, to *directory) error { return renameWindows(from, n, to, n) }
func renameOwned(d *directory, from, to string) error     { return renameWindows(d, from, d, to) }
func renameWindows(from *directory, a string, to *directory, b string) error {
	if !validName(a) || !validName(b) {
		return ErrUnsafe
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
