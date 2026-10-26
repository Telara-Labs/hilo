package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"golang.org/x/sys/windows"
)

func userID() string {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return ""
	}
	return u.User.Sid.String()
}
func managerTool(platform string) string {
	if platform != "windows" {
		return ""
	}
	// GetSystemDirectory, never a mutable PATH or caller-supplied SystemRoot.
	d, e := windows.GetSystemDirectory()
	if e != nil {
		return ""
	}
	return filepath.Join(d, "schtasks.exe")
}
func loginSession(ctx context.Context) (string, error) {
	var b [256]byte
	var n uint32
	if windows.GetTokenInformation(windows.GetCurrentProcessToken(), windows.TokenStatistics, &b[0], uint32(len(b)), &n) != nil || n < 16 {
		return "", ErrUnavailable
	}
	// TOKEN_STATISTICS begins with TokenId followed by AuthenticationId LUID.
	id := *(*windows.LUID)(unsafe.Pointer(&b[8]))
	return fmt.Sprintf("%08x%08x", uint32(id.HighPart), id.LowPart), nil
}
func trustedSID(s *windows.SID) bool {
	if s == nil {
		return false
	}
	id := s.String()
	return id == userID() || id == "S-1-5-18" || id == "S-1-5-32-544" || id == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}
func security(h windows.Handle, private, root bool) error {
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return unsafePath("GetSecurityInfo", fmt.Sprintf("handle=%d", h), "owner/ACL metadata required", e)
	}
	owner, _, e := sd.Owner()
	if e != nil || !trustedSID(owner) || (private && owner.String() != userID()) {
		return unsafePath("security", fmt.Sprintf("handle=%d", h), "trusted owner required; private owner must be current user", e)
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return unsafePath("security", fmt.Sprintf("handle=%d", h), "non-null DACL required", e)
	}
	const mutation = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | 0x40 | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.MAXIMUM_ALLOWED
	mask := uint32(mutation)
	if root {
		mask &^= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &a) != nil {
			return unsafePath("GetAce", fmt.Sprintf("handle=%d", h), "ACL entry must be readable", nil)
		}
		if a.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if a.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if a.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return unsafePath("security", fmt.Sprintf("handle=%d", h), "ACL entry type unsupported", nil)
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		if private {
			if sid.String() != userID() && a.Mask != 0 {
				return unsafePath("security", fmt.Sprintf("handle=%d", h), "private ACL forbids other-user grants", nil)
			}
		} else if uint32(a.Mask)&mask != 0 && !trustedSID(sid) {
			return unsafePath("security", fmt.Sprintf("handle=%d", h), "ACL forbids untrusted mutation grants", nil)
		}
	}
	return nil
}
func closeHandles(hs []windows.Handle) {
	for i := len(hs) - 1; i >= 0; i-- {
		windows.CloseHandle(hs[i])
	}
}
func openHandle(path string, directory, private, root bool) (windows.Handle, error) {
	u, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return 0, unsafePath("UTF16 path", path, "valid Windows string required", e)
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	access := uint32(windows.READ_CONTROL | windows.GENERIC_READ)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
		access = windows.READ_CONTROL | windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES
	}
	// Directory handles pin ancestry against deletion/replacement while allowing
	// file creation and rename beneath them. Executable handles additionally
	// refuse write sharing, so their verified bytes cannot change at launch.
	share := uint32(windows.FILE_SHARE_READ)
	if directory {
		share |= windows.FILE_SHARE_WRITE
	}
	h, e := windows.CreateFile(u, access, share, nil, windows.OPEN_EXISTING, flags, 0)
	if e != nil {
		return 0, e
	}
	var info windows.ByHandleFileInformation
	e = windows.GetFileInformationByHandle(h, &info)
	if e == nil {
		switch {
		case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
			e = unsafePath("openHandle", path, "symlink/reparse forbidden", nil)
		case (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory:
			e = unsafePath("openHandle", path, "file/directory type mismatch", nil)
		case !directory && info.NumberOfLinks != 1:
			e = unsafePath("openHandle", path, "link count must be one", nil)
		default:
			e = security(h, private, root)
		}
	}
	if e != nil {
		windows.CloseHandle(h)
		return 0, unsafePath("openHandle", path, "metadata and security validation required", e)
	}
	return h, nil
}
func dirHandles(path string, private bool) ([]windows.Handle, error) {
	if !absolute(path) || strings.HasPrefix(path, `\\`) || strings.Contains(strings.TrimPrefix(path, filepath.VolumeName(path)), ":") {
		return nil, unsafePath("dirHandles", path, "absolute clean local path without alternate streams required", nil)
	}
	root := filepath.VolumeName(path) + string(filepath.Separator)
	if path == root {
		return nil, unsafePath("dirHandles", path, "non-root directory required", nil)
	}
	h, e := openHandle(root, true, false, true)
	if e != nil {
		return nil, e
	}
	hs := []windows.Handle{h}
	current := root
	parts := strings.Split(strings.TrimPrefix(path, root), string(filepath.Separator))
	for i, p := range parts {
		current = filepath.Join(current, p)
		h, e = openHandle(current, true, private && i == len(parts)-1, false)
		if e != nil {
			closeHandles(hs)
			return nil, e
		}
		hs = append(hs, h)
	}
	return hs, nil
}
func checkDir(path string, private bool) error {
	hs, e := dirHandles(path, private)
	if e != nil {
		return e
	}
	closeHandles(hs)
	return nil
}
func ensureDir(path string, private bool) error {
	if e := checkDir(path, private); e == nil {
		return nil
	}
	if !absolute(path) {
		return unsafePath("ensureDir", path, "absolute clean path required", nil)
	}
	parent := filepath.Dir(path)
	if parent == path {
		return unsafePath("ensureDir", path, "non-root directory required", nil)
	}
	if e := ensureDir(parent, false); e != nil {
		return e
	}
	// ipc creates missing directories with explicit owner-only protected DACLs.
	if e := ipc.ValidateDir(path, true); e != nil {
		return e
	}
	return checkDir(path, private)
}
func openTrusted(path string, private bool) (*os.File, func(), error) {
	if !absolute(path) {
		return nil, nil, unsafePath("openTrusted", path, "absolute clean path required", nil)
	}
	hs, e := dirHandles(filepath.Dir(path), false)
	if e != nil {
		return nil, nil, e
	}
	h, e := openHandle(path, false, private, false)
	if e != nil {
		closeHandles(hs)
		return nil, nil, e
	}
	return os.NewFile(uintptr(h), path), func() { closeHandles(hs) }, nil
}
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	hs, e := dirHandles(filepath.Dir(path), false)
	if e != nil {
		return e
	}
	defer closeHandles(hs)
	name, e := randomName()
	if e != nil {
		return e
	}
	temp := filepath.Join(filepath.Dir(path), name)
	u, e := windows.UTF16PtrFromString(temp)
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("O:" + userID() + "D:P(A;;FA;;;" + userID() + ")")
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateFile(u, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(h), temp)
	defer os.Remove(temp)
	defer f.Close()
	if e := security(h, true, false); e != nil {
		return unsafePath("writeAtomic", temp, "private owner/ACL required", e)
	}
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(temp, path)
}
func removeOwned(path string) error {
	f, release, e := openTrusted(path, true)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	f.Close()
	defer release()
	return os.Remove(path)
}
