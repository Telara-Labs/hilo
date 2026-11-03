package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func currentSID() (*windows.SID, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	return u.User.Sid, nil
}
func ownerSecurity() (*windows.SECURITY_DESCRIPTOR, error) {
	sid, e := currentSID()
	if e != nil {
		return nil, e
	}
	return windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;OICI;FA;;;" + sid.String() + ")")
}
func attributes(sd *windows.SECURITY_DESCRIPTOR) *windows.SecurityAttributes {
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
}
func platformPaths(data, run string) (Paths, error) {
	sid, e := currentSID()
	if e != nil {
		return Paths{}, e
	}
	// Keep the v1 pipe locator for verified legacy installations and clients.
	// Hilo profile paths still produce distinct per-owner endpoints.
	h := shaPath(sid.String() + "\x00" + strings.ToLower(filepath.Clean(data)))
	return Paths{Data: data, Run: run, Endpoint: fmt.Sprintf(`\\.\pipe\telara-memory-%x`, h[:16])}, nil
}
func checkSecurity(h windows.Handle) error {
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return unsafePath("GetSecurityInfo", fmt.Sprintf("handle=%d", h), "owner/ACL metadata required", e)
	}
	sid, e := currentSID()
	if e != nil {
		return e
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !windows.EqualSid(owner, sid) {
		return unsafePath("checkSecurity", fmt.Sprintf("handle=%d", h), "owner must be current user", e)
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount != 1 {
		return unsafePath("checkSecurity", fmt.Sprintf("handle=%d", h), "DACL must have exactly one entry", e)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(acl, 0, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || !windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), sid) {
		return unsafePath("checkSecurity", fmt.Sprintf("handle=%d", h), "ACL must permit current user without inherit-only flag", nil)
	}
	return nil
}

// Trusted administrators and the current owner may manage ancestors. No other
// principal may receive mutation rights, even when the final directory is private.
func trustedSID(sid, current *windows.SID) bool {
	return windows.EqualSid(sid, current) || sid.String() == "S-1-5-18" || sid.String() == "S-1-5-32-544" || sid.String() == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}
func checkAncestor(h windows.Handle, volumeRoot bool) error {
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return unsafePath("GetSecurityInfo", fmt.Sprintf("handle=%d", h), "ancestor owner/ACL metadata required", e)
	}
	current, e := currentSID()
	if e != nil {
		return e
	}
	return checkAncestorSecurity(sd, current, volumeRoot)
}
func checkAncestorSecurity(sd *windows.SECURITY_DESCRIPTOR, current *windows.SID, volumeRoot bool) error {
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !trustedSID(owner, current) {
		return unsafePath("checkAncestorSecurity", "security descriptor", "owner must be trusted", e)
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return unsafePath("checkAncestorSecurity", "security descriptor", "non-null DACL required", e)
	}
	const mutation = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | 0x40 /* FILE_DELETE_CHILD */ | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.MAXIMUM_ALLOWED
	forbidden := uint32(mutation)
	if volumeRoot {
		// On a verified volume-root directory these two bits only create new
		// entries. Standard Users root ACEs grant ADD_SUBDIRECTORY. Retained
		// no-delete-sharing handles and every descendant's strict checks still
		// prevent replacement. Do not relax delete, metadata or generic writes.
		forbidden &^= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			return unsafePath("GetAce", "security descriptor", "ACL entry must be readable", nil)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if uint32(ace.Mask)&forbidden != 0 && !trustedSID((*windows.SID)(unsafe.Pointer(&ace.SidStart)), current) {
				return unsafePath("checkAncestorSecurity", "security descriptor", "ACL forbids untrusted mutation grants", nil)
			}
		default:
			return unsafePath("checkAncestorSecurity", "security descriptor", "ACL conditional/object grants unsupported", nil) // unsupported conditional/object grants fail closed
		}
	}
	return nil
}
func closeDirs(hs []windows.Handle) {
	for i := len(hs) - 1; i >= 0; i-- {
		windows.CloseHandle(hs[i])
	}
}
func relativeOpen(parent windows.Handle, name string, directory, create bool, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	u, e := windows.NewNTUnicodeString(name)
	if e != nil {
		return 0, unsafePath("NTUnicodeString", name, "valid Windows string required", e)
	}
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent, ObjectName: u, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE, SecurityDescriptor: sd}
	access := uint32(windows.READ_CONTROL | windows.SYNCHRONIZE | windows.FILE_READ_ATTRIBUTES)
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if directory {
		options |= windows.FILE_DIRECTORY_FILE
		access |= windows.FILE_LIST_DIRECTORY
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE
		access |= windows.GENERIC_READ | windows.GENERIC_WRITE
	}
	disposition := uint32(windows.FILE_OPEN)
	if create {
		disposition = windows.FILE_OPEN_IF
	}
	var h windows.Handle
	var ios windows.IO_STATUS_BLOCK
	e = windows.NtCreateFile(&h, access, &oa, &ios, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, disposition, options, 0, 0)
	if e != nil {
		return 0, unsafePath("NtCreateFile", name, "no symlink/reparse; relative open required", e)
	}
	var info windows.ByHandleFileInformation
	e = windows.GetFileInformationByHandle(h, &info)
	rule := "metadata query required"
	if e == nil {
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			rule = "symlink/reparse forbidden"
		} else if (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
			rule = "file/directory type mismatch"
		} else {
			return h, nil
		}
	}
	windows.CloseHandle(h)
	return 0, unsafePath("relativeOpen", name, rule, e)
}

// Walk relative to retained no-delete-sharing handles, including the volume root.
func openDirs(path string, create bool) (hs []windows.Handle, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, `\\`) || strings.Contains(strings.TrimPrefix(path, filepath.VolumeName(path)), ":") {
		return nil, unsafePath("openDirs", path, "absolute clean local path without alternate streams required", nil)
	}
	root := filepath.VolumeName(path) + string(filepath.Separator)
	u, e := windows.UTF16PtrFromString(root)
	if e != nil {
		return nil, unsafePath("UTF16 root", root, "valid Windows string required", e)
	}
	h, e := windows.CreateFile(u, windows.READ_CONTROL|windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, unsafePath("CreateFile root", root, "root directory open required", e)
	}
	hs = append(hs, h)
	defer func() {
		if err != nil {
			closeDirs(hs)
			hs = nil
		}
	}()
	var info windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(h, &info); e != nil {
		return hs, unsafePath("openDirs", root, "metadata query required", e)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return hs, unsafePath("openDirs", root, "symlink/reparse forbidden", nil)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return hs, unsafePath("openDirs", root, "type must be directory", nil)
	}
	if e = checkAncestor(h, true); e != nil {
		return hs, unsafePath("openDirs", root, "trusted ancestor ACL required", e)
	}
	current := root
	parts := strings.Split(strings.TrimPrefix(path, root), string(filepath.Separator))
	for i, part := range parts {
		if part == "" || strings.ContainsAny(part, `:/\`) {
			return hs, unsafePath("openDirs", part, "non-empty single component required", nil)
		}
		sd, e := ownerSecurity()
		if e != nil {
			return hs, e
		}
		current = filepath.Join(current, part)
		h, e = relativeOpen(h, part, true, create, sd)
		if e != nil {
			return hs, unsafePath("openDirs", current, "relative directory open required", e)
		}
		hs = append(hs, h)
		if i == len(parts)-1 {
			e = checkSecurity(h)
		} else {
			e = checkAncestor(h, false)
		}
		if e != nil {
			return hs, unsafePath("openDirs", current, "directory security validation required", e)
		}
	}
	return hs, nil
}
func ValidateDir(path string, create bool) error {
	hs, e := openDirs(path, create)
	closeDirs(hs)
	return e
}

// ValidatePrivateFile checks a regular owner-only, single-link file beneath
// protected ancestors. Reparse points are opened without following them and
// rejected. Retained no-delete-sharing ancestor handles protect the walk.
func ValidatePrivateFile(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, `\\`) || strings.Contains(strings.TrimPrefix(path, filepath.VolumeName(path)), ":") {
		return unsafePath("ValidatePrivateFile", path, "absolute clean local path without alternate streams required", nil)
	}
	hs, e := openDirs(filepath.Dir(path), false)
	if e != nil {
		return e
	}
	defer closeDirs(hs)
	u, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	h, e := windows.CreateFile(u, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return unsafePath("ValidatePrivateFile", path, "metadata handle required", e)
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(h, &info); e != nil {
		return unsafePath("ValidatePrivateFile", path, "metadata query required", e)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 {
		return unsafePath("ValidatePrivateFile", path, "regular non-reparse single-link private file required", nil)
	}
	return checkSecurity(h)
}

type lockedFile struct {
	*os.File
	dirs []windows.Handle
	once sync.Once
	err  error
}

func (f *lockedFile) Close() error {
	f.once.Do(func() { f.err = f.File.Close(); closeDirs(f.dirs) })
	return f.err
}
func Lock(path string) (*lockedFile, error) {
	hs, e := openDirs(filepath.Dir(path), false)
	if e != nil {
		return nil, e
	}
	sd, e := ownerSecurity()
	if e != nil {
		closeDirs(hs)
		return nil, e
	}
	h, e := relativeOpen(hs[len(hs)-1], filepath.Base(path), false, true, sd)
	if e != nil {
		closeDirs(hs)
		return nil, e
	}
	var info windows.ByHandleFileInformation
	e = windows.GetFileInformationByHandle(h, &info)
	if e == nil && info.NumberOfLinks != 1 {
		e = unsafePath("Lock", path, "link count must be one", nil)
	}
	if e == nil {
		e = checkSecurity(h)
	}
	if e != nil {
		windows.CloseHandle(h)
		closeDirs(hs)
		return nil, unsafePath("Lock", path, "file metadata/private ACL required", e)
	}
	if e = windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); e != nil {
		windows.CloseHandle(h)
		closeDirs(hs)
		if e == windows.ERROR_LOCK_VIOLATION {
			return nil, ErrBusy
		}
		return nil, e
	}
	return &lockedFile{File: os.NewFile(uintptr(h), path), dirs: hs}, nil
}

type pipeAddr string

func (p pipeAddr) Network() string { return "pipe" }
func (p pipeAddr) String() string  { return string(p) }

type pipeConn struct {
	*os.File
	server bool
	name   string
}

func (c *pipeConn) LocalAddr() net.Addr  { return pipeAddr(c.name) }
func (c *pipeConn) RemoteAddr() net.Addr { return pipeAddr(c.name) }
func Peer(c net.Conn) (int, error) {
	p, ok := c.(*pipeConn)
	if !ok {
		return 0, ErrPeer
	}
	var pid uint32
	raw, e := p.SyscallConn()
	if e != nil {
		return 0, ErrPeer
	}
	var queryErr error
	e = raw.Control(func(fd uintptr) {
		if p.server {
			queryErr = windows.GetNamedPipeClientProcessId(windows.Handle(fd), &pid)
		} else {
			queryErr = windows.GetNamedPipeServerProcessId(windows.Handle(fd), &pid)
		}
	})
	if queryErr != nil {
		return 0, ErrPeer
	}
	if e != nil || pid == 0 {
		return 0, ErrPeer
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return 0, ErrPeer
	}
	defer windows.CloseHandle(h)
	var token windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) != nil {
		return 0, ErrPeer
	}
	defer token.Close()
	u, e := token.GetTokenUser()
	sid, se := currentSID()
	if e != nil || se != nil || !windows.EqualSid(u.User.Sid, sid) {
		return 0, ErrPeer
	}
	return int(pid), nil
}
func Dial(ctx context.Context, p Paths) (net.Conn, error) {
	if e := p.ValidateRuntime(); e != nil {
		return nil, e
	}
	u, e := windows.UTF16PtrFromString(p.Endpoint)
	if e != nil {
		return nil, e
	}
	for {
		h, e := windows.CreateFile(u, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if e == nil {
			c := &pipeConn{os.NewFile(uintptr(h), p.Endpoint), false, p.Endpoint}
			if _, e = Peer(c); e != nil {
				c.Close()
				return nil, e
			}
			return c, nil
		}
		if e != windows.ERROR_PIPE_BUSY && e != windows.ERROR_FILE_NOT_FOUND {
			return nil, e
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

type pipeListener struct {
	mu      sync.Mutex
	pending windows.Handle
	name    string
	closed  bool
}

func createPipe(name string, first bool) (windows.Handle, error) {
	sd, e := ownerSecurity()
	if e != nil {
		return 0, e
	}
	u, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return 0, e
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	return windows.CreateNamedPipe(u, flags, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 255, 65536, 65536, 0, attributes(sd))
}
func Listen(p Paths) (net.Listener, error) {
	h, e := createPipe(p.Endpoint, true)
	if e != nil {
		return nil, e
	}
	return &pipeListener{pending: h, name: p.Endpoint}, nil
}
func (l *pipeListener) Accept() (net.Conn, error) {
	for {
		c, e := l.acceptOne()
		if e == windows.ERROR_NO_DATA || e == windows.ERROR_BROKEN_PIPE || e == windows.ERROR_PIPE_NOT_CONNECTED {
			continue
		}
		return c, e
	}
}
func (l *pipeListener) acceptOne() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	h := l.pending
	l.mu.Unlock()
	event, e := windows.CreateEvent(nil, 1, 0, nil)
	if e != nil {
		return nil, e
	}
	defer windows.CloseHandle(event)
	ov := windows.Overlapped{HEvent: event}
	e = windows.ConnectNamedPipe(h, &ov)
	if e == windows.ERROR_IO_PENDING {
		var done uint32
		e = windows.GetOverlappedResult(h, &ov, &done, true)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, net.ErrClosed
	}
	disconnected := e == windows.ERROR_NO_DATA || e == windows.ERROR_BROKEN_PIPE || e == windows.ERROR_PIPE_NOT_CONNECTED
	if e != nil && e != windows.ERROR_PIPE_CONNECTED && !disconnected {
		return nil, e
	}
	next, ne := createPipe(l.name, false)
	if ne != nil {
		return nil, ne
	}
	l.pending = next
	if disconnected {
		windows.CloseHandle(h)
		return nil, e
	}
	return &pipeConn{os.NewFile(uintptr(h), l.name), true, l.name}, nil
}
func (l *pipeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	windows.CancelIoEx(l.pending, nil)
	return windows.CloseHandle(l.pending)
}
func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.name) }
func RecordOwner(p Paths) error        { return nil }
func Cleanup(p Paths)                  {}
