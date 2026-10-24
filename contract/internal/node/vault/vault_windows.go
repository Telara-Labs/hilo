package vault

import (
	"context"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var advapi = windows.NewLazySystemDLL("advapi32.dll")
var credRead = advapi.NewProc("CredReadW")
var credWrite = advapi.NewProc("CredWriteW")
var credDelete = advapi.NewProc("CredDeleteW")
var credFree = advapi.NewProc("CredFree")

// CREDENTIALW layout follows wincred.h; Go supplies pointer-width padding.
type credential struct {
	Flags, Type             uint32
	TargetName, Comment     *uint16
	LastWritten             windows.Filetime
	BlobSize                uint32
	Blob                    *byte
	Persist, AttributeCount uint32
	Attributes              uintptr
	TargetAlias, UserName   *uint16
}

func target(h string) *uint16 { p, _ := windows.UTF16PtrFromString(service + "/" + h); return p }

// CredWrite replaces existing credentials. Serialize every cooperating writer
// with an owner-only named kernel mutex and check existence under that mutex.
// Windows mutex ownership belongs to a native thread, not a goroutine.
func locked(ctx context.Context, h string, fn func() error) error {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ErrUnavailable
	}
	sid := u.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + sid + ")")
	if err != nil {
		return ErrUnavailable
	}
	name, _ := windows.UTF16PtrFromString("Global\\" + service + "." + sid + "." + h)
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	m, err := windows.CreateMutex(&sa, false, name)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return ErrUnavailable
	}
	defer windows.CloseHandle(m)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		s, err := windows.WaitForSingleObject(m, 20)
		if err != nil {
			return ErrUnavailable
		}
		if s == uint32(windows.WAIT_TIMEOUT) {
			continue
		}
		if s != windows.WAIT_OBJECT_0 && s != windows.WAIT_ABANDONED {
			return ErrUnavailable
		}
		defer windows.ReleaseMutex(m)
		return fn()
	}
}
func read(h string) ([]byte, error) {
	var c *credential
	r, _, e := credRead.Call(uintptr(unsafe.Pointer(target(h))), 1, 0, uintptr(unsafe.Pointer(&c)))
	if r == 0 {
		if e == windows.ERROR_NOT_FOUND {
			return nil, ErrNotFound
		}
		return nil, ErrUnavailable
	}
	if c == nil {
		return nil, ErrUnavailable
	}
	defer credFree.Call(uintptr(unsafe.Pointer(c)))
	if c.Type != 1 || c.Blob == nil || c.BlobSize == 0 || c.BlobSize > maxSecret {
		return nil, ErrUnavailable
	}
	b := unsafe.Slice(c.Blob, int(c.BlobSize))
	defer clear(b)
	return append([]byte(nil), b...), nil
}
func (v *Vault) put(ctx context.Context, h string, b []byte) error {
	return locked(ctx, h, func() error {
		old, err := read(h)
		clear(old)
		if err == nil {
			return ErrExists
		}
		if err != ErrNotFound {
			return err
		}
		c := credential{Type: 1, TargetName: target(h), BlobSize: uint32(len(b)), Blob: &b[0], Persist: 2}
		r, _, _ := credWrite.Call(uintptr(unsafe.Pointer(&c)), 0)
		runtime.KeepAlive(b)
		if r == 0 {
			return ErrUnavailable
		}
		return nil
	})
}
func (*Vault) get(_ context.Context, h string) ([]byte, error) { return read(h) }
func (*Vault) delete(ctx context.Context, h string) error {
	return locked(ctx, h, func() error {
		r, _, e := credDelete.Call(uintptr(unsafe.Pointer(target(h))), 1, 0)
		if r == 0 && e != windows.ERROR_NOT_FOUND {
			return ErrUnavailable
		}
		return nil
	})
}
