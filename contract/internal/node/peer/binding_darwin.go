//go:build darwin && cgo

package peer

/*
#cgo LDFLAGS: -lbsm -framework Security -framework CoreFoundation
#include <sys/socket.h>
#include <sys/un.h>
#include <bsm/libbsm.h>
#include <Security/Security.h>
#include <libproc.h>
#include <stdlib.h>
#include <string.h>
static int peerToken(int fd, void *out) {
 socklen_t n = sizeof(audit_token_t);
 return getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, out, &n) || n != sizeof(audit_token_t);
}
static int tokenPID(void *p) {return audit_token_to_pid(*(audit_token_t*)p);}
static int tokenUID(void *p) {return audit_token_to_euid(*(audit_token_t*)p);}
// Compare the actual running signed code with the on-disk signed image. Never
// grant a replacement pathname the identity of the old running image.
static int runningImage(void *token, const char *path, void *out, size_t *n) {
 CFDataRef data = CFDataCreate(NULL, token, sizeof(audit_token_t));
 const void *keys[]={kSecGuestAttributeAudit}; const void *values[]={data};
 CFDictionaryRef attrs=CFDictionaryCreate(NULL,keys,values,1,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 SecCodeRef guest=NULL; OSStatus s=SecCodeCopyGuestWithAttributes(NULL,attrs,kSecCSDefaultFlags,&guest);
 CFRelease(attrs);CFRelease(data);
 CFDictionaryRef info=NULL;
 if (!s) s=SecCodeCopySigningInformation(guest,kSecCSSigningInformation,&info);
 CFDataRef cd=info?CFDictionaryGetValue(info,kSecCodeInfoUnique):NULL;
 // Unsigned code has no kernel-verifiable mapped identity. Fail closed.
 if (!s && (!cd || CFDataGetLength(cd)>*n)) s=errSecCSUnsigned;
 if (!s) { *n=CFDataGetLength(cd);memcpy(out,CFDataGetBytePtr(cd),*n); }
 CFURLRef url=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8*)path,strlen(path),false);
 SecStaticCodeRef disk=NULL;CFDictionaryRef diskInfo=NULL;
 if (!s) s=SecStaticCodeCreateWithPath(url,kSecCSDefaultFlags,&disk);
 if (!s) s=SecStaticCodeCheckValidity(disk,kSecCSStrictValidate|kSecCSCheckAllArchitectures,NULL);
 if (!s) s=SecCodeCheckValidity(guest,kSecCSStrictValidate,NULL);
 if (!s) s=SecCodeCopySigningInformation(disk,kSecCSSigningInformation,&diskInfo);
 CFDataRef diskCD=diskInfo?CFDictionaryGetValue(diskInfo,kSecCodeInfoUnique):NULL;
 if (!s && (!diskCD || !CFEqual(cd,diskCD))) s=errSecCSReqFailed;
 if (diskInfo)CFRelease(diskInfo);if(disk)CFRelease(disk);CFRelease(url);
 if(info)CFRelease(info);if(guest)CFRelease(guest);return s;
}
*/
import "C"
import (
	"bytes"
	"net"
	"os"
	"unsafe"
)

type darwinBinding struct {
	token          [32]byte
	pid            int
	identity, path string
	hash           []byte
	closed         bool
}

func bindProcess(c net.Conn) (processBinding, error) {
	conn, ok := c.(*net.UnixConn)
	if !ok {
		return nil, ErrAuthority
	}
	raw, e := conn.SyscallConn()
	if e != nil {
		return nil, e
	}
	b := &darwinBinding{}
	bad := false
	if e = raw.Control(func(fd uintptr) { bad = C.peerToken(C.int(fd), unsafe.Pointer(&b.token[0])) != 0 }); e != nil || bad {
		return nil, ErrAuthority
	}
	b.pid = int(C.tokenPID(unsafe.Pointer(&b.token[0])))
	if int(C.tokenUID(unsafe.Pointer(&b.token[0]))) != os.Geteuid() {
		return nil, ErrAuthority
	}
	b.path, b.identity, e = executable(b.pid)
	if e != nil {
		return nil, ErrAuthority
	}
	b.hash, e = b.running()
	if e != nil {
		return nil, e
	}
	return b, nil
}
func (b *darwinBinding) running() ([]byte, error) {
	p := C.CString(b.path)
	defer C.free(unsafe.Pointer(p))
	hash := make([]byte, 64)
	n := C.size_t(len(hash))
	if C.runningImage(unsafe.Pointer(&b.token[0]), p, unsafe.Pointer(&hash[0]), &n) != 0 {
		return nil, ErrAuthority
	}
	return hash[:int(n)], nil
}
func (b *darwinBinding) check(pid int) error {
	if b.closed || pid != b.pid {
		return ErrAuthority
	}
	path, id, e := executable(pid)
	if e != nil || path != b.path || id != b.identity {
		return ErrAuthority
	}
	h, e := b.running()
	if e != nil || !bytes.Equal(h, b.hash) {
		return ErrAuthority
	}
	return nil
}
func (b *darwinBinding) close() { b.closed = true; clear(b.token[:]); clear(b.hash) }
