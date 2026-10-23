package ipc

import (
	"crypto/sha256"
	"encoding/binary"
	"runtime"
	"strings"
)

func shaPath(s string) [32]byte { return sha256.Sum256([]byte(s)) }
func splitPath(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '/' })
}
func systemPath(s string) string {
	if runtime.GOOS == "darwin" {
		for _, p := range []string{"/tmp", "/var", "/etc"} {
			if s == p || strings.HasPrefix(s, p+"/") {
				return "/private" + s
			}
		}
	}
	return s
}

// Darwin sys/kauth.h vnode rights. Directory aliases share the corresponding
// file right. Keep traversal (EXECUTE/SEARCH) separate from mutation rights.
const (
	KAUTH_VNODE_READ_DATA           uint32 = 1 << 1
	KAUTH_VNODE_WRITE_DATA          uint32 = 1 << 2
	KAUTH_VNODE_ADD_FILE                   = KAUTH_VNODE_WRITE_DATA
	KAUTH_VNODE_EXECUTE             uint32 = 1 << 3
	KAUTH_VNODE_SEARCH                     = KAUTH_VNODE_EXECUTE
	KAUTH_VNODE_DELETE              uint32 = 1 << 4
	KAUTH_VNODE_APPEND_DATA         uint32 = 1 << 5
	KAUTH_VNODE_ADD_SUBDIRECTORY           = KAUTH_VNODE_APPEND_DATA
	KAUTH_VNODE_DELETE_CHILD        uint32 = 1 << 6
	KAUTH_VNODE_WRITE_ATTRIBUTES    uint32 = 1 << 8
	KAUTH_VNODE_WRITE_EXTATTRIBUTES uint32 = 1 << 10
	KAUTH_VNODE_WRITE_SECURITY      uint32 = 1 << 12
	KAUTH_VNODE_TAKE_OWNERSHIP      uint32 = 1 << 13
	KAUTH_ACE_GENERIC_ALL           uint32 = 1 << 21
	KAUTH_ACE_GENERIC_WRITE         uint32 = 1 << 23
	KAUTH_VNODE_LINKTARGET          uint32 = 1 << 25
	KAUTH_VNODE_CHECKIMMUTABLE      uint32 = 1 << 26
)

func checkDarwinACL(buf []byte, private bool) error {
	if len(buf) < 12 {
		return ErrUnsafe
	}
	n := int(binary.LittleEndian.Uint32(buf[:4]))
	if n < 12 || n > len(buf) {
		return ErrUnsafe
	}
	off := int(int32(binary.LittleEndian.Uint32(buf[4:8]))) + 4
	size := int(binary.LittleEndian.Uint32(buf[8:12]))
	if size == 0 {
		return nil
	}
	if off < 12 || size < 44 || off > n-size {
		return ErrUnsafe
	}
	acl := buf[off : off+size]
	if binary.LittleEndian.Uint32(acl[:4]) != 0x012cc16d {
		return ErrUnsafe
	}
	count := binary.LittleEndian.Uint32(acl[36:40])
	if count == 0xffffffff {
		return nil
	}
	if count > 128 || int(count) > (len(acl)-44)/24 {
		return ErrUnsafe
	}
	// Conservative allow policy. Private objects reject all effective permit
	// entries, including owner permits. Ancestors may grant read/search only.
	const mutation = KAUTH_VNODE_ADD_FILE | KAUTH_VNODE_DELETE |
		KAUTH_VNODE_ADD_SUBDIRECTORY | KAUTH_VNODE_DELETE_CHILD |
		KAUTH_VNODE_WRITE_ATTRIBUTES | KAUTH_VNODE_WRITE_EXTATTRIBUTES |
		KAUTH_VNODE_WRITE_SECURITY | KAUTH_VNODE_TAKE_OWNERSHIP |
		KAUTH_ACE_GENERIC_ALL | KAUTH_ACE_GENERIC_WRITE |
		KAUTH_VNODE_LINKTARGET | KAUTH_VNODE_CHECKIMMUTABLE
	for i := 0; i < int(count); i++ {
		ace := acl[44+i*24 : 44+(i+1)*24]
		flags := binary.LittleEndian.Uint32(ace[16:20])
		rights := binary.LittleEndian.Uint32(ace[20:24])
		if flags&(1<<8) != 0 {
			continue
		}
		if flags&0xf == 2 {
			continue
		}
		if flags&0xf != 1 || (private && rights != 0) || rights&mutation != 0 {
			return ErrUnsafe
		}
	}
	return nil
}
