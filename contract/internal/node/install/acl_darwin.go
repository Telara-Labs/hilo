package install

import (
	"encoding/binary"
	"golang.org/x/sys/unix"
	"unsafe"
)

func checkACL(fd int, private bool) error {
	attrs := unix.Attrlist{Bitmapcount: 5, Commonattr: 0x00400000}
	var b [4096]byte
	_, _, e := unix.Syscall6(unix.SYS_FGETATTRLIST, uintptr(fd), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0)
	if e != 0 {
		return ErrUnsafe
	}
	return darwinACL(b[:], private)
}

// kauth_filesec ACL entries are evaluated conservatively. Deny-only home ACLs
// are safe; unknown grants, inherited mutation and private read grants refuse.
func darwinACL(b []byte, private bool) error {
	if len(b) < 12 {
		return ErrUnsafe
	}
	size := int(binary.LittleEndian.Uint32(b[:4]))
	off := int(int32(binary.LittleEndian.Uint32(b[4:8]))) + 4
	length := int(binary.LittleEndian.Uint32(b[8:12]))
	if size < 12 || size > len(b) || length == 0 {
		if size >= 12 && size <= len(b) && length == 0 {
			return nil
		}
		return ErrUnsafe
	}
	if off < 12 || length < 44 || off > size-length {
		return ErrUnsafe
	}
	x := b[off : off+length]
	if binary.LittleEndian.Uint32(x[:4]) != 0x012cc16d {
		return ErrUnsafe
	}
	count := binary.LittleEndian.Uint32(x[36:40])
	if count == 0xffffffff {
		return nil
	}
	if count > 128 || 44+int(count)*24 > len(x) {
		return ErrUnsafe
	}
	for i := 0; i < int(count); i++ {
		entry := x[44+i*24 : 44+(i+1)*24]
		flags := binary.LittleEndian.Uint32(entry[16:20])
		rights := binary.LittleEndian.Uint32(entry[20:24])
		if flags&0xf == 2 {
			continue
		}
		// Writes, deletes, ACL/owner changes. An inherit-only ACE may affect
		// newly created install files, so it is not exempted here.
		const mutation = 0x4 | 0x10 | 0x20 | 0x40 | 0x100 | 0x400 | 0x1000 | 0x2000 | 1<<21 | 1<<23 | 1<<25 | 1<<26
		if flags&0xf != 1 || private || rights&mutation != 0 {
			return ErrUnsafe
		}
	}
	return nil
}
