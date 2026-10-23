package ipc

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFrames(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		ok          bool
	}{{"valid", "{}\n", true}, {"blank", "\n", false}, {"partial", "{}", false}, {"malformed", "{secret}\n", false}, {"boundary", `"` + strings.Repeat("a", MaxFrame-3) + "\"\n", true}, {"oversize", `"` + strings.Repeat("a", MaxFrame-2) + "\"\n", false}} {
		t.Run(tc.name, func(t *testing.T) {
			_, e := ReadFrame(bufio.NewReader(strings.NewReader(tc.input)))
			if (e == nil) != tc.ok {
				t.Fatalf("got %v", e)
			}
		})
	}
	var b bytes.Buffer
	if WriteFrame(&b, map[string]int{"v": 1}) != nil || b.String() != "{\"v\":1}\n" {
		t.Fatal("write")
	}
	if !errors.Is(WriteFrame(io.Discard, strings.Repeat("a", MaxFrame)), ErrFrame) {
		t.Fatal("oversize output")
	}
	if !errors.Is(DecodeStrict([]byte(`{"unknown":"secret"}`), &Hello{}), ErrFrame) {
		t.Fatal("unknown field")
	}
}
func TestHello(t *testing.T) {
	h := Hello{T: "hello", V: 1, Kind: "mcp", PID: 1, Client: "test"}
	if !h.Valid() {
		t.Fatal("hello")
	}
	for i := 0; i < 7; i++ {
		h.Ancestry = append(h.Ancestry, Proc{PID: 2, StartMS: 1})
	}
	if h.Valid() {
		t.Fatal("ancestry")
	}
	h.Ancestry = []Proc{{PID: 2}}
	if h.Valid() {
		t.Fatal("missing start")
	}
	h.Ancestry = nil
	h.V = 2
	if h.Valid() {
		t.Fatal("wire version")
	}
}
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte("{}\n"))
	f.Add([]byte("not-json\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxFrame+1 {
			return
		}
		v, e := ReadFrame(bufio.NewReader(bytes.NewReader(b)))
		if e == nil && (!json.Valid(v) || len(v)+1 > MaxFrame) {
			t.Fatal("unbounded or invalid")
		}
	})
}

func TestDarwinACLDecoder(t *testing.T) {
	fixture := func(flags, rights uint32) []byte {
		b := make([]byte, 80)
		binary.LittleEndian.PutUint32(b[:4], 80)
		binary.LittleEndian.PutUint32(b[4:8], 8)
		binary.LittleEndian.PutUint32(b[8:12], 68)
		binary.LittleEndian.PutUint32(b[12:16], 0x012cc16d)
		binary.LittleEndian.PutUint32(b[48:52], 1)
		binary.LittleEndian.PutUint32(b[72:76], flags)
		binary.LittleEndian.PutUint32(b[76:80], rights)
		return b
	}
	for _, tc := range []struct {
		name          string
		flags, rights uint32
		private, ok   bool
	}{
		{"private permit", 1, KAUTH_VNODE_READ_DATA, true, false},
		{"ancestor mutation", 1, KAUTH_VNODE_DELETE_CHILD, false, false},
		{"ancestor read", 1, KAUTH_VNODE_READ_DATA, false, true},
		{"ancestor search", 1, KAUTH_VNODE_SEARCH, false, true},
		{"private search", 1, KAUTH_VNODE_SEARCH, true, false},
		{"ancestor add subdirectory", 1, KAUTH_VNODE_ADD_SUBDIRECTORY, false, false},
		{"ancestor append data", 1, KAUTH_VNODE_APPEND_DATA, false, false},
		{"ancestor add file", 1, KAUTH_VNODE_ADD_FILE, false, false},
		{"ancestor delete", 1, KAUTH_VNODE_DELETE, false, false},
		{"ancestor write attributes", 1, KAUTH_VNODE_WRITE_ATTRIBUTES, false, false},
		{"ancestor write extattributes", 1, KAUTH_VNODE_WRITE_EXTATTRIBUTES, false, false},
		{"ancestor write security", 1, KAUTH_VNODE_WRITE_SECURITY, false, false},
		{"ancestor take ownership", 1, KAUTH_VNODE_TAKE_OWNERSHIP, false, false},
		{"ancestor generic all", 1, KAUTH_ACE_GENERIC_ALL, false, false},
		{"ancestor generic write", 1, KAUTH_ACE_GENERIC_WRITE, false, false},
		{"ancestor linktarget", 1, KAUTH_VNODE_LINKTARGET, false, false},
		{"ancestor checkimmutable", 1, KAUTH_VNODE_CHECKIMMUTABLE, false, false},
		{"deny", 2, 0xffffffff, true, true}, {"inherit-only", 1 | 1<<8, 0xffffffff, true, true}, {"unsupported ACE", 3, 1, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := checkDarwinACL(fixture(tc.flags, tc.rights), tc.private); (e == nil) != tc.ok {
				t.Fatal(e)
			}
		})
	}
	for _, b := range [][]byte{nil, make([]byte, 12), fixture(1, 1)[:79]} {
		if checkDarwinACL(b, true) == nil {
			t.Fatal("malformed ACL accepted")
		}
	}
	b := fixture(2, 1)
	binary.LittleEndian.PutUint32(b[48:52], 129)
	if checkDarwinACL(b, false) == nil {
		t.Fatal("oversize ACL")
	}
	b = fixture(2, 1)
	binary.LittleEndian.PutUint32(b[48:52], 0xffffffff)
	if checkDarwinACL(b, true) != nil {
		t.Fatal("NOACL rejected")
	}
	b = make([]byte, 12)
	binary.LittleEndian.PutUint32(b[:4], 12)
	if checkDarwinACL(b, true) != nil {
		t.Fatal("empty ACL rejected")
	}
}
func TestEncodeRejectsBeforeWrite(t *testing.T) {
	for _, v := range []any{make(chan int), strings.Repeat("<", 1000000)} {
		var out bytes.Buffer
		if e := WriteFrame(&out, v); !errors.Is(e, ErrFrame) || out.Len() != 0 {
			t.Fatalf("preflight wrote %d %v", out.Len(), e)
		}
	}
}
