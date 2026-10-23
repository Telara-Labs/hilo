package install

import (
	"encoding/binary"
	"testing"
)

func aclFixture(flags, rights uint32) []byte {
	b := make([]byte, 80)
	binary.LittleEndian.PutUint32(b[0:4], 80)
	binary.LittleEndian.PutUint32(b[4:8], 8)
	binary.LittleEndian.PutUint32(b[8:12], 68)
	x := b[12:]
	binary.LittleEndian.PutUint32(x[:4], 0x012cc16d)
	binary.LittleEndian.PutUint32(x[36:40], 1)
	binary.LittleEndian.PutUint32(x[60:64], flags)
	binary.LittleEndian.PutUint32(x[64:68], rights)
	return b
}
func TestACLBoundsAndMutation(t *testing.T) {
	for _, b := range [][]byte{nil, make([]byte, 12), aclFixture(9, 0), aclFixture(1, 1<<2), aclFixture(1, 1<<21), aclFixture(1, 1<<23), aclFixture(1, 1<<25)} {
		if darwinACL(b, false) == nil {
			t.Fatal("unsafe ACL accepted")
		}
	}
	if e := darwinACL(aclFixture(2, 0xffffffff), true); e != nil {
		t.Fatal("deny-only ACL", e)
	}
	if e := darwinACL(aclFixture(1, 1<<1), false); e != nil {
		t.Fatal("read-only ancestor", e)
	}
	if e := darwinACL(aclFixture(1, 1<<1), true); e == nil {
		t.Fatal("private read grant accepted")
	}
}
