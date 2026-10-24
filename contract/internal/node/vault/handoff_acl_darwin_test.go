//go:build darwin && cgo

package vault

import (
	"encoding/binary"
	"testing"
)

func custodyACLFixture(flags, rights uint32) []byte {
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
func TestCustodyACLBoundsAndMutation(t *testing.T) {
	for _, b := range [][]byte{nil, make([]byte, 12), custodyACLFixture(9, 0), custodyACLFixture(1, 1<<2), custodyACLFixture(1, 1<<21), custodyACLFixture(1, 1<<23), custodyACLFixture(1, 1<<25)} {
		if custodyDarwinACL(b, false) == nil {
			t.Fatal("unsafe ACL accepted")
		}
	}
	if e := custodyDarwinACL(custodyACLFixture(2, 0xffffffff), true); e != nil {
		t.Fatal("deny-only ACL", e)
	}
	if e := custodyDarwinACL(custodyACLFixture(1, 1<<1), false); e != nil {
		t.Fatal("read-only ancestor", e)
	}
	if e := custodyDarwinACL(custodyACLFixture(1, 1<<1), true); e == nil {
		t.Fatal("private read grant accepted")
	}
}
