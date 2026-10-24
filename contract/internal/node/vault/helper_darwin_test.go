//go:build darwin && cgo

package vault

import (
	"bytes"
	"testing"
)

func TestNativeHelperRejectsMalformedBoundedInput(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("{}"), make([]byte, 9000), append([]byte{1}, make([]byte, 34)...)} {
		var out bytes.Buffer
		if !RunHelper([]string{helperArg}, bytes.NewReader(b), &out) {
			t.Fatal("helper not recognized")
		}
		if out.Len() > 1 {
			t.Fatal("malformed request returned material")
		}
	}
	var out bytes.Buffer
	if RunHelper([]string{"unrelated"}, bytes.NewReader(nil), &out) {
		t.Fatal("unrelated command consumed")
	}
}
func TestKeychainErrorIsExplicitAndClassifiable(t *testing.T) {
	if ErrKeychainUnavailable.Error() != "keychain_unavailable" {
		t.Fatal(ErrKeychainUnavailable)
	}
}
