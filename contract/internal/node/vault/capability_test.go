package vault

import (
	"bytes"
	"testing"
)

func TestCapabilitiesAreVersionedNonmutatingAndBounded(t *testing.T) {
	for _, native := range []bool{false, true} {
		var out bytes.Buffer
		if !runCapabilities([]string{capabilityArg}, bytes.NewReader(capabilityRequest), &out, native) {
			t.Fatal("request not consumed")
		}
		if compatibleCapabilities(out.Bytes()) != native {
			t.Fatal("incorrect native capability", out.Bytes())
		}
	}
	for _, b := range [][]byte{nil, []byte("invalid"), append(append([]byte(nil), capabilityRequest...), 0), {'T', 'M', 'V', 'C', 0, 0}} {
		var out bytes.Buffer
		if !runCapabilities([]string{capabilityArg}, bytes.NewReader(b), &out, true) || out.Len() != 0 {
			t.Fatal("invalid request answered")
		}
	}
	for _, b := range [][]byte{nil, {'T', 'M', 'V', 'C', 0, 0, 7}, {'T', 'M', 'V', 'C', 0, 1, 3}, {'T', 'M', 'V', 'C', 0, 1, 5}, {'T', 'M', 'V', 'C', 0, 1, 6}, {'T', 'M', 'V', 'C', 0, 1, 7, 0}} {
		if compatibleCapabilities(b) {
			t.Fatal("incompatible target accepted", b)
		}
	}
	var out bytes.Buffer
	if runCapabilities([]string{"other"}, bytes.NewReader(capabilityRequest), &out, true) {
		t.Fatal("unrelated command consumed")
	}
}

func TestHelperCapabilitiesMatchCompiledCustodySupport(t *testing.T) {
	var out bytes.Buffer
	if !RunHelper([]string{capabilityArg}, bytes.NewReader(capabilityRequest), &out) {
		t.Fatal("capability command not handled")
	}
	if compatibleCapabilities(out.Bytes()) != UpgradeHandoffRequired() {
		t.Fatal("helper advertised incorrect custody support", out.Bytes())
	}
}
