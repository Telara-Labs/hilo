package vault

import (
	"bytes"
	"io"
)

const capabilityArg = "native-custody-capabilities"

// The capability request has no handle, keychain path or secret and must never
// open native custody. Version 1 requires transfer, own-slot read and cleanup.
var capabilityRequest = []byte{'T', 'M', 'V', 'C', 0, 1}

func runCapabilities(args []string, in io.Reader, out io.Writer, native bool) bool {
	if len(args) != 1 || args[0] != capabilityArg {
		return false
	}
	b, e := io.ReadAll(io.LimitReader(in, 7))
	if e != nil || !bytes.Equal(b, capabilityRequest) {
		return true
	}
	flags := byte(0)
	if native {
		flags = 7
	}
	_, _ = out.Write(append(append([]byte(nil), capabilityRequest...), flags))
	return true
}

func compatibleCapabilities(b []byte) bool {
	return len(b) == 7 && bytes.Equal(b[:6], capabilityRequest) && b[6] == 7
}
