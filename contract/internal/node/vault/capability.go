package vault

import (
	"bytes"
	"errors"
	"io"
	"time"
)

const capabilityArg = "native-custody-capabilities"

const profileLifecycleWait = 5 * time.Minute

var ErrLegacyCustody = errors.New("custody_maintenance_migration_required")

// The capability request has no handle, keychain path or secret and must never
// open native custody. Version 2 additionally requires complete typed profile
// inventory, writer fencing and per-handle creator evidence. Legacy callers
// cannot negotiate this protocol and must retain their current custody.
var capabilityRequest = []byte{'T', 'M', 'V', 'C', 0, 2}

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
