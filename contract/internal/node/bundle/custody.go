package bundle

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/Telara-Labs/hilo/contract/internal/node/custodyguard"
	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	"github.com/Telara-Labs/hilo/contract/record"
)

// OwnedCredentialHandles validates public identity pins before exposing opaque
// handles to the lifecycle inventory. The caller retains custody admission.
func OwnedCredentialHandles(dir string) ([]custodyguard.Handle, error) {
	id, err := ProfileIdentity(dir)
	if err != nil {
		return nil, err
	}
	var out []custodyguard.Handle
	k, ok, err := readExportKey(dir)
	if err != nil {
		return nil, err
	}
	if ok {
		if k.Genesis != id.Genesis || k.Device != id.Device || k.Machine != id.Machine {
			return nil, ErrProfile
		}
		out = append(out, custodyguard.Handle{Handle: k.Handle, Purpose: "bundle-export"})
	}
	b, err := store.ReadProfileRecord(dir, store.JoinPendingName)
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(dir, store.JoinPendingName)); errors.Is(statErr, os.ErrNotExist) {
			return out, nil
		}
		return nil, err
	}
	var p joinPending
	if decodeFile(b, &p) != nil || p.Version != 1 || p.Genesis != id.Genesis || p.Device != id.Device || p.Machine != id.Machine || !record.IsKeyID(p.Handle) || !record.IsHex64(p.DeviceAdd) {
		return nil, ErrProfile
	}
	out = append(out, custodyguard.Handle{Handle: p.Handle, Purpose: "bundle-pending-join"})
	return out, nil
}
