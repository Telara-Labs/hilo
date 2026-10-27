package syncnode

import (
	"github.com/Telara-Labs/telara-memory/contract/internal/node/custodyguard"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
)

// OwnedCredentialHandles reads only validated typed metadata. The lifecycle
// caller retains custody admission and LockCustodyProfile while reading.
func OwnedCredentialHandles(dir string) ([]custodyguard.Handle, error) {
	p, err := LoadProfile(dir)
	if Disabled(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	genesis, machine, err := store.InstalledIdentity(dir)
	if err != nil || genesis != p.Genesis || machine != p.Device {
		return nil, ErrIdentity
	}
	out := []custodyguard.Handle{{Handle: p.Credential, Purpose: "sync-dpop"}}
	if p.Refresh != "" {
		out = append(out, custodyguard.Handle{Handle: p.Refresh, Purpose: "sync-refresh"})
	}
	for _, h := range p.Retired {
		out = append(out, custodyguard.Handle{Handle: h, Purpose: "sync-retired"})
	}
	return out, nil
}
