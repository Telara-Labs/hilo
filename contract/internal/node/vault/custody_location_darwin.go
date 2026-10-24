//go:build darwin && cgo

package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

const custodyLocationFile = "custody-location.json"

type custodyLocation struct {
	Version  int    `json:"version"`
	Keychain string `json:"keychain"`
}

// Caller holds db.lock. A missing recorded store is never replaced by whichever
// Keychain happens to be the default in this process.
func (v *Vault) bindCustody(ctx context.Context, data string, create bool) error {
	raw, e := privateRead(filepath.Join(data, custodyLocationFile))
	if os.IsNotExist(e) && create {
		if e = v.selectKeychain(ctx); e != nil {
			return e
		}
		m := custodyLocation{1, v.keychainPath}
		raw, e = json.Marshal(m)
		if e != nil {
			return e
		}
		if len(raw) > 16384 || !filepath.IsAbs(m.Keychain) || filepath.Clean(m.Keychain) != m.Keychain || len(m.Keychain) > 4096 {
			return ErrUnavailable
		}
		f, e := os.CreateTemp(data, ".custody-location-")
		if e != nil {
			return e
		}
		defer os.Remove(f.Name())
		if _, e = f.Write(raw); e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		if e = os.Rename(f.Name(), filepath.Join(data, custodyLocationFile)); e != nil {
			return e
		}
		if e = syncHandoffDir(data); e != nil {
			return e
		}
	} else if e != nil {
		return ErrUnavailable
	}
	var m custodyLocation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || m.Version != 1 || !filepath.IsAbs(m.Keychain) || filepath.Clean(m.Keychain) != m.Keychain || len(m.Keychain) > 4096 {
		return ErrUnavailable
	}
	// Resolve accessibility even when the caller has cached a location. Helpers
	// explicitly open this path and cannot silently fall back to the default.
	path, e := filepath.EvalSymlinks(m.Keychain)
	if e != nil || path != m.Keychain {
		return ErrUnavailable
	}
	v.keychainPath = m.Keychain
	return nil
}
