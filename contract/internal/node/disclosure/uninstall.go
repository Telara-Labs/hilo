package disclosure

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// DeleteInstalledSecret is called only after daemon quiescence under the
// installation lifecycle lock. The non-secret manifest stays for retry and
// retained-data diagnostics; deletion never grants permission to rebootstrap.
func DeleteInstalledSecret(ctx context.Context, dir string, vault SecretVault) error {
	if vault == nil || !filepath.IsAbs(dir) || ipc.ValidateDir(dir, false) != nil {
		return installedFailure()
	}
	b, err := store.ReadInstalledRecord(dir)
	if err != nil {
		return installedFailure()
	}
	var m installedManifest
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || m.Version != 1 || !record.IsKeyID(m.Owner) || !record.IsUUIDv4(m.Machine) || !record.IsUUIDv4(m.Credential) || !record.IsKeyID(m.VaultHandle) {
		return installedFailure()
	}
	if vault.Delete(ctx, m.VaultHandle) != nil {
		return installedFailure()
	}
	return nil
}
