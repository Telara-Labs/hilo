package store

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Installed records contain public pins and opaque vault handles only. Identity
// private keys and credential tokens remain in the caller's OS secret vault.
func ReadInstalledRecord(dir string) ([]byte, error) {
	return readPrivateRecord(dir, "installed-authority.json")
}

// Profile records beside the store hold public pins, public keys and opaque
// vault handles only. Each name is fixed; no caller chooses a path.
const (
	DeviceJoinName       = "device-join.json"
	JoinPendingName      = "join-pending.json"
	ExportKeyName        = "export-key.json"
	ExportRecipientsName = "export-recipients.json"
)

func profileRecordName(name string) bool {
	switch name {
	case DeviceJoinName, JoinPendingName, ExportKeyName, ExportRecipientsName:
		return true
	}
	return false
}

// ReadProfileRecord reads one fixed owner-only profile record.
func ReadProfileRecord(dir, name string) ([]byte, error) {
	if !profileRecordName(name) {
		return nil, failure("unsafe_path")
	}
	return readPrivateRecord(dir, name)
}

// WriteProfileRecord durably publishes one fixed owner-only profile record.
// Only the recipient list may be replaced; the others are written once.
func WriteProfileRecord(dir, name string, b []byte) error {
	if !profileRecordName(name) {
		return failure("unsafe_path")
	}
	return writePrivateRecord(dir, name, b, name == ExportRecipientsName)
}

// RemoveProfileRecord deletes a pending record once its successor is durable.
func RemoveProfileRecord(dir, name string) error {
	if name != JoinPendingName {
		return failure("unsafe_path")
	}
	if err := privateDir(dir); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
		return failure("storage_error")
	}
	return nil
}

func readPrivateRecord(dir, name string) ([]byte, error) {
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	if err := privateFile(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, failure("unsafe_path")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, failure("unsafe_path")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() > 16384 {
		return nil, failure("unsafe_path")
	}
	b, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(b) > 16384 {
		return nil, failure("unsafe_path")
	}
	return b, nil
}
func WriteInstalledRecord(dir string, b []byte) error {
	return writePrivateRecord(dir, "installed-authority.json", b, false)
}

func writePrivateRecord(dir, name string, b []byte, replace bool) error {
	if len(b) == 0 || len(b) > 16384 {
		return failure("invalid_config")
	}
	if err := privateDir(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	if st, err := os.Lstat(path); !os.IsNotExist(err) && (!replace || err != nil || !st.Mode().IsRegular()) {
		return failure("installed_authority_exists")
	}
	f, err := os.CreateTemp(dir, "."+strings.TrimSuffix(name, ".json")+"-")
	if err != nil {
		return failure("installed_authority_exists")
	}
	temp := f.Name()
	defer os.Remove(temp)
	// Publish only complete, synced bytes while the caller holds writer admission.
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return failure("storage_error")
	}
	if err = privateFile(temp); err != nil {
		return err
	}
	if err = os.Rename(temp, path); err != nil {
		return failure("storage_error")
	}
	d, err := os.Open(dir)
	if err != nil {
		return failure("storage_error")
	}
	defer d.Close()
	if d.Sync() != nil {
		return failure("storage_error")
	}
	return nil
}
