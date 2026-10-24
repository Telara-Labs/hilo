package store

import (
	"io"
	"os"
	"path/filepath"
)

// Installed records contain public pins and opaque vault handles only. Identity
// private keys and credential tokens remain in the caller's OS secret vault.
func ReadInstalledRecord(dir string) ([]byte, error) {
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "installed-authority.json")
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
	if len(b) == 0 || len(b) > 16384 {
		return failure("invalid_config")
	}
	if err := privateDir(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, "installed-authority.json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return failure("installed_authority_exists")
	}
	// A failed/partial bootstrap is preserved for explicit trusted recovery.
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return failure("storage_error")
	}
	if err = privateFile(path); err != nil {
		return err
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
