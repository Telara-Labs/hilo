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
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return failure("installed_authority_exists")
	}
	f, err := os.CreateTemp(dir, ".installed-authority-")
	if err != nil {
		return failure("installed_authority_exists")
	}
	name := f.Name()
	defer os.Remove(name)
	// Publish only complete, synced bytes while the caller holds writer admission.
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return failure("storage_error")
	}
	if err = privateFile(name); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
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
