package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// Sidecar names are fixed. Sync state and its owner-only profile live beside
// the store in the same private data directory, never at a caller-chosen path.
const (
	SyncDatabaseName = "sync.sqlite"
	SyncProfileName  = "sync-profile.json"
)

const maxProfileFile = 65536

// OpenSidecarDatabase opens the fixed sync database with the store's SQLite
// privacy and durability settings. The caller owns its schema and closes it.
func OpenSidecarDatabase(ctx context.Context, dir string) (*sql.DB, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, failure("invalid_options")
	}
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, SyncDatabaseName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		f.Close()
	} else if !os.IsExist(err) {
		return nil, failure("storage_error")
	}
	if err = privateFile(path); err != nil {
		return nil, err
	}
	if err = securePathFiles(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path}).String())
	if err != nil {
		return nil, failure("storage_error")
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	fail := func(err error) (*sql.DB, error) { db.Close(); return nil, err }
	var version string
	if db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&version) != nil || version != "3.53.4" {
		return fail(failure("unsupported_sqlite"))
	}
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA synchronous=FULL", "PRAGMA secure_delete=ON", "PRAGMA temp_store=MEMORY"} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return fail(failure("storage_error"))
		}
	}
	for name, want := range map[string]int{"foreign_keys": 1, "busy_timeout": 5000, "synchronous": 2, "secure_delete": 1, "temp_store": 2} {
		var v int
		if db.QueryRowContext(ctx, "PRAGMA "+name).Scan(&v) != nil || v != want {
			return fail(failure("unsafe_sqlite"))
		}
	}
	var mode string
	if db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode) != nil || mode != "wal" {
		return fail(failure("unsafe_sqlite"))
	}
	if err = securePathFiles(path); err != nil {
		return fail(err)
	}
	return db, nil
}

// ReadSyncProfile returns the owner-only profile bytes, or os.ErrNotExist.
func ReadSyncProfile(dir string) ([]byte, error) {
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, SyncProfileName)
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, failure("unsafe_path")
	}
	if err = privateFile(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, failure("unsafe_path")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() > maxProfileFile {
		return nil, failure("unsafe_path")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxProfileFile+1))
	if err != nil || len(b) > maxProfileFile {
		return nil, failure("unsafe_path")
	}
	return b, nil
}

// WriteSyncProfile atomically replaces the profile with complete synced bytes.
func WriteSyncProfile(dir string, b []byte) error {
	if len(b) == 0 || len(b) > maxProfileFile {
		return failure("invalid_config")
	}
	if err := privateDir(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".sync-profile-")
	if err != nil {
		return failure("storage_error")
	}
	name := f.Name()
	defer os.Remove(name)
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
	if err = os.Rename(name, filepath.Join(dir, SyncProfileName)); err != nil {
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

// RemoveSyncProfile deletes the profile. A missing profile is not an error.
func RemoveSyncProfile(dir string) error {
	if err := privateDir(dir); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, SyncProfileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return failure("storage_error")
	}
	return nil
}

// InstalledIdentity returns the public owner genesis and machine id pinned by
// installation. It never returns or reads a vault secret.
func InstalledIdentity(dir string) (genesis, machine string, err error) {
	b, err := ReadInstalledRecord(dir)
	if err != nil {
		return "", "", err
	}
	var m struct {
		Owner   string `json:"owner"`
		Machine string `json:"machine"`
	}
	if json.Unmarshal(b, &m) != nil || !record.IsKeyID(m.Owner) || !record.IsUUIDv4(m.Machine) {
		return "", "", failure("unsafe_path")
	}
	return m.Owner, m.Machine, nil
}
