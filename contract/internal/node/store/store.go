// Package store persists a single pinned local device stream. It is an internal
// inspection and storage boundary, not a network authentication or delivery API.
package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/Telara-Labs/telara-memory/contract/record"
	_ "modernc.org/sqlite"
)

type Error struct {
	Code         string
	OwnerBlocked bool
}

func (e *Error) Error() string  { return e.Code }
func failure(code string) error { return &Error{Code: code} }
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err != nil {
		return "storage_error"
	}
	return ""
}

type Options struct{ Dir, PinnedGenesisID, LocalMachineID string }
type SignedRecord struct {
	HeaderJCS, BodyJCS []byte
	Sigs               []record.Signature
	AdvisoryID         string
}
type AdmissionResult struct {
	ID                   string
	Sequence, Generation int64
	State                string
	Duplicate            bool
}
type EraseResult struct {
	AdmissionResult
	Physical string
}
type ReadRequest struct{ IDs []string }
type Entry struct {
	SignedRecord
	ID, Owner, State, SignatureStatus string
	Sequence, Generation              int64
	TaskStatus                        string
}
type Snapshot struct {
	Generation int64
	Entries    []Entry
}
type SourceOccurrence struct {
	Owner, Source, SessionKey string
	EventIDs                  []string
}
type Suppression struct {
	Suppressed   bool
	OwnerBlocked bool
}
type JobToken struct {
	RecordID   string
	Generation int64
}
type Projection struct {
	Model  string
	Vector []byte
}
type ScrubResult struct {
	ControlID, State string
	Generation       int64
}

type Store struct {
	instanceID     string
	poisoned       bool
	barrierAttempt bool
	mu             sync.Mutex
	db             *sql.DB
	conn           *sql.Conn
	opts           Options
	path           string
	closed         bool
}

// Open refuses unsupported privacy, incompatible identities and SQLite settings.
func Open(ctx context.Context, o Options) (*Store, error) {
	if !record.IsKeyID(o.PinnedGenesisID) || !record.IsUUIDv4(o.LocalMachineID) || o.Dir == "" {
		return nil, failure("invalid_options")
	}
	dir, err := filepath.Abs(o.Dir)
	if err != nil {
		return nil, failure("unsafe_path")
	}
	o.Dir = dir
	if err = privateDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "memory.sqlite")
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
	conn, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		return nil, failure("storage_error")
	}
	s := &Store{db: db, conn: conn, opts: o, path: path}
	fail := func(err error) (*Store, error) { conn.Close(); db.Close(); return nil, err }
	if err = s.configure(ctx); err != nil {
		return fail(err)
	}
	if err = s.write(ctx, func() error { return s.initialize(ctx) }); err != nil {
		return fail(err)
	}
	if err = s.secureFiles(); err != nil {
		return fail(err)
	}
	return s, nil
}
func (s *Store) configure(ctx context.Context) error {
	var version string
	if s.conn.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&version) != nil || version != "3.53.4" {
		return failure("unsupported_sqlite")
	}
	for _, q := range []string{"PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA synchronous=FULL", "PRAGMA secure_delete=ON", "PRAGMA temp_store=MEMORY"} {
		if _, err := s.conn.ExecContext(ctx, q); err != nil {
			return failure("storage_error")
		}
	}
	for name, want := range map[string]int{"foreign_keys": 1, "busy_timeout": 5000, "synchronous": 2, "secure_delete": 1, "temp_store": 2, "auto_vacuum": 2} {
		var v int
		if s.conn.QueryRowContext(ctx, "PRAGMA "+name).Scan(&v) != nil || v != want {
			return failure("unsafe_sqlite")
		}
	}
	var mode string
	if s.conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode) != nil || mode != "wal" {
		return failure("unsafe_sqlite")
	}
	return nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.conn.Close()
	if e := s.db.Close(); err == nil {
		err = e
	}
	if err != nil {
		return failure("storage_error")
	}
	return nil
}

// write serializes connections and checks authority only after acquiring SQLite's writer.
func (s *Store) write(ctx context.Context, f func() error) error { return s.writeMode(ctx, false, f) }
func (s *Store) writeMode(ctx context.Context, capture bool, f func() error) (result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return failure("closed")
	}
	if s.poisoned {
		if capture {
			return failure("outcome_unknown")
		}
		return failure("unavailable")
	}
	if _, err := s.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return failure("storage_error")
	}
	committed := false
	defer func() {
		if !committed {
			if _, err := s.conn.ExecContext(context.Background(), "ROLLBACK"); err != nil && capture {
				s.poisoned = true
				result = failure("outcome_unknown")
			}
		}
	}()
	var refused error
	if err := f(); err != nil {
		if post, ok := err.(*postCommitRefusal); ok {
			refused = post.err
		} else {
			return err
		}
	}
	if _, err := s.conn.ExecContext(ctx, "COMMIT"); err != nil {
		if capture || s.barrierAttempt {
			s.poisoned = true
		}
		if capture {
			return failure("outcome_unknown")
		}
		return failure("storage_error")
	}
	committed = true
	s.barrierAttempt = false
	if err := s.secureFiles(); err != nil {
		if capture || refused != nil {
			s.poisoned = true
		}
		if capture {
			return failure("outcome_unknown")
		}
		return err
	}
	return refused
}
func (s *Store) secureFiles() error { return securePathFiles(s.path) }
func securePathFiles(path string) error {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		p := path + suffix
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return failure("storage_error")
		}
		if err := privateFile(p); err != nil {
			return err
		}
	}
	return nil
}
