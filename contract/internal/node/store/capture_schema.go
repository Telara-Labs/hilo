package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
)

// Only opaque identities, counters and verification metadata survive erasure.
// Payloads, event salts and payload comparison hashes never enter these tables.
const captureSchema = `
CREATE TABLE IF NOT EXISTS capture_instance(singleton INTEGER PRIMARY KEY CHECK(singleton=1), id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS capture_progress(source TEXT PRIMARY KEY, session TEXT NOT NULL, version INTEGER NOT NULL, settled INTEGER NOT NULL, reader TEXT NOT NULL, reader_version TEXT NOT NULL, ruleset TEXT NOT NULL, first INTEGER NOT NULL, last_exclusive INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS capture_source(source TEXT NOT NULL REFERENCES capture_progress(source), position INTEGER NOT NULL, record_id TEXT NOT NULL REFERENCES record(id), PRIMARY KEY(source,position));
CREATE TABLE IF NOT EXISTS capture_page(source TEXT NOT NULL REFERENCES capture_progress(source), page INTEGER NOT NULL, record_id TEXT NOT NULL REFERENCES record(id), PRIMARY KEY(source,page));
CREATE TABLE IF NOT EXISTS capture_transition(id TEXT PRIMARY KEY, source TEXT NOT NULL, session TEXT NOT NULL, expected_version INTEGER NOT NULL, resulting_version INTEGER NOT NULL, settled INTEGER NOT NULL, reader TEXT NOT NULL, reader_version TEXT NOT NULL, ruleset TEXT NOT NULL, first INTEGER NOT NULL, last_exclusive INTEGER NOT NULL, UNIQUE(source,expected_version));
CREATE TABLE IF NOT EXISTS capture_transition_record(transition_id TEXT NOT NULL REFERENCES capture_transition(id), position INTEGER NOT NULL, record_id TEXT NOT NULL REFERENCES record(id), sequence INTEGER NOT NULL, PRIMARY KEY(transition_id,position));
CREATE TABLE IF NOT EXISTS capture_transition_source(transition_id TEXT NOT NULL REFERENCES capture_transition(id), position INTEGER NOT NULL, record_id TEXT NOT NULL REFERENCES record(id), sequence INTEGER NOT NULL, PRIMARY KEY(transition_id,position));
CREATE TABLE IF NOT EXISTS capture_transition_page(transition_id TEXT NOT NULL REFERENCES capture_transition(id), page INTEGER NOT NULL, record_id TEXT NOT NULL REFERENCES record(id), PRIMARY KEY(transition_id,page));
`

func (s *Store) initializeCapture(ctx context.Context) error {
	if _, e := s.conn.ExecContext(ctx, captureSchema+spoolSchema); e != nil {
		return failure("storage_error")
	}
	var id string
	e := s.conn.QueryRowContext(ctx, "SELECT id FROM capture_instance WHERE singleton=1").Scan(&id)
	if e == sql.ErrNoRows {
		var b [16]byte
		if _, e = rand.Read(b[:]); e != nil {
			return failure("entropy_unavailable")
		}
		id = hex.EncodeToString(b[:])
		if _, e = s.conn.ExecContext(ctx, "INSERT INTO capture_instance VALUES(1,?)", id); e != nil {
			return failure("storage_error")
		}
	} else if e != nil {
		return failure("storage_error")
	}
	if len(id) != 32 {
		return failure("corrupt_database")
	}
	s.instanceID = id
	return nil
}
