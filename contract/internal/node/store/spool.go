package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// Additive migration runs inside Open's FULL initialization transaction, including
// for existing schema-v1/v2 databases. There are no source bodies, event salts,
// payload hashes or authority facts here. Identity/path/process hints are retained
// capture metadata under section 7.1, never native scope or signing authority.
const spoolSchema = `
CREATE TABLE IF NOT EXISTS spool_announcement(
 client TEXT NOT NULL, ulid TEXT NOT NULL, binding TEXT NOT NULL,
 at INTEGER NOT NULL, client_version TEXT NOT NULL, event TEXT NOT NULL,
 native_session TEXT NOT NULL, transcript_path TEXT NOT NULL, cwd TEXT NOT NULL,
 prompt_id TEXT NOT NULL, source TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL,
 hook_pid INTEGER NOT NULL, PRIMARY KEY(client,ulid));
CREATE TABLE IF NOT EXISTS spool_process(
 client TEXT NOT NULL, ulid TEXT NOT NULL, position INTEGER NOT NULL,
 pid INTEGER NOT NULL, start_ms INTEGER NOT NULL, argv0 TEXT NOT NULL,
 PRIMARY KEY(client,ulid,position), FOREIGN KEY(client,ulid) REFERENCES spool_announcement(client,ulid));
CREATE TABLE IF NOT EXISTS spool_done(
 client TEXT NOT NULL, ulid TEXT NOT NULL, mode TEXT NOT NULL CHECK(mode IN ('identity','capture')),
 receipt BLOB NOT NULL, PRIMARY KEY(client,ulid),
 FOREIGN KEY(client,ulid) REFERENCES spool_announcement(client,ulid));
`

type spoolAdmission struct {
	h                   transport.HookSignal
	ulid, binding, mode string
}

func spoolID(client, ulid string) bool {
	if client != "claude" && client != "codex" && client != "cursor" && client != "pi" {
		return false
	}
	if len(ulid) != 26 || ulid[0] > '7' {
		return false
	}
	for _, c := range ulid {
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", c) {
			return false
		}
	}
	return true
}

func signalReader(client string) string {
	switch client {
	case "claude":
		return "claude-code"
	case "cursor":
		return "cursor-agent"
	default:
		return client
	}
}

// Inputs are already validated by the trusted collector. Recheck the same finite
// vocabulary before retention; root authorization and source opening stay with
// the collector. Constructing rules with an explicit home performs no I/O and
// never consults personal configuration. This lexical check grants no path access.
func (s *Store) prepareSpool(h transport.HookSignal, ulid, mode string, q *CaptureRequest) (spoolAdmission, error) {
	if !spoolID(h.Client, ulid) || len(h.Ancestry) > 6 || h.NativeSession == "" {
		return spoolAdmission{}, failure("invalid_signal")
	}
	for _, value := range []string{h.ClientVersion, h.Event, h.NativeSession, h.TranscriptPath, h.Cwd, h.PromptID, h.Source, h.Reason, h.Status} {
		if len(value) > 4096 || !utf8.ValidString(value) {
			return spoolAdmission{}, failure("invalid_signal")
		}
	}
	for _, p := range h.Ancestry {
		if len(p.Argv0) > 256 || !utf8.ValidString(p.Argv0) {
			return spoolAdmission{}, failure("invalid_signal")
		}
	}
	rules, err := clients.HookRules(clients.Options{Client: clients.Client(h.Client), Home: s.opts.Dir})
	if err != nil {
		return spoolAdmission{}, failure("invalid_signal")
	}
	if h.TranscriptPath != "" {
		rules.TranscriptRoot = filepath.Dir(h.TranscriptPath)
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return spoolAdmission{}, failure("invalid_signal")
	}
	parsed, err := transport.ParseHook(raw, rules)
	if err != nil {
		return spoolAdmission{}, failure("invalid_signal")
	}
	if mode == "identity" && h.TranscriptPath != "" || mode == "capture" && h.TranscriptPath == "" {
		return spoolAdmission{}, failure("invalid_signal")
	}
	if q != nil {
		// Bound request serialization before allocating or hashing the binding.
		if !validOccurrence(s.opts, q.Occurrence) || len(q.EventIDs) > 4096 || !readerValid(q.Reader) || q.PolicyID != "" && !record.IsHex64(q.PolicyID) || !record.IsKeyID(q.AuthorKeyID) || !record.IsHex64(q.RulesetFingerprint) {
			return spoolAdmission{}, failure("invalid_request")
		}
		for _, id := range q.EventIDs {
			if !record.IsEventID(id) {
				return spoolAdmission{}, failure("invalid_request")
			}
		}
		reader := signalReader(h.Client)
		sk, err := record.SessionKey(reader, "local", record.NativeGlobal, h.NativeSession, s.opts.LocalMachineID)
		if err != nil || reader != q.Reader.Reader || sk != q.Occurrence.SessionKey {
			return spoolAdmission{}, failure("signal_conflict")
		}
	}
	// Only validated metadata and opaque request identities enter this binding.
	// It detects immutable spool-ID reuse; it is never a source-content hash.
	request, err := json.Marshal(q)
	if err != nil {
		return spoolAdmission{}, failure("invalid_request")
	}
	binding, err := record.HE("spool-admission", mode, string(raw), string(request))
	if err != nil {
		return spoolAdmission{}, failure("invalid_signal")
	}
	return spoolAdmission{*parsed, ulid, binding, mode}, nil
}

// SignalDone is receipt-only and deliberately never opens or loads source bodies.
// Retained receipts have no erasure FK, so crash-before-unlink can be cleaned up
// after source erasure without re-reading banned text.
func (s *Store) SignalDone(ctx context.Context, client, ulid string) (bool, error) {
	if !spoolID(client, ulid) {
		return false, failure("invalid_signal")
	}
	done := false
	err := s.writeMode(ctx, true, func() error {
		if err := s.checkInstance(ctx); err != nil {
			return err
		}
		var n int
		if err := s.conn.QueryRowContext(ctx, "SELECT count(*) FROM spool_done WHERE client=? AND ulid=?", client, ulid).Scan(&n); err != nil {
			return failure("storage_error")
		}
		done = n == 1
		return nil
	})
	return done && err == nil, err
}

// CaptureSignal uses Capture's exact writer, including prior-transition and
// no-change paths. Success means announcement, output and spool_done committed
// together with synchronous=FULL. It never acknowledges a refused producer.
func (s *Store) CaptureSignal(ctx context.Context, h transport.HookSignal, ulid string, q CaptureRequest, producer func(*CaptureTxn) (CommitPlan, error)) (CaptureReceipt, error) {
	a, err := s.prepareSpool(h, ulid, "capture", &q)
	if err != nil {
		return CaptureReceipt{}, err
	}
	return s.capture(ctx, q, producer, &a)
}

// AdmitSignal admits only identity-only hints, with no native authority effect.
func (s *Store) AdmitSignal(ctx context.Context, h transport.HookSignal, ulid string) error {
	a, err := s.prepareSpool(h, ulid, "identity", nil)
	if err != nil {
		return err
	}
	return s.writeMode(ctx, true, func() error {
		if err := s.checkInstance(ctx); err != nil {
			return err
		}
		_, found, err := s.spoolReceipt(ctx, a)
		if err != nil || found {
			return err
		}
		return s.persistSpool(ctx, a, CaptureReceipt{})
	})
}

func (s *Store) spoolReceipt(ctx context.Context, a spoolAdmission) (CaptureReceipt, bool, error) {
	var binding, mode string
	var raw []byte
	err := s.conn.QueryRowContext(ctx, `SELECT a.binding,d.mode,d.receipt FROM spool_announcement a
 LEFT JOIN spool_done d USING(client,ulid) WHERE a.client=? AND a.ulid=?`, a.h.Client, a.ulid).Scan(&binding, &mode, &raw)
	if err == sql.ErrNoRows {
		return CaptureReceipt{}, false, nil
	}
	if err != nil {
		return CaptureReceipt{}, false, failure("storage_error")
	}
	if binding != a.binding || mode != a.mode {
		return CaptureReceipt{}, false, failure("signal_conflict")
	}
	var out CaptureReceipt
	if len(raw) > 64<<10 || json.Unmarshal(raw, &out) != nil {
		return out, false, failure("corrupt_database")
	}
	return out, true, nil
}

func (s *Store) persistSpool(ctx context.Context, a spoolAdmission, r CaptureReceipt) error {
	h := a.h
	if _, err := s.conn.ExecContext(ctx, `INSERT INTO spool_announcement VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, h.Client, a.ulid, a.binding, h.At, h.ClientVersion, h.Event, h.NativeSession, h.TranscriptPath, h.Cwd, h.PromptID, h.Source, h.Reason, h.Status, h.HookPID); err != nil {
		return failure("storage_error")
	}
	for i, p := range h.Ancestry {
		if _, err := s.conn.ExecContext(ctx, "INSERT INTO spool_process VALUES(?,?,?,?,?,?)", h.Client, a.ulid, i, p.PID, p.StartMS, p.Argv0); err != nil {
			return failure("storage_error")
		}
	}
	// CaptureReceipt contains only identifiers/counters/verification metadata.
	// Availability is recomputed on replay, never trusted from a saved snapshot.
	r.CurrentAvailability = nil
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 64<<10 {
		return failure("receipt_limit")
	}
	if _, err = s.conn.ExecContext(ctx, "INSERT INTO spool_done VALUES(?,?,?,?)", h.Client, a.ulid, a.mode, raw); err != nil {
		return failure("storage_error")
	}
	return nil
}
