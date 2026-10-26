package syncnode

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	gosync "sync"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// The logical sync tables of the design live in a sibling database in the same
// owner-only data directory. Outbox rows hold exact signed metadata variants;
// receipts, cursors and fetched controls are keyed by authenticated destination.
const stateSchema = `
CREATE TABLE IF NOT EXISTS selection_rule(rule_id TEXT PRIMARY KEY, version INTEGER NOT NULL CHECK(version>0), enabled INTEGER NOT NULL CHECK(enabled IN(0,1)), repos TEXT NOT NULL, kinds TEXT NOT NULL, profile TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS operation(op_id TEXT PRIMARY KEY, destination TEXT NOT NULL, raw BLOB NOT NULL, digest TEXT NOT NULL, state TEXT NOT NULL, attempt INTEGER NOT NULL, not_before INTEGER NOT NULL, created INTEGER NOT NULL, reason TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS operation_pending ON operation(destination, state, created);
CREATE TABLE IF NOT EXISTS outbox(destination TEXT NOT NULL, record_id TEXT NOT NULL, op_id TEXT NOT NULL, source_id TEXT NOT NULL, lid TEXT NOT NULL, kind TEXT NOT NULL, repo TEXT NOT NULL, remote TEXT NOT NULL, authority TEXT NOT NULL, profile TEXT NOT NULL, state TEXT NOT NULL, policy_at_queue TEXT NOT NULL, header BLOB, body BLOB, sigs BLOB, PRIMARY KEY(destination, record_id));
CREATE INDEX IF NOT EXISTS outbox_source ON outbox(destination, source_id);
CREATE INDEX IF NOT EXISTS outbox_op ON outbox(op_id);
CREATE TABLE IF NOT EXISTS sync_state(destination TEXT PRIMARY KEY, ctl_cursor INTEGER NOT NULL, data_cursor INTEGER NOT NULL, keyset_version INTEGER NOT NULL, acked_ctl INTEGER NOT NULL, acked_data INTEGER NOT NULL, barrier_hseq INTEGER NOT NULL, barrier_reason TEXT NOT NULL, last_error TEXT NOT NULL, last_round INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ctl_pending(destination TEXT NOT NULL, hseq INTEGER NOT NULL CHECK(hseq>0), envelope BLOB NOT NULL, body BLOB, reason TEXT NOT NULL, PRIMARY KEY(destination, hseq));
CREATE TABLE IF NOT EXISTS delivery_receipt(destination TEXT NOT NULL, record_id TEXT NOT NULL, receipt BLOB NOT NULL, hseq INTEGER NOT NULL, hosted_task_id TEXT NOT NULL, PRIMARY KEY(destination, record_id));
CREATE TABLE IF NOT EXISTS data_quarantine(destination TEXT NOT NULL, hseq INTEGER NOT NULL CHECK(hseq>0), envelope BLOB NOT NULL, PRIMARY KEY(destination, hseq));
`

// Row and operation states. Only a verified receipt makes a row complete.
const (
	statePending     = "pending"
	stateComplete    = "complete"
	stateCancelled   = "cancelled"
	stateUnavailable = "unavailable"
	stateRejected    = "rejected"
)

var (
	ErrRule            = errors.New("sync_rule_invalid")
	errControlConflict = errors.New("sync_control_log_conflict")
)

var ruleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Rule selects repositories and kinds for the default push-metadata profile.
// An empty repository or kind list selects nothing. Profile is fixed.
type Rule struct {
	ID      string   `json:"id"`
	Version int64    `json:"version"`
	Enabled bool     `json:"enabled"`
	Repos   []string `json:"repos"`
	Kinds   []string `json:"kinds"`
	Profile string   `json:"profile"`
}

func (r Rule) authority() string { return "rule:" + r.ID + "@" + strconv.FormatInt(r.Version, 10) }
func (r Rule) matches(kind record.Kind, repo string) bool {
	return r.Enabled && r.Profile == record.ProfilePushMetadata && contains(r.Kinds, string(kind)) && contains(r.Repos, repo)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// State is the durable sync database. All methods end their transaction
// before returning; no network wait ever holds a transaction open.
type State struct {
	db   *sql.DB
	path string
	mu   gosync.Mutex
	now  func() time.Time
}

func OpenState(ctx context.Context, dir string) (*State, error) {
	db, err := store.OpenSidecarDatabase(ctx, dir)
	if err != nil {
		return nil, err
	}
	if _, err = db.ExecContext(ctx, stateSchema+fenceSchema); err != nil {
		db.Close()
		return nil, errStateInvalid
	}
	return &State{db: db, path: filepath.Join(dir, store.SyncDatabaseName), now: time.Now}, nil
}

// checkpoint folds the sync database WAL into the main file and truncates it.
// Deleted rows are already zeroed in place by secure_delete, so a clean result
// means no superseded page image of a dropped copy remains in either file. A
// reader pinning the WAL makes it report false; it never reports a clean
// result it did not establish.
func (s *State) checkpoint(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.db.Conn(ctx)
	if err != nil {
		return false, errStateInvalid
	}
	defer c.Close()
	var busy, log, done int
	if err = c.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done); err != nil {
		return false, errStateInvalid
	}
	if busy != 0 || log != 0 || done != 0 {
		return false, nil
	}
	info, err := os.Stat(s.path + "-wal")
	if err != nil && !os.IsNotExist(err) {
		return false, errStateInvalid
	}
	return err != nil || info.Size() == 0, nil
}

// fetchedThrough is where a control scan resumes: after the highest exact
// envelope persisted above ctl_cursor, or at the cursor when none is. Pages
// are persisted in order, so every control at or below it is already held.
func (s *State) fetchedThrough(ctx context.Context, dest string, cursor int64) (int64, error) {
	var top sql.NullInt64
	err := s.tx(ctx, func(q querier) error {
		if q.QueryRowContext(ctx, "SELECT max(hseq) FROM ctl_pending WHERE destination=? AND hseq>?", dest, cursor).Scan(&top) != nil {
			return errStateInvalid
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return max(cursor, top.Int64), nil
}

func (s *State) Close() error { return s.db.Close() }

type querier interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// tx runs f inside BEGIN IMMEDIATE, so a concurrent CLI writer serializes on
// SQLite's lock instead of failing a deferred upgrade.
func (s *State) tx(ctx context.Context, f func(querier) error) (result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.db.Conn(ctx)
	if err != nil {
		return errStateInvalid
	}
	defer c.Close()
	if _, err = c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return errStateInvalid
	}
	committed := false
	defer func() {
		if !committed {
			if _, err := c.ExecContext(context.Background(), "ROLLBACK"); err != nil && result == nil {
				result = errStateInvalid
			}
		}
	}()
	if err = f(c); err != nil {
		return err
	}
	if _, err = c.ExecContext(ctx, "COMMIT"); err != nil {
		return errStateInvalid
	}
	committed = true
	return nil
}

// PutRule creates a rule or edits it to a new version. An edit cancels every
// pending row queued under the previous version in the same transaction.
func (s *State) PutRule(ctx context.Context, id string, repos, kinds []string, enabled bool) (Rule, error) {
	if !ruleIDPattern.MatchString(id) || len(repos) > 128 || len(kinds) > 2 {
		return Rule{}, ErrRule
	}
	r := Rule{ID: id, Enabled: enabled, Repos: uniqueSorted(repos), Kinds: uniqueSorted(kinds), Profile: record.ProfilePushMetadata}
	for _, repo := range r.Repos {
		if !strings.HasPrefix(repo, "r1:") || !record.IsHex64(strings.TrimPrefix(repo, "r1:")) {
			return Rule{}, ErrRule
		}
	}
	for _, k := range r.Kinds {
		if k != string(record.KindSession) && k != string(record.KindTask) {
			return Rule{}, ErrRule
		}
	}
	err := s.tx(ctx, func(q querier) error {
		var version int64
		err := q.QueryRowContext(ctx, "SELECT version FROM selection_rule WHERE rule_id=?", id).Scan(&version)
		if err != nil && err != sql.ErrNoRows {
			return errStateInvalid
		}
		if version > 0 {
			if err := cancelAuthority(ctx, q, Rule{ID: id, Version: version}.authority(), "rule_changed"); err != nil {
				return err
			}
		}
		r.Version = version + 1
		repoJSON, _ := json.Marshal(r.Repos)
		kindJSON, _ := json.Marshal(r.Kinds)
		_, err = q.ExecContext(ctx, "INSERT INTO selection_rule VALUES(?,?,?,?,?,?) ON CONFLICT(rule_id) DO UPDATE SET version=excluded.version,enabled=excluded.enabled,repos=excluded.repos,kinds=excluded.kinds,profile=excluded.profile", id, r.Version, boolInt(enabled), string(repoJSON), string(kindJSON), r.Profile)
		if err != nil {
			return errStateInvalid
		}
		return nil
	})
	if err != nil {
		return Rule{}, err
	}
	return r, nil
}

// RemoveRule deletes a rule and cancels its pending rows transactionally.
func (s *State) RemoveRule(ctx context.Context, id string) error {
	if !ruleIDPattern.MatchString(id) {
		return ErrRule
	}
	return s.tx(ctx, func(q querier) error {
		var version int64
		err := q.QueryRowContext(ctx, "SELECT version FROM selection_rule WHERE rule_id=?", id).Scan(&version)
		if err == sql.ErrNoRows {
			return ErrRule
		}
		if err != nil {
			return errStateInvalid
		}
		if err := cancelAuthority(ctx, q, Rule{ID: id, Version: version}.authority(), "rule_removed"); err != nil {
			return err
		}
		if _, err := q.ExecContext(ctx, "DELETE FROM selection_rule WHERE rule_id=?", id); err != nil {
			return errStateInvalid
		}
		return nil
	})
}

func (s *State) Rules(ctx context.Context) ([]Rule, error) {
	var out []Rule
	err := s.tx(ctx, func(q querier) error {
		var err error
		out, err = readRules(ctx, q)
		return err
	})
	return out, err
}

func readRules(ctx context.Context, q querier) ([]Rule, error) {
	rows, err := q.QueryContext(ctx, "SELECT rule_id,version,enabled,repos,kinds,profile FROM selection_rule ORDER BY rule_id")
	if err != nil {
		return nil, errStateInvalid
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		var r Rule
		var repos, kinds string
		if rows.Scan(&r.ID, &r.Version, &r.Enabled, &repos, &kinds, &r.Profile) != nil || json.Unmarshal([]byte(repos), &r.Repos) != nil || json.Unmarshal([]byte(kinds), &r.Kinds) != nil {
			return nil, errStateInvalid
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		return nil, errStateInvalid
	}
	return out, nil
}

// cancelAuthority cancels each whole pending operation holding a row queued
// under authority. Sibling rows are re-exported later with fresh seals.
func cancelAuthority(ctx context.Context, q querier, authority, reason string) error {
	rows, err := q.QueryContext(ctx, "SELECT DISTINCT op_id FROM outbox WHERE authority=? AND state=?", authority, statePending)
	if err != nil {
		return errStateInvalid
	}
	var ops []string
	for rows.Next() {
		var op string
		if rows.Scan(&op) != nil {
			rows.Close()
			return errStateInvalid
		}
		ops = append(ops, op)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return errStateInvalid
	}
	return cancelOps(ctx, q, ops, reason)
}

// cancelOps marks pending operations and rows cancelled and drops the queued
// metadata copies. A cancelled row is never retried as new authority.
func cancelOps(ctx context.Context, q querier, ops []string, reason string) error {
	for _, op := range ops {
		if _, err := q.ExecContext(ctx, "UPDATE operation SET state=?,reason=?,raw=x'' WHERE op_id=? AND state=?", stateCancelled, reason, op, statePending); err != nil {
			return errStateInvalid
		}
		if _, err := q.ExecContext(ctx, "UPDATE outbox SET state=?,header=NULL,body=NULL,sigs=NULL WHERE op_id=? AND state=?", stateCancelled, op, statePending); err != nil {
			return errStateInvalid
		}
	}
	return nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func uniqueSorted(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// cursorState is the durable per-destination round state.
type cursorState struct {
	Ctl, Data, Keyset   int64
	AckedCtl, AckedData int64
	BarrierHSeq         int64
	BarrierReason       string
	LastError           string
	LastRound           int64
}

func ensureCursor(ctx context.Context, q querier, dest string) error {
	_, err := q.ExecContext(ctx, "INSERT OR IGNORE INTO sync_state VALUES(?,0,0,0,0,0,0,'','',0)", dest)
	if err != nil {
		return errStateInvalid
	}
	return nil
}

func (s *State) cursors(ctx context.Context, dest string) (cursorState, error) {
	var c cursorState
	err := s.tx(ctx, func(q querier) error {
		if err := ensureCursor(ctx, q, dest); err != nil {
			return err
		}
		if q.QueryRowContext(ctx, "SELECT ctl_cursor,data_cursor,keyset_version,acked_ctl,acked_data,barrier_hseq,barrier_reason,last_error,last_round FROM sync_state WHERE destination=?", dest).Scan(&c.Ctl, &c.Data, &c.Keyset, &c.AckedCtl, &c.AckedData, &c.BarrierHSeq, &c.BarrierReason, &c.LastError, &c.LastRound) != nil {
			return errStateInvalid
		}
		return nil
	})
	return c, err
}

func (s *State) outboxDepth(ctx context.Context, dest string) (int64, error) {
	var n int64
	err := s.tx(ctx, func(q querier) error {
		if q.QueryRowContext(ctx, "SELECT count(*) FROM outbox WHERE destination=? AND state=?", dest, statePending).Scan(&n) != nil {
			return errStateInvalid
		}
		return nil
	})
	return n, err
}

// persistControls stores exact fetched control envelopes. A refetch must be
// byte-identical; a different envelope at the same hseq is a log conflict.
func (s *State) persistControls(ctx context.Context, dest string, items []transport.LogItem) error {
	return s.tx(ctx, func(q querier) error {
		var cursor int64
		if err := ensureCursor(ctx, q, dest); err != nil {
			return err
		}
		if q.QueryRowContext(ctx, "SELECT ctl_cursor FROM sync_state WHERE destination=?", dest).Scan(&cursor) != nil {
			return errStateInvalid
		}
		for _, x := range items {
			if x.HSeq <= cursor {
				continue
			}
			env, err := json.Marshal(x.Envelope)
			if err != nil {
				return errStateInvalid
			}
			var existing []byte
			err = q.QueryRowContext(ctx, "SELECT envelope FROM ctl_pending WHERE destination=? AND hseq=?", dest, x.HSeq).Scan(&existing)
			if err == nil {
				if string(existing) != string(env) {
					return errControlConflict
				}
				continue
			}
			if err != sql.ErrNoRows {
				return errStateInvalid
			}
			var body any
			if x.DecodedBody != nil {
				body = x.DecodedBody
			}
			if _, err = q.ExecContext(ctx, "INSERT INTO ctl_pending VALUES(?,?,?,?,'')", dest, x.HSeq, env, body); err != nil {
				return errStateInvalid
			}
		}
		return nil
	})
}

type pendingControl struct {
	HSeq     int64
	Envelope record.Envelope
	Body     []byte
}

// pendingControls returns fetched controls above both ctl_cursor and the
// in-round position after, in hseq order.
func (s *State) pendingControls(ctx context.Context, dest string, after int64, limit int) ([]pendingControl, error) {
	var out []pendingControl
	err := s.tx(ctx, func(q querier) error {
		rows, err := q.QueryContext(ctx, "SELECT p.hseq,p.envelope,p.body FROM ctl_pending p JOIN sync_state s ON s.destination=p.destination WHERE p.destination=? AND p.hseq>s.ctl_cursor AND p.hseq>? ORDER BY p.hseq LIMIT ?", dest, after, limit)
		if err != nil {
			return errStateInvalid
		}
		defer rows.Close()
		for rows.Next() {
			var c pendingControl
			var env []byte
			if rows.Scan(&c.HSeq, &env, &c.Body) != nil || json.Unmarshal(env, &c.Envelope) != nil {
				return errStateInvalid
			}
			out = append(out, c)
		}
		if rows.Err() != nil {
			return errStateInvalid
		}
		return nil
	})
	return out, err
}

// completeControl advances ctl_cursor over exactly one enforced control. It
// refuses a gap: no earlier fetched control may remain above the cursor.
func (s *State) completeControl(ctx context.Context, dest string, hseq int64) error {
	return s.tx(ctx, func(q querier) error {
		var cursor, earlier int64
		if q.QueryRowContext(ctx, "SELECT ctl_cursor FROM sync_state WHERE destination=?", dest).Scan(&cursor) != nil {
			return errStateInvalid
		}
		if q.QueryRowContext(ctx, "SELECT count(*) FROM ctl_pending WHERE destination=? AND hseq>? AND hseq<?", dest, cursor, hseq).Scan(&earlier) != nil {
			return errStateInvalid
		}
		if hseq <= cursor || earlier != 0 {
			return errStateInvalid
		}
		if _, err := q.ExecContext(ctx, "DELETE FROM ctl_pending WHERE destination=? AND hseq=?", dest, hseq); err != nil {
			return errStateInvalid
		}
		if _, err := q.ExecContext(ctx, "UPDATE sync_state SET ctl_cursor=?,barrier_hseq=0,barrier_reason='' WHERE destination=?", hseq, dest); err != nil {
			return errStateInvalid
		}
		return nil
	})
}

// stageControl marks a fetched control as held in the verification-only view.
// Its exact envelope stays in ctl_pending; the cursor and barrier do not move.
func (s *State) stageControl(ctx context.Context, dest string, hseq int64) error {
	return s.tx(ctx, func(q querier) error {
		if _, err := q.ExecContext(ctx, "UPDATE ctl_pending SET reason='staged' WHERE destination=? AND hseq=?", dest, hseq); err != nil {
			return errStateInvalid
		}
		return nil
	})
}

func (s *State) blockControl(ctx context.Context, dest string, hseq int64, reason string) error {
	return s.tx(ctx, func(q querier) error {
		if _, err := q.ExecContext(ctx, "UPDATE ctl_pending SET reason=? WHERE destination=? AND hseq=?", reason, dest, hseq); err != nil {
			return errStateInvalid
		}
		if _, err := q.ExecContext(ctx, "UPDATE sync_state SET barrier_hseq=?,barrier_reason=? WHERE destination=?", hseq, reason, dest); err != nil {
			return errStateInvalid
		}
		return nil
	})
}

// applyData quarantines a page of hosted data and advances data_cursor to the
// page watermark in the same transaction. v1 imports no hosted-origin data.
// An item at or below the cursor is a replay and is never stored again; every
// other item is stored only when no persistent fence and no store tomb or ban
// invalidates it or anything it depends on. A dropped item becomes a fence,
// and any quarantined copy that depends on it is deleted in the same
// transaction. It reports how many already quarantined copies were deleted.
func (s *State) applyData(ctx context.Context, dest string, items []transport.LogItem, next int64, check storeCheck) (int, error) {
	purged := 0
	err := s.tx(ctx, func(q querier) error {
		var cursor int64
		if q.QueryRowContext(ctx, "SELECT data_cursor FROM sync_state WHERE destination=?", dest).Scan(&cursor) != nil {
			return errStateInvalid
		}
		if next < cursor {
			return errStateInvalid
		}
		dropped := false
		for _, x := range items {
			if x.HSeq <= cursor {
				continue
			}
			env, err := json.Marshal(x.Envelope)
			if err != nil {
				return errStateInvalid
			}
			keep, err := admit(ctx, q, x.Envelope, check)
			if err != nil {
				return err
			}
			if !keep {
				dropped = true
				continue
			}
			if _, err = q.ExecContext(ctx, "INSERT OR IGNORE INTO data_quarantine VALUES(?,?,?)", dest, x.HSeq, env); err != nil {
				return errStateInvalid
			}
		}
		if dropped {
			// A dropped item may be the ancestor of a copy stored earlier.
			n, err := sweepQuarantine(ctx, q, check)
			if err != nil {
				return err
			}
			purged = n
		}
		if _, err := q.ExecContext(ctx, "UPDATE sync_state SET data_cursor=? WHERE destination=?", next, dest); err != nil {
			return errStateInvalid
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return purged, nil
}

func (s *State) recordAck(ctx context.Context, dest string, a transport.Ack) error {
	return s.tx(ctx, func(q querier) error {
		if _, err := q.ExecContext(ctx, "UPDATE sync_state SET acked_ctl=?,acked_data=? WHERE destination=?", a.CtlEnforcedThrough, a.DataAppliedThrough, dest); err != nil {
			return errStateInvalid
		}
		return nil
	})
}

func (s *State) recordKeyset(ctx context.Context, dest string, v int64) error {
	return s.tx(ctx, func(q querier) error {
		if _, err := q.ExecContext(ctx, "UPDATE sync_state SET keyset_version=? WHERE destination=?", v, dest); err != nil {
			return errStateInvalid
		}
		return nil
	})
}

func (s *State) recordRound(ctx context.Context, dest, failure string) error {
	return s.tx(ctx, func(q querier) error {
		if err := ensureCursor(ctx, q, dest); err != nil {
			return err
		}
		if _, err := q.ExecContext(ctx, "UPDATE sync_state SET last_error=?,last_round=? WHERE destination=?", failure, s.now().UnixMilli(), dest); err != nil {
			return errStateInvalid
		}
		return nil
	})
}

// rejectOp records a hosted refusal of a whole operation. Rejected sources are
// not re-exported automatically, so a deterministic refusal cannot loop.
func (s *State) rejectOp(ctx context.Context, dest, op, reason string) error {
	return s.tx(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, "UPDATE operation SET state=?,reason=?,raw=x'' WHERE op_id=? AND destination=? AND state=?", stateRejected, reason, op, dest, statePending)
		if err != nil {
			return errStateInvalid
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return errStateInvalid
		}
		if _, err = q.ExecContext(ctx, "UPDATE outbox SET state=?,body=NULL,sigs=NULL WHERE op_id=? AND state=?", stateRejected, op, statePending); err != nil {
			return errStateInvalid
		}
		return nil
	})
}

// cancelAll cancels every pending operation for a destination.
func (s *State) cancelAll(ctx context.Context, dest, reason string) error {
	return s.tx(ctx, func(q querier) error {
		ops, err := pendingOps(ctx, q, dest)
		if err != nil {
			return err
		}
		return cancelOps(ctx, q, ops, reason)
	})
}

func pendingOps(ctx context.Context, q querier, dest string) ([]string, error) {
	rows, err := q.QueryContext(ctx, "SELECT op_id FROM operation WHERE destination=? AND state=?", dest, statePending)
	if err != nil {
		return nil, errStateInvalid
	}
	defer rows.Close()
	var ops []string
	for rows.Next() {
		var op string
		if rows.Scan(&op) != nil {
			return nil, errStateInvalid
		}
		ops = append(ops, op)
	}
	if rows.Err() != nil {
		return nil, errStateInvalid
	}
	return ops, nil
}

// purgeDestination cancels the queue and removes cursors, fetched controls and
// quarantined data for one destination. Verified receipts and the persistent
// quarantine fences are retained.
func (s *State) purgeDestination(ctx context.Context, dest string) error {
	return s.tx(ctx, func(q querier) error {
		ops, err := pendingOps(ctx, q, dest)
		if err != nil {
			return err
		}
		if err = cancelOps(ctx, q, ops, "logout"); err != nil {
			return err
		}
		for _, stmt := range []string{"DELETE FROM ctl_pending WHERE destination=?", "DELETE FROM data_quarantine WHERE destination=?", "DELETE FROM quarantine_scrub WHERE destination=?", "DELETE FROM sync_state WHERE destination=?", "UPDATE outbox SET header=NULL,body=NULL,sigs=NULL WHERE destination=?"} {
			if _, err = q.ExecContext(ctx, stmt, dest); err != nil {
				return errStateInvalid
			}
		}
		return nil
	})
}
