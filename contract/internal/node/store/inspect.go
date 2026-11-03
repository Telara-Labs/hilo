package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"time"

	"github.com/Telara-Labs/hilo/contract/policy"
)

// PolicyDiagnostics is the installed tenant policy state. It carries ids,
// sequence numbers and switch states only, never policy text or keys.
type PolicyDiagnostics struct {
	Installed      bool   `json:"installed"`
	Tenant         string `json:"tenant,omitempty"`
	Seq            int64  `json:"seq,omitempty"`
	Freshness      string `json:"freshness"`
	Stale          bool   `json:"stale"`
	FailClosed     bool   `json:"fail_closed"`
	KillSync       bool   `json:"kill_sync"`
	KillWithdraw   bool   `json:"kill_withdraw_pulled"`
	KillCapture    bool   `json:"kill_capture_tenant_repos"`
	DataPush       bool   `json:"data_push"`
	DataPull       bool   `json:"data_pull"`
	Tampered       bool   `json:"tampered"`
	ClockRollback  bool   `json:"clock_rollback"`
	LoggedOut      int64  `json:"logged_out_policies"`
	Equivocations  int64  `json:"equivocations"`
	EvaluationCode string `json:"evaluation_error,omitempty"`
}

// ScrubJob is one durable post-commit physical scrub job.
type ScrubJob struct {
	Control  string `json:"control"`
	State    string `json:"state"`
	Attempts int64  `json:"attempts"`
}

// ScrubDiagnostics reports physical scrub progress and the holds that block it.
type ScrubDiagnostics struct {
	Pending         int64      `json:"pending"`
	Complete        int64      `json:"complete"`
	Jobs            []ScrubJob `json:"jobs"`
	ErasurePending  int64      `json:"erasure_pending"`
	PrivacyBarriers int64      `json:"privacy_barriers"`
	ProjectionHolds int64      `json:"projection_holds"`
	WALBytes        int64      `json:"wal_bytes"`
}

// Diagnostics is a content-free read of the store's operational state.
type Diagnostics struct {
	Generation     int64             `json:"generation"`
	Records        int64             `json:"records"`
	SignatureState map[string]int64  `json:"signature_states"`
	SigningBacklog int64             `json:"signing_backlog"`
	Policy         PolicyDiagnostics `json:"policy"`
	Scrub          ScrubDiagnostics  `json:"scrub"`
	// SpoolGaps counts hook hints acknowledged as capture gaps, keyed
	// "client:code". Codes are fixed refusal codes, never source text.
	SpoolGaps map[string]int64 `json:"spool_gaps"`
}

// ErrNoDatabase reports that no store has been created in the directory.
var ErrNoDatabase = failure("no_database")

// Inspect opens the store file read-only and reports counts and states. It
// never creates, migrates, checkpoints or writes the database or its -wal and
// -shm files, and it does not require the writer lock, so it works with or
// without a running daemon.
func Inspect(ctx context.Context, dir string) (Diagnostics, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return emptyDiagnostics(), failure("unsafe_path")
	}
	path := filepath.Join(abs, "memory.sqlite")
	if _, err = os.Lstat(path); os.IsNotExist(err) {
		return emptyDiagnostics(), ErrNoDatabase
	} else if err != nil {
		return emptyDiagnostics(), failure("storage_error")
	}
	// A read-only connection to a WAL database still creates the -wal and
	// -shm files when they are absent. Without either there is no live
	// writer state outside the main file, so it is read as immutable and
	// nothing is created. With both present a writer's log and index already
	// exist and are only read, so a live WAL is seen. A WAL without its index,
	// or an index without its WAL, cannot be read without creating the other.
	// A writer that starts during an immutable read may have changed what it
	// read, so the read is repeated through the writer's log and index.
	for attempt := 0; ; attempt++ {
		walInfo, walErr := os.Lstat(path + "-wal")
		_, shmErr := os.Lstat(path + "-shm")
		switch {
		case os.IsNotExist(walErr) && os.IsNotExist(shmErr):
			out, err := inspectFile(ctx, path, "mode=ro&immutable=1", 0)
			if _, walErr = os.Lstat(path + "-wal"); os.IsNotExist(walErr) || attempt > 0 {
				return out, err
			}
		case walErr != nil || shmErr != nil:
			return emptyDiagnostics(), failure("wal_index_missing")
		default:
			return inspectFile(ctx, path, "mode=ro", walInfo.Size())
		}
	}
}

func emptyDiagnostics() Diagnostics {
	return Diagnostics{SignatureState: map[string]int64{}, Scrub: ScrubDiagnostics{Jobs: []ScrubJob{}}, SpoolGaps: map[string]int64{}}
}

// inspectFile reads one consistent snapshot of the store file opened with
// the given read-only query.
func inspectFile(ctx context.Context, path, query string, walBytes int64) (Diagnostics, error) {
	out := emptyDiagnostics()
	out.Scrub.WALBytes = walBytes
	db, err := sql.Open("sqlite", SQLiteURI(path, query))
	if err != nil {
		return out, failure("storage_error")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return out, failure("storage_error")
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "PRAGMA query_only=1"); err != nil {
		return out, failure("storage_error")
	}
	// One read transaction gives a consistent snapshot of every count.
	if _, err = conn.ExecContext(ctx, "BEGIN"); err != nil {
		return out, failure("storage_error")
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	var genesis string
	if conn.QueryRowContext(ctx, "SELECT generation,genesis FROM meta WHERE singleton=1").Scan(&out.Generation, &genesis) != nil {
		return out, failure("incompatible_database")
	}
	rows, err := conn.QueryContext(ctx, "SELECT sig_status,count(*) FROM record GROUP BY sig_status")
	if err != nil {
		return out, failure("storage_error")
	}
	for rows.Next() {
		var state string
		var n int64
		if rows.Scan(&state, &n) != nil {
			rows.Close()
			return out, failure("storage_error")
		}
		out.SignatureState[state] = n
		out.Records += n
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, failure("storage_error")
	}
	out.SigningBacklog = out.SignatureState["unsigned-local"]
	for q, dst := range map[string]*int64{
		"SELECT count(*) FROM scrub_job WHERE state!='complete'": &out.Scrub.Pending,
		"SELECT count(*) FROM scrub_job WHERE state='complete'":  &out.Scrub.Complete,
		"SELECT count(*) FROM erasure_pending":                   &out.Scrub.ErasurePending,
		"SELECT count(*) FROM privacy_barrier":                   &out.Scrub.PrivacyBarriers,
		"SELECT count(*) FROM projection_hold":                   &out.Scrub.ProjectionHolds,
		"SELECT count(*) FROM policy_logout":                     &out.Policy.LoggedOut,
		"SELECT count(*) FROM policy_equivocation":               &out.Policy.Equivocations,
	} {
		if conn.QueryRowContext(ctx, q).Scan(dst) != nil {
			return out, failure("storage_error")
		}
	}
	jobs, err := conn.QueryContext(ctx, "SELECT control,state,attempts FROM scrub_job WHERE state!='complete' ORDER BY control LIMIT 64")
	if err != nil {
		return out, failure("storage_error")
	}
	for jobs.Next() {
		var j ScrubJob
		if jobs.Scan(&j.Control, &j.State, &j.Attempts) != nil {
			jobs.Close()
			return out, failure("storage_error")
		}
		out.Scrub.Jobs = append(out.Scrub.Jobs, j)
	}
	err = jobs.Err()
	jobs.Close()
	if err != nil {
		return out, failure("storage_error")
	}
	if err = inspectSpoolGaps(ctx, conn, out.SpoolGaps); err != nil {
		return out, err
	}
	out.Policy = inspectPolicy(ctx, conn, genesis, out.Policy)
	return out, nil
}

// inspectSpoolGaps reads gap receipts only. A database created before gap
// receipts existed has no table and therefore no gaps; Inspect never migrates.
func inspectSpoolGaps(ctx context.Context, conn *sql.Conn, out map[string]int64) error {
	var n int
	if conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='spool_gap'").Scan(&n) != nil {
		return failure("storage_error")
	}
	if n == 0 {
		return nil
	}
	rows, err := conn.QueryContext(ctx, "SELECT client,code,count(*) FROM spool_gap GROUP BY client,code ORDER BY client,code LIMIT 256")
	if err != nil {
		return failure("storage_error")
	}
	defer rows.Close()
	for rows.Next() {
		var client, code string
		var count int64
		if rows.Scan(&client, &code, &count) != nil {
			return failure("storage_error")
		}
		out[client+":"+code] = count
	}
	if rows.Err() != nil {
		return failure("storage_error")
	}
	return nil
}

// inspectPolicy evaluates the installed chain exactly as admission does, with
// a clock restored from the persisted floor instead of the persisting clock.
func inspectPolicy(ctx context.Context, conn *sql.Conn, genesis string, p PolicyDiagnostics) PolicyDiagnostics {
	p.Freshness = string(policy.NoPolicy)
	var rollback bool
	if conn.QueryRowContext(ctx, "SELECT rollback FROM trusted_time WHERE singleton=1").Scan(&rollback) == nil {
		p.ClockRollback = rollback
	}
	ro := &Store{conn: conn, opts: Options{PinnedGenesisID: genesis}}
	t, err := ro.tenantWith(ctx, func(ctx context.Context) (*policy.Clock, error) {
		var floor int64
		if conn.QueryRowContext(ctx, "SELECT floor FROM trusted_time WHERE singleton=1").Scan(&floor) != nil {
			return nil, failure("storage_error")
		}
		c := policy.RestoreClock(floor)
		c.Now(time.Now().UnixMilli(), 0)
		return c, nil
	})
	if err != nil {
		p.EvaluationCode = Code(err)
		p.FailClosed = true
		return p
	}
	if t == nil {
		return p
	}
	p.Installed = true
	p.Tenant = t.tenant
	p.Seq = t.chain.HighestSeq
	p.Tampered = t.chain.Tampered
	p.Freshness = string(t.freshness)
	p.Stale = t.freshness != policy.Fresh
	p.FailClosed = t.freshness != policy.Fresh && t.freshness != policy.RefreshDue
	p.DataPush, p.DataPull = t.effects.DataPush, t.effects.DataPull
	if b := t.body(); b != nil {
		p.KillSync, p.KillWithdraw, p.KillCapture = b.Kill.Sync, b.Kill.WithdrawPulled, b.Kill.CaptureTenantRepos
	}
	return p
}
