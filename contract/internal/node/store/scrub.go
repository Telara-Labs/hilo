package store

import (
	"context"
	"os"
)

// Scrub retries the durable post-commit job. A busy reader never produces a clean receipt.
func (s *Store) Scrub(ctx context.Context, controlID string) (ScrubResult, error) {
	out := ScrubResult{ControlID: controlID, State: "pending"}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned {
		return out, failure("unavailable")
	}
	if s.closed {
		return out, failure("closed")
	}
	if _, err := s.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return out, failure("storage_error")
	}
	begun := true
	s.reductions = newReductionContext()
	defer func() { s.reductions = nil }()
	defer func() {
		if begun {
			s.conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	// A cached pending table is not proof that recovered signed controls have
	// complete event coverage. Recompute before either checkpoint or clean receipt.
	d, err := s.load(ctx)
	if err != nil {
		return out, err
	}
	if !d.projectionBlocked {
		if err = s.persistErasurePending(ctx, d); err != nil {
			return out, err
		}
	}
	var held int
	if s.conn.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM privacy_barrier WHERE owner=?)+(SELECT count(*) FROM projection_hold)+(SELECT count(*) FROM erasure_pending)", s.opts.PinnedGenesisID).Scan(&held) != nil {
		return out, failure("storage_error")
	}
	if held > 0 || d.blocked {
		out.State = "blocked"
		if _, err = s.conn.ExecContext(ctx, "COMMIT"); err != nil {
			return out, failure("storage_error")
		}
		begun = false
		return out, nil
	}
	// An in-flight bundle export carrying erased content keeps the erasure
	// pending until its staging copy is destroyed.
	exportPending, err := s.reconcileBundleExports(ctx, d)
	if err != nil {
		return out, err
	}
	if exportPending {
		if _, err = s.conn.ExecContext(ctx, "COMMIT"); err != nil {
			return out, failure("storage_error")
		}
		begun = false
		return out, nil
	}
	sidecarsClean, err := s.scrubSyncCopies(ctx, d)
	if err != nil {
		return out, err
	}
	if !sidecarsClean {
		if _, err = s.conn.ExecContext(ctx, "COMMIT"); err != nil {
			return out, failure("storage_error")
		}
		begun = false
		return out, nil
	}
	var captured int64
	var jobState string
	if s.conn.QueryRowContext(ctx, "SELECT generation FROM meta WHERE singleton=1").Scan(&captured) != nil {
		return out, failure("storage_error")
	}
	if s.conn.QueryRowContext(ctx, "SELECT state FROM scrub_job WHERE control=?", controlID).Scan(&jobState) != nil {
		return out, failure("unknown_scrub")
	}
	if _, err := s.conn.ExecContext(ctx, "UPDATE scrub_job SET state='pending',attempts=attempts+1 WHERE control=?", controlID); err != nil {
		return out, failure("storage_error")
	}
	if _, err := s.conn.ExecContext(ctx, "COMMIT"); err != nil {
		return out, failure("storage_error")
	}
	begun = false
	checkpoint := func() (bool, error) {
		var busy, log, done int
		if err := s.conn.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done); err != nil {
			return false, failure("storage_error")
		}
		return busy == 0 && log == 0 && done == 0, nil
	}
	ok, err := checkpoint()
	if err != nil {
		return out, err
	}
	if !ok {
		return out, nil
	}
	if _, err = s.conn.ExecContext(ctx, "PRAGMA incremental_vacuum"); err != nil {
		return out, failure("storage_error")
	}
	ok, err = checkpoint()
	if err != nil {
		return out, err
	}
	if !ok {
		return out, nil
	}
	if _, err = s.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return out, failure("storage_error")
	}
	begun = true
	var current int64
	if s.conn.QueryRowContext(ctx, "SELECT generation FROM meta WHERE singleton=1").Scan(&current) != nil {
		return out, failure("storage_error")
	}
	if current != captured {
		return out, nil
	}
	if err = s.secureFiles(); err != nil {
		return out, err
	}
	info, err := os.Stat(s.path + "-wal")
	if err != nil && !os.IsNotExist(err) {
		return out, failure("storage_error")
	}
	if err == nil && info.Size() != 0 {
		return out, nil
	}
	if _, err = s.conn.ExecContext(ctx, "UPDATE scrub_job SET state='complete',target_generation=? WHERE control=?", captured, controlID); err != nil {
		return out, failure("storage_error")
	}
	if _, err = s.conn.ExecContext(ctx, "COMMIT"); err != nil {
		return out, failure("storage_error")
	}
	begun = false
	out.State = "complete"
	out.Generation = captured
	return out, nil
}
