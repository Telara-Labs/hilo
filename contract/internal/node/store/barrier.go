package store

import (
	"context"
	"github.com/Telara-Labs/telara-memory/contract/invalidate"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"math"
	"sort"
	"strings"
)

type bulkLimit struct{ cause string }

func (*bulkLimit) Error() string { return "bulk_confirmation_required" }

type postCommitRefusal struct{ err error }

func (p *postCommitRefusal) Error() string { return p.err.Error() }
func ownerBlocked() error                  { return &Error{Code: "bulk_confirmation_required", OwnerBlocked: true} }

// Only an already accepted cause newly reaching previously available bodies may
// commit this metadata-only exception to ordinary no-mutation bulk refusal.
func (s *Store) refuseBulk(ctx context.Context, d *databaseState, err error) error {
	b, ok := err.(*bulkLimit)
	if !ok {
		return err
	}
	if b.cause == "" {
		return failure("bulk_confirmation_required")
	}
	return s.commitPrivacyBarrier(ctx, b.cause, "bulk_confirmation_required", "bulk_confirmation_required")
}

// A producer's refused valid batch must not forget a newly verified relationship
// between existing live bodies and an already accepted erasure.
func lateErasureCause(d *databaseState) string {
	causes := map[string]bool{}
	for id, cs := range d.eval.Causes {
		x := d.byID[id]
		if x == nil || !x.persisted || !x.previousLive || x.rec.Header.Type.IsControl() {
			continue
		}
		for _, c := range cs {
			control := d.byID[c.Cause]
			if c.Kind == invalidate.Erased && control != nil && control.persisted && control.rec.Header.Type == record.KindErasure {
				causes[c.Cause] = true
			}
		}
	}
	for id, tokens := range d.eval.HoldCauses {
		x := d.byID[id]
		if x == nil || !x.persisted || !x.previousLive || x.rec.Header.Type.IsControl() {
			continue
		}
		for _, token := range tokens {
			parts := strings.Split(token, "/")
			if len(parts) != 2 {
				continue
			}
			c := d.byID[parts[1]]
			if c != nil && c.persisted && c.rec.Header.Type == record.KindErasure {
				causes[c.rec.ID] = true
			}
		}
	}
	ids := make([]string, 0, len(causes))
	for id := range causes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}
func (s *Store) commitPrivacyBarrier(ctx context.Context, cause, reason, code string) error {
	var generation int64
	if s.conn.QueryRowContext(ctx, "SELECT generation FROM meta WHERE singleton=1").Scan(&generation) != nil {
		return failure("storage_error")
	}
	if generation == math.MaxInt64 {
		s.poisoned = true
		return failure("unavailable")
	}
	s.barrierAttempt = true
	if _, e := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO privacy_barrier VALUES(?,?,?,?)", s.opts.PinnedGenesisID, cause, reason, generation+1); e != nil {
		s.poisoned = true
		return failure("unavailable")
	}
	if _, e := s.conn.ExecContext(ctx, "UPDATE meta SET generation=generation+1 WHERE singleton=1"); e != nil {
		s.poisoned = true
		return failure("unavailable")
	}
	if _, e := s.conn.ExecContext(ctx, "DELETE FROM projection_job"); e != nil {
		s.poisoned = true
		return failure("unavailable")
	}
	if _, e := s.conn.ExecContext(ctx, "DELETE FROM render_body"); e != nil {
		s.poisoned = true
		return failure("unavailable")
	}
	return &postCommitRefusal{err: &Error{Code: code, OwnerBlocked: true}}
}

func (d *databaseState) blockedError() error {
	if d.projectionBlocked {
		return &Error{Code: "lineage_evaluation_required", OwnerBlocked: true}
	}
	return ownerBlocked()
}
