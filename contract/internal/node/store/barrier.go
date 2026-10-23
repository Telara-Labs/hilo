package store

import "context"

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
	s.barrierAttempt = true
	if _, e := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO privacy_barrier VALUES(?,?,'bulk_confirmation_required',?)", s.opts.PinnedGenesisID, b.cause, d.generation+1); e != nil {
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
	return &postCommitRefusal{err: ownerBlocked()}
}
