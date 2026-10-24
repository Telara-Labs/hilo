package store

import "context"

func (s *Store) recoverV3(ctx context.Context, d *databaseState) error {
	purge := false
	for _, x := range d.records {
		if x.state == "invalidated" && x.rec.Body != nil {
			purge = true
		}
		// Signed wire ancestry is reconstructed without deleting unrelated caches,
		// changing generation, or manufacturing positive completeness facts.
		for _, id := range x.deps {
			if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO dep VALUES(?,?)", x.rec.ID, id); err != nil {
				return failure("storage_error")
			}
		}
	}
	if purge {
		return s.persistState(ctx, d)
	}
	return s.persistErasurePending(ctx, d)
}
