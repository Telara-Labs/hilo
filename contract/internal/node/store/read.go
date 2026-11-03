package store

import (
	"context"
	"github.com/Telara-Labs/hilo/contract/invalidate"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
	"math"
)

// Snapshot is inspection only. It neither renders a model response nor records delivery.
func (s *Store) Snapshot(ctx context.Context, q ReadRequest) (Snapshot, error) {
	var out Snapshot
	if len(q.IDs) > 8192 {
		return out, failure("invalid_request")
	}
	ids := map[string]bool{}
	for _, id := range q.IDs {
		if !record.IsHex64(id) {
			return out, failure("invalid_request")
		}
		ids[id] = true
	}
	err := s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked {
			return d.blockedError()
		}
		out.Generation = d.generation
		out.Entries = []Entry{}
		for _, x := range d.records {
			if len(ids) > 0 && !ids[x.rec.ID] {
				continue
			}
			e := Entry{ID: x.rec.ID, Owner: x.owner, Sequence: x.seq, Generation: x.generation, State: x.state, SignatureStatus: string(x.sigStatus)}
			e.HeaderJCS = append([]byte(nil), x.rec.HeaderJCS...)
			e.Sigs = append([]record.Signature(nil), x.sigs...)
			e.AdvisoryID = x.rec.ID
			if x.state == string(invalidate.Live) && x.sigStatus == sig.StatusVerified && d.policyReadAllowed(x) {
				e.BodyJCS = append([]byte(nil), x.rec.BodyJCS...)
			}
			if x.rec.Header.Subj.TaskID != "" {
				e.TaskStatus = d.taskStatus(x.owner, x.rec.Header.Subj.TaskID)
			}
			out.Entries = append(out.Entries, e)
		}
		return nil
	})
	return out, err
}

// Suppressed is a pre-capture check; append rechecks all fences atomically.
func (s *Store) Suppressed(ctx context.Context, q SourceOccurrence) (Suppression, error) {
	var out Suppression
	if (q.Source == "" && q.SessionKey == "" && len(q.EventIDs) == 0) || q.Owner != s.opts.PinnedGenesisID || q.SessionKey != "" && !record.IsSessionKey(q.SessionKey) || q.Source != "" && !record.IsHex64(q.Source) {
		return out, failure("invalid_request")
	}
	if len(q.EventIDs) > 4096 {
		return out, failure("invalid_request")
	}
	for _, id := range q.EventIDs {
		if !record.IsEventID(id) {
			return out, failure("invalid_request")
		}
	}
	err := s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked {
			out.Suppressed = true
			out.OwnerBlocked = true
			return nil
		}
		for _, x := range d.records {
			if x.owner != q.Owner {
				continue
			}
			match := q.Source != "" && x.rec.Header.Subj.Source == q.Source || q.SessionKey != "" && x.rec.Header.Subj.SessionKey == q.SessionKey
			if !match {
				continue
			}
			for _, c := range d.eval.Causes[x.rec.ID] {
				if c.Kind == invalidate.Erased {
					out.Suppressed = true
				}
			}
		}
		if q.SessionKey != "" && signedSessionBan(d, q.Owner, q.SessionKey) {
			out.Suppressed = true
		}
		if q.SessionKey != "" {
			var n int
			if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM event_ban WHERE owner=? AND session=?", q.Owner, q.SessionKey).Scan(&n) != nil {
				return failure("storage_error")
			}
			if n > 0 {
				out.Suppressed = true
			}
		}
		for _, id := range q.EventIDs {
			var n int
			if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM event_ban WHERE owner=? AND session=? AND event_id=?", q.Owner, q.SessionKey, id).Scan(&n) != nil {
				return failure("storage_error")
			}
			if n > 0 {
				out.Suppressed = true
			}
		}
		return nil
	})
	return out, err
}

// Reindex replaces only disposable projections. Security truth is never truncated.
func (s *Store) Reindex(ctx context.Context) error {
	return s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked {
			return d.blockedError()
		}
		if _, err = s.effectDelta(ctx, d); err != nil {
			return err
		}
		if d.generation == math.MaxInt64 {
			return failure("ordinal_limit")
		}
		if err = d.prepareRelations(); err != nil {
			return s.refuseVerified(ctx, d, err)
		}
		d.generation++
		if _, err = s.conn.ExecContext(ctx, "UPDATE meta SET generation=? WHERE singleton=1", d.generation); err != nil {
			return failure("storage_error")
		}
		return s.persistState(ctx, d)
	})
}

// PublishProjection admits a fixed-size local vector only at its exact live generation.
func (s *Store) PublishProjection(ctx context.Context, t JobToken, p Projection) error {
	if !record.IsHex64(t.RecordID) || t.Generation <= 0 || len(p.Vector) != 256 || len(p.Model) == 0 || len(p.Model) > 128 {
		return failure("invalid_projection")
	}
	for _, c := range []byte(p.Model) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return failure("invalid_projection")
		}
	}
	vector := append([]byte(nil), p.Vector...)
	return s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked {
			return d.blockedError()
		}
		if d.generation == math.MaxInt64 {
			return failure("ordinal_limit")
		}
		x := d.byID[t.RecordID]
		if x == nil || x.generation != t.Generation || x.state != string(invalidate.Live) || x.sigStatus != sig.StatusVerified || x.rec.Body == nil || len(freshFields(d, x.rec.ID)) == 0 {
			return failure("stale_projection")
		}
		var n int
		if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_job WHERE id=? AND generation=?", t.RecordID, t.Generation).Scan(&n) != nil {
			return failure("storage_error")
		}
		if n != 1 {
			return failure("stale_projection")
		}
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO vector VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,model=excluded.model,value=excluded.value", t.RecordID, t.Generation, p.Model, vector); err != nil {
			return failure("storage_error")
		}
		if _, err = s.conn.ExecContext(ctx, "DELETE FROM projection_job WHERE id=?", t.RecordID); err != nil {
			return failure("storage_error")
		}
		if _, err = s.conn.ExecContext(ctx, "UPDATE meta SET generation=generation+1 WHERE singleton=1"); err != nil {
			return failure("storage_error")
		}
		return nil
	})
}
