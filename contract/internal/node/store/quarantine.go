package store

import (
	"context"

	"github.com/Telara-Labs/telara-memory/contract/invalidate"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// QuarantineInvalidated reports whether any named ID has a durable tomb or
// lineage hold, including IDs whose envelopes have never arrived here.
// Snapshot enumerates stored records and therefore cannot answer this query
// for an absent target of a local erasure.
func (s *Store) QuarantineInvalidated(ctx context.Context, ids []string) (bool, error) {
	if len(ids) == 0 || len(ids) > 8192 {
		return true, failure("invalid_request")
	}
	for _, id := range ids {
		if !record.IsHex64(id) {
			return true, failure("invalid_request")
		}
	}
	invalid := true
	err := s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked {
			return d.blockedError()
		}
		for _, id := range ids {
			if len(d.eval.Causes[id]) > 0 || len(d.eval.HoldCauses[id]) > 0 {
				return nil
			}
			if x := d.byID[id]; x != nil && x.state != string(invalidate.Live) {
				return nil
			}
		}
		invalid = false
		return nil
	})
	return invalid, err
}
