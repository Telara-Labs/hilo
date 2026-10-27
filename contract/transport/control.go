package transport

import (
	"errors"
	"github.com/Telara-Labs/hilo/contract/record"
)

type ControlDecision struct {
	Verified            bool
	Complete            bool
	CoveragePending     bool // ONLY recognized erasure supplemental coverage
	RestrictionsApplied bool
}

// ControlProgress separates the in-round scan watermark from the durable
// completed-prefix cursor. The adapter persists exact pending envelopes and
// restrictive effects atomically. Verification-only authority never grants data.
type ControlProgress struct {
	Cursor, Scan int64
	pending      []LogItem
}

func NewControlProgress(cursor int64) *ControlProgress {
	return &ControlProgress{Cursor: cursor, Scan: cursor}
}
func (c *ControlProgress) Pending() []LogItem { return append([]LogItem(nil), c.pending...) }
func (c *ControlProgress) Stage(p Page, through int64) error {
	if p.NextAfter != p.ScannedThrough || p.NextAfter < c.Scan || p.NextAfter > through || p.More && p.NextAfter == through {
		return errors.New("invalid control scan watermark")
	}
	last := c.Scan
	for _, x := range p.Items {
		if x.Class != "control" || x.HSeq <= last || x.HSeq > p.ScannedThrough {
			return errors.New("invalid control order")
		}
		last = x.HSeq
	}
	c.pending = append(c.pending, p.Items...)
	c.Scan = p.NextAfter
	return nil
}

// Enforce's verifier must start from completed authority and replay every
// intervening exact control into a separate verification-only view while fenced.
// A staged key cannot validate itself. Unknown/invalid controls are barriers.
// Returning true means data may proceed. No ACK ever uses Scan.
func (c *ControlProgress) Enforce(verify func(LogItem, bool) ControlDecision) bool {
	for len(c.pending) > 0 {
		first := c.pending[0]
		r, err := CheckEnvelope(first.Envelope, first.DecodedBody)
		if err != nil || r.Body == nil || !r.Header.Type.IsControl() {
			return false
		}
		d := verify(first, false)
		if !d.Verified || !d.RestrictionsApplied {
			return false
		}
		if d.Complete {
			c.Cursor = first.HSeq
			c.pending = c.pending[1:]
			continue
		}
		if !d.CoveragePending || !isControlKind(first, record.KindErasure) {
			return false
		}
		progressed := false
		for _, later := range c.pending[1:] {
			// Require exact recognized versions/schema BEFORE any staged effect.
			r, err := CheckEnvelope(later.Envelope, later.DecodedBody)
			if err != nil || r.Body == nil || !r.Header.Type.IsControl() {
				return false
			}
			switch r.Header.Type {
			case record.KindErasure, record.KindRetraction, record.KindWithdrawal, record.KindPolicy, record.KindKeyOp:
			default:
				return false
			}
			staged := verify(later, true)
			if !staged.Verified || !staged.RestrictionsApplied {
				return false
			}
			if isControlKind(later, record.KindErasure) && staged.Complete {
				retry := verify(first, false)
				if retry.Verified && retry.RestrictionsApplied && retry.Complete {
					progressed = true
					break
				}
			}
		}
		if !progressed {
			return false
		}
		// Complete through the normal order, revalidating every staged control.
	}
	if c.Scan > c.Cursor {
		c.Cursor = c.Scan
	}
	return true
}
func isControlKind(x LogItem, kind record.Kind) bool {
	r, err := CheckEnvelope(x.Envelope, x.DecodedBody)
	return err == nil && r.Body != nil && r.Header.Type == kind
}
