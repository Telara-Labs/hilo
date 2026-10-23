// Package replay models mutation idempotency separately from rendered disclosure
// and confirmed delivery. The adapter persists these changes atomically with writes.
package replay

import (
	"errors"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

const Unavailable = "The operation was recorded, but its prior memory content is no longer available to this caller."

var ErrConflict = errors.New("op_conflict")

type Outcome struct {
	Tool, ArgsHash, Text, RenderVersion string
	RecordIDs                           []string
}
type Cache struct{ rows map[string]Outcome }

func New() *Cache { return &Cache{rows: map[string]Outcome{}} }

// Lookup authenticates the original tool/arguments before returning an outcome.
func (c *Cache) Lookup(op, tool, argsHash string) (Outcome, bool, error) {
	o, ok := c.rows[op]
	if !ok {
		return Outcome{}, false, nil
	}
	if o.Tool != tool || o.ArgsHash != argsHash {
		return Outcome{}, true, ErrConflict
	}
	o.RecordIDs = append([]string(nil), o.RecordIDs...)
	return o, true, nil
}
func (c *Cache) Commit(op string, o Outcome) error {
	if !record.IsHex64(op) || !record.IsHex64(o.ArgsHash) || o.Tool == "" {
		return errors.New("invalid operation identity")
	}
	if _, ok, err := c.Lookup(op, o.Tool, o.ArgsHash); ok {
		return err
	}
	o.RecordIDs = append([]string(nil), o.RecordIDs...)
	c.rows[op] = o
	return nil
}

// Replay receives current complete receiver eligibility and render version.
// Rerender consumes stored outcome only and must not perform the mutation.
func (c *Cache) Replay(op, tool, argsHash string, eligible bool, version string, rerender func(Outcome) (string, error)) (string, bool, error) {
	o, ok, err := c.Lookup(op, tool, argsHash)
	if !ok || err != nil {
		return "", ok, err
	}
	if !eligible {
		o.Text = ""
		o.RenderVersion = ""
		c.rows[op] = o
		return Unavailable, true, nil
	}
	if o.Text == "" || o.RenderVersion != version {
		if rerender == nil {
			return Unavailable, true, nil
		}
		text, err := rerender(o)
		if err != nil {
			return Unavailable, true, nil
		}
		o.Text = text
		o.RenderVersion = version
		c.rows[op] = o
	}
	return o.Text, true, nil
}

type Delivery struct {
	generation         uint64
	exposed, confirmed map[string]uint64
}

func NewDelivery() *Delivery {
	return &Delivery{generation: 1, exposed: map[string]uint64{}, confirmed: map[string]uint64{}}
}
func (d *Delivery) Generation() uint64 { return d.generation }
func (d *Delivery) Compact()           { d.generation++; d.confirmed = map[string]uint64{} }

// Expose is conservative lineage state, committed before sending a reply.
func (d *Delivery) Expose(id string) uint64 { d.exposed[id] = d.generation; return d.generation }
func (d *Delivery) Confirm(id string, generation uint64) bool {
	if generation != d.generation || d.exposed[id] != generation {
		return false
	}
	d.confirmed[id] = generation
	return true
}
func (d *Delivery) Confirmed(id string) bool { return d.confirmed[id] == d.generation }
func (d *Delivery) Exposed(id string) bool   { _, ok := d.exposed[id]; return ok }
