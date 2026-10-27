// Package replay models mutation idempotency separately from rendered disclosure
// and confirmed delivery. The adapter persists these changes atomically with writes.
package replay

import (
	"encoding/json"
	"errors"
	"github.com/Telara-Labs/hilo/contract/record"
)

const Unavailable = "The operation was recorded, but its prior memory content is no longer available to this caller."

var ErrConflict = errors.New("op_conflict")

type Outcome struct {
	Tool, ArgsHash, Text, RenderVersion string
	// RecordIDs and Dependencies are verified mutation/input/render provenance.
	// Every content root must be declared here and in the signed call. Dependencies
	// also includes the call itself so its managed key copies share its lifetime.
	RecordIDs    []string
	Call         *record.Record
	Dependencies []string
}
type Cache struct{ rows map[string]Outcome }

func New() *Cache { return &Cache{rows: map[string]Outcome{}} }

// Lookup returns a uniform unavailable state BEFORE inspecting candidate tool or
// arguments when the original comparator key has been destroyed.
func (c *Cache) Lookup(op, tool string, args json.RawMessage) (Outcome, bool, error) {
	o, ok := c.rows[op]
	if !ok {
		return Outcome{}, false, nil
	}
	if o.Call == nil {
		return Outcome{RecordIDs: append([]string(nil), o.RecordIDs...)}, true, nil
	}
	b := o.Call.Body.(*record.CallBody)
	if b.ArgsHash == "" {
		return Outcome{}, true, nil
	}
	if tool != o.Tool {
		return Outcome{}, true, ErrConflict
	}
	hash, err := record.CallCommitment(b.Salt, "args", tool, args)
	if err != nil || hash != b.ArgsHash {
		return Outcome{}, true, ErrConflict
	}
	return cloneOutcome(o), true, nil
}
func cloneOutcome(o Outcome) Outcome {
	o.RecordIDs = append([]string(nil), o.RecordIDs...)
	o.Dependencies = append([]string(nil), o.Dependencies...)
	if o.Call != nil {
		o.Call, _ = record.Parse(append([]byte(nil), o.Call.HeaderJCS...), append([]byte(nil), o.Call.BodyJCS...), o.Call.ID)
	}
	return o
}
func (c *Cache) Commit(op string, o Outcome) error {
	if !record.IsHex64(op) || o.Call == nil {
		return errors.New("complete signed call linkage required")
	}
	r, err := record.Parse(o.Call.HeaderJCS, o.Call.BodyJCS, o.Call.ID)
	if err != nil || r.Header.Op != op {
		return errors.New("commitment_dependencies")
	}
	depSet := map[string]bool{}
	known := append([]string(nil), o.RecordIDs...)
	for _, id := range o.Dependencies {
		if !record.IsHex64(id) || depSet[id] {
			return errors.New("commitment_dependencies")
		}
		depSet[id] = true
		// The call's own identity is a local key-lifetime edge, not an input.
		// Every other consulted root must survive signed transfer/recovery.
		if id != r.ID {
			known = append(known, id)
		}
	}
	if record.ValidateCommitmentDependencies(r, known) != nil {
		return errors.New("commitment_dependencies")
	}
	b := r.Body.(*record.CallBody)
	if o.Tool != b.Tool || o.ArgsHash != "" && o.ArgsHash != b.ArgsHash {
		return errors.New("invalid comparator")
	}
	roots := append([]string{r.ID}, b.CommitmentDeps...)
	for _, id := range roots {
		if !depSet[id] {
			return errors.New("commitment_dependencies")
		}
	}
	if _, ok := c.rows[op]; ok {
		return errors.New("operation already settled")
	}
	o.Call = r
	o.ArgsHash = b.ArgsHash
	c.rows[op] = cloneOutcome(o)
	return nil
}

// Erase destroys every managed comparator and render copy in this pure model.
// Durable adapters also scrub database/WAL/FTS/artifacts before acknowledgement.
func (c *Cache) Erase(op string) {
	o, ok := c.rows[op]
	if !ok {
		return
	}
	if o.Call != nil {
		clear(o.Call.BodyJCS)
		o.Call.Body = nil
		o.Call = nil
	}
	o.Text = ""
	o.RenderVersion = ""
	o.ArgsHash = ""
	c.rows[op] = o
}
func (c *Cache) Invalidate(dependency string) {
	for op, o := range c.rows {
		for _, d := range o.Dependencies {
			if d == dependency {
				c.Erase(op)
				break
			}
		}
	}
}

// Replay's adapter must recheck eligibility and restrict rerender to the admitted
// signed input roots. A callback discovering a new content root must withhold the
// result; it cannot extend or repair the settled signed call in place.
func (c *Cache) Replay(op, tool string, args json.RawMessage, eligible bool, version string, rerender func(Outcome) (string, error)) (string, bool, error) {
	// Eligibility loss cannot inspect arguments or expose a conflict predicate.
	o, ok := c.rows[op]
	if !ok {
		return "", false, nil
	}
	if !eligible {
		o.Text = ""
		o.RenderVersion = ""
		c.rows[op] = o
		return Unavailable, true, nil
	}
	o, ok, err := c.Lookup(op, tool, args)
	if err != nil {
		return "", ok, err
	}
	if o.Call == nil || o.Call.Body.(*record.CallBody).ArgsHash == "" {
		return Unavailable, true, nil
	}
	if o.Text == "" || o.RenderVersion != version {
		if rerender == nil {
			return Unavailable, true, nil
		}
		text, err := rerender(cloneOutcome(o))
		if err != nil {
			return Unavailable, true, nil
		}
		o.Text = text
		o.RenderVersion = version
		c.rows[op] = cloneOutcome(o)
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
