package store

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/invalidate"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/view"
)

// SQL keys preserve column boundaries, affinity and ordered witness endpoints.
// Pure alias-key normalization must never collapse distinct retained SQL rows.
type relationKey [7]string

func relationKeyOf(row []any) (key relationKey) {
	for i, v := range row {
		switch n := v.(type) {
		case string:
			key[i] = "s" + n
		case int64:
			key[i] = "i" + integerKey(n)
		case int:
			key[i] = "i" + integerKey(int64(n))
		case []byte:
			key[i] = "b" + string(n)
		default:
			key[i] = fmt.Sprintf("?%T", v)
		}
	}
	return
}

type relationPlan struct {
	rows  map[string]map[relationKey]bool
	seq   map[relationKey]int64
	facts map[string]view.EventFacts
}

func (p *relationPlan) has(table string, key relationKey) bool { return p.rows[table][key] }
func (p *relationPlan) count(table string) int                 { return len(p.rows[table]) }
func (p *relationPlan) add(table string, row []any) error {
	k := relationKeyOf(row)
	if p.rows[table][k] {
		return nil
	}
	if len(p.rows[table]) >= 65536 {
		return &projectionLimit{}
	}
	p.rows[table][k] = true
	return nil
}

var relationColumns = map[string]string{
	"dep": "id,parent", "item_event": "id,event_id", "item_recall": "id,event_seq,recalled", "supersession": "owner,kind,lid,successor,predecessor", "tomb": "target,kind,cause", "event_ban": "owner,session,event_id,cause", "presence": "owner,session,event_id,revision,source", "presence_parent": "owner,session,event_id,revision,source,predecessor", "presence_taint": "owner,session,event_id,revision,source,tag", "witness": "owner,session,event_id,a,b,source_a,source_b",
	"exposure_affect": "exposure,target", "semantic_hold_cause": "owner,target,root,control",
}

func (c *reductionContext) relations(d *databaseState) (*relationPlan, error) {
	if c.plan != nil {
		return c.plan, nil
	}
	p := &relationPlan{rows: map[string]map[relationKey]bool{}, seq: map[relationKey]int64{}, facts: map[string]view.EventFacts{}}
	tables := make([]string, 0, len(relationColumns))
	for t := range relationColumns {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	for _, table := range tables {
		columns := relationColumns[table]
		p.rows[table] = map[relationKey]bool{}
		var n int
		if d.store.conn.QueryRowContext(d.ctx, "SELECT count(*) FROM "+table).Scan(&n) != nil {
			return nil, failure("storage_error")
		}
		if n > 65536 {
			return nil, &projectionLimit{}
		}
		if err := c.charge(n); err != nil {
			return nil, err
		}
		query := columns
		if table == "presence" {
			query += ",seq"
		}
		rows, err := d.store.conn.QueryContext(d.ctx, "SELECT "+query+" FROM "+table)
		if err != nil {
			return nil, failure("storage_error")
		}
		count := len(strings.Split(query, ","))
		for rows.Next() {
			values := make([]any, count)
			ptrs := make([]any, count)
			for i := range values {
				ptrs[i] = &values[i]
			}
			if rows.Scan(ptrs...) != nil {
				rows.Close()
				return nil, failure("storage_error")
			}
			keyValues := values
			if table == "presence" {
				keyValues = values[:count-1]
			}
			key := relationKeyOf(keyValues)
			p.rows[table][key] = true
			if len(p.rows[table]) > 65536 {
				rows.Close()
				return nil, &projectionLimit{}
			}
			if table == "presence" {
				seq, ok := values[count-1].(int64)
				if !ok {
					rows.Close()
					return nil, failure("corrupt_database")
				}
				p.seq[key] = seq
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, failure("storage_error")
		}
	}
	c.plan = p
	return p, nil
}
func (c *reductionContext) stageFacts(d *databaseState, f view.EventFacts) error {
	p, err := c.relations(d)
	if err != nil {
		return err
	}
	if err = c.charge(len(f.Presence) + len(f.Witnesses)); err != nil {
		return err
	}
	for _, x := range f.Presence {
		if err = c.charge(len(x.Replaces) + len(x.ObservedTaint)); err != nil {
			return err
		}
		row := []any{x.Owner, x.SessionKey, x.EventID, x.Revision, x.RecordID}
		key := relationKeyOf(row)
		if seq, ok := p.seq[key]; ok && seq != x.Seq {
			return failure("corrupt_database")
		}
		if !x.Admissible {
			continue
		}
		if !p.has("presence", key) {
			if err = c.charge(1); err != nil {
				return err
			}
		}
		if err = p.add("presence", row); err != nil {
			return err
		}
		p.seq[key] = x.Seq
		for _, v := range x.Replaces {
			if err = p.add("presence_parent", append(append([]any(nil), row...), v)); err != nil {
				return err
			}
		}
		for _, v := range x.ObservedTaint {
			if err = p.add("presence_taint", append(append([]any(nil), row...), v)); err != nil {
				return err
			}
		}
	}
	for _, w := range f.Witnesses {
		if w.Admissible {
			if err = p.add("witness", witnessRow(w)); err != nil {
				return err
			}
		}
	}
	// Cache the complete admitted facts for a later body purge, not just the
	// current manifest. This contains no text, event salt or serialization hash.
	if len(f.Presence) > 0 {
		sk := f.Presence[0].SessionKey
		p.facts[sk] = f
	} else if len(f.Witnesses) > 0 {
		p.facts[f.Witnesses[0].SessionKey] = f
	}
	return nil
}
func (d *databaseState) prepareRelations() error {
	if d.relationsReady {
		return nil
	}
	c, err := d.reductions()
	if err != nil {
		return err
	}
	p, err := c.relations(d)
	if err != nil {
		return err
	}
	for _, f := range d.exposures {
		if err = c.charge(len(f.affects)); err != nil {
			return err
		}
		for id := range f.affects {
			if err = p.add("exposure_affect", []any{f.id, id}); err != nil {
				return err
			}
		}
	}
	for id, tokens := range d.eval.HoldCauses {
		if err = c.charge(len(tokens)); err != nil {
			return err
		}
		for _, token := range tokens {
			parts := strings.Split(token, "/")
			if len(parts) != 2 || !record.IsHex64(parts[0]) || !record.IsHex64(parts[1]) {
				return failure("corrupt_database")
			}
			if err = p.add("semantic_hold_cause", []any{d.store.opts.PinnedGenesisID, id, parts[0], parts[1]}); err != nil {
				return err
			}
		}
	}
	sessions := map[string]bool{}
	for _, x := range d.records {
		if err = c.charge(len(x.deps) + len(x.events) + len(x.recalls) + len(x.rec.Header.Links.Supersedes) + len(d.eval.Causes[x.rec.ID])); err != nil {
			return err
		}
		r := x.rec
		if sk := r.Header.Subj.SessionKey; sk != "" {
			sessions[sk] = true
		}
		for _, v := range x.deps {
			if err = p.add("dep", []any{r.ID, v}); err != nil {
				return err
			}
		}
		for _, v := range x.events {
			if err = p.add("item_event", []any{r.ID, v}); err != nil {
				return err
			}
		}
		for _, v := range x.recalls {
			if err = p.add("item_recall", []any{r.ID, v.Seq, v.ID}); err != nil {
				return err
			}
		}
		for _, v := range r.Header.Links.Supersedes {
			if err = p.add("supersession", []any{x.owner, string(r.Header.Type), r.Header.LID, r.ID, v}); err != nil {
				return err
			}
		}
		for _, cause := range d.eval.Causes[r.ID] {
			if err = p.add("tomb", []any{r.ID, string(cause.Kind), cause.Cause}); err != nil {
				return err
			}
			if cause.Kind == invalidate.Erased {
				for _, e := range x.events {
					if err = p.add("event_ban", []any{x.owner, r.Header.Subj.SessionKey, e, cause.Cause}); err != nil {
						return err
					}
				}
			}
		}
	}
	for _, x := range d.records {
		if task := x.rec.Header.Subj.TaskID; task != "" {
			d.taskStatus(x.owner, task)
		}
	}
	if len(sessions) > 128 {
		return &projectionLimit{}
	}
	for sk := range sessions {
		if _, err = d.reduceSession(sk); err != nil {
			return err
		}
	}
	// Simulate body removal before the first SQL mutation, using the complete
	// admitted facts as history. Restore full bodies afterward so other staged
	// projections retain the same inputs until actual destructive persistence.
	saved := map[*stored]*record.Record{}
	originalFacts := d.facts
	postFacts := make(map[string]view.EventFacts, len(d.facts))
	for sk, f := range d.facts {
		postFacts[sk] = f
	}
	for _, x := range d.records {
		if x.state == string(invalidate.Invalidated) && x.rec.Body != nil {
			saved[x] = x.rec
			x.rec = x.rec.WithoutBody()
			d.groups = nil
			sk := x.rec.Header.Subj.SessionKey
			if f, ok := p.facts[sk]; ok {
				postFacts[sk] = mergedFacts(d.facts[sk], f)
			}
		}
	}
	if len(saved) == 0 {
		d.plannedFacts = map[string]view.EventFacts{}
		for sk := range sessions {
			d.plannedFacts[sk] = p.facts[sk]
		}
		d.relationsReady = true
		return nil
	}
	d.facts = postFacts
	defer func() {
		for x, r := range saved {
			x.rec = r
		}
		d.facts = originalFacts
		d.groups = nil
	}()
	for sk := range sessions {
		if _, err = d.reduceSession(sk); err != nil {
			return err
		}
	}
	d.plannedFacts = map[string]view.EventFacts{}
	for sk := range sessions {
		d.plannedFacts[sk] = p.facts[sk]
	}
	d.relationsReady = true
	return nil
}
