package store

import (
	"context"
	"github.com/Telara-Labs/hilo/contract/invalidate"
	"sort"
)

type occurrence struct{ owner, session, event string }

func (s *Store) loadFences(ctx context.Context, d *databaseState) error {
	var barriers int
	if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier WHERE owner=?", s.opts.PinnedGenesisID).Scan(&barriers) != nil {
		return failure("storage_error")
	}
	d.blocked = barriers > 0
	d.retained = map[string][]invalidate.Tomb{}
	d.bans = map[occurrence]map[string]bool{}
	rows, err := s.conn.QueryContext(ctx, "SELECT target,kind,cause FROM tomb")
	if err != nil {
		return failure("storage_error")
	}
	for rows.Next() {
		var id, cause string
		var kind invalidate.TombKind
		if rows.Scan(&id, &kind, &cause) != nil {
			rows.Close()
			return failure("storage_error")
		}
		d.retained[id] = append(d.retained[id], invalidate.Tomb{Kind: kind, Cause: cause})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	rows, err = s.conn.QueryContext(ctx, "SELECT owner,session,event_id,cause FROM event_ban")
	if err != nil {
		return failure("storage_error")
	}
	for rows.Next() {
		var k occurrence
		var cause string
		if rows.Scan(&k.owner, &k.session, &k.event, &cause) != nil {
			rows.Close()
			return failure("storage_error")
		}
		if d.bans[k] == nil {
			d.bans[k] = map[string]bool{}
		}
		d.bans[k][cause] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	rows, err = s.conn.QueryContext(ctx, "SELECT id,known,first_seq,last_seq FROM item_order")
	if err != nil {
		return failure("storage_error")
	}
	for rows.Next() {
		var id string
		var known int
		var lo, hi int64
		if rows.Scan(&id, &known, &lo, &hi) != nil || d.byID[id] == nil {
			rows.Close()
			return failure("corrupt_database")
		}
		x := d.byID[id]
		x.orderKnown = known == 1
		x.firstSeq = lo
		x.lastSeq = hi
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	return nil
}
func tombRank(k invalidate.TombKind) int {
	switch k {
	case invalidate.Erased:
		return 3
	case invalidate.Withdrawn:
		return 2
	case invalidate.Retracted:
		return 1
	}
	return 0
}

// Committed fences are independent of a later reclassification of an absent ID.
// Security-control bodies are retained, while their old opaque dependency fence
// still prevents ordinary descendants from being revived.
func (d *databaseState) enforceFences() error {
	work := 0
	limit := false
	causeCount := 0
	causes := map[string]map[invalidate.Tomb]bool{}
	add := func(id string, t invalidate.Tomb) bool {
		if causes[id] == nil {
			causes[id] = map[invalidate.Tomb]bool{}
		}
		if causes[id][t] {
			return false
		}
		causeCount++
		if causeCount > 65536 {
			limit = true
			return false
		}
		causes[id][t] = true
		return true
	}
	for id, all := range d.eval.Causes {
		for _, t := range all {
			add(id, t)
		}
	}
	for id, all := range d.retained {
		for _, t := range all {
			add(id, t)
		}
	}
	bans := map[occurrence]map[string]bool{}
	for k, all := range d.bans {
		bans[k] = map[string]bool{}
		for c := range all {
			bans[k][c] = true
		}
	}
	changed := true
	for changed {
		changed = false
		for _, x := range d.records {
			work++
			if work > 1048576 || limit {
				return &projectionLimit{}
			}
			if x.rec.Header.Type.IsControl() {
				continue
			}
			id := x.rec.ID
			deps := append([]string(nil), x.deps...)
			if origin := x.rec.Header.Links.Origin; origin != "" {
				deps = append(deps, origin)
			}
			for _, p := range deps {
				for t := range causes[p] {
					if add(id, t) {
						changed = true
					}
				}
			}
			for _, event := range x.events {
				key := occurrence{x.owner, x.rec.Header.Subj.SessionKey, event}
				for c := range bans[key] {
					if add(id, invalidate.Tomb{Kind: invalidate.Erased, Cause: c}) {
						changed = true
					}
				}
				for t := range causes[id] {
					if t.Kind != invalidate.Erased {
						continue
					}
					if bans[key] == nil {
						bans[key] = map[string]bool{}
					}
					if !bans[key][t.Cause] {
						bans[key][t.Cause] = true
						changed = true
					}
				}
			}
		}
	}
	d.eval.Causes = map[string][]invalidate.Tomb{}
	d.eval.Tombs = map[string]invalidate.Tomb{}
	for id, all := range causes {
		for t := range all {
			d.eval.Causes[id] = append(d.eval.Causes[id], t)
			old := d.eval.Tombs[id]
			if tombRank(t.Kind) > tombRank(old.Kind) || tombRank(t.Kind) == tombRank(old.Kind) && t.Cause < old.Cause {
				d.eval.Tombs[id] = t
			}
		}
		if x := d.byID[id]; x != nil && !x.rec.Header.Type.IsControl() {
			d.eval.Status[id] = invalidate.Invalidated
		}
	}
	holds := map[string]map[string]bool{}
	for id, tokens := range d.retainedHolds {
		holds[id] = map[string]bool{}
		for token := range tokens {
			holds[id][token] = true
		}
	}
	for id, tokens := range d.eval.HoldCauses {
		if holds[id] == nil {
			holds[id] = map[string]bool{}
		}
		for _, v := range tokens {
			holds[id][v] = true
		}
	}
	holdCount := 0
	for _, tokens := range holds {
		holdCount += len(tokens)
	}
	if holdCount > 65536 {
		return &projectionLimit{}
	}
	addHold := func(id, v string) bool {
		if holds[id] == nil {
			holds[id] = map[string]bool{}
		}
		if holds[id][v] {
			return false
		}
		holdCount++
		if holdCount > 65536 {
			limit = true
			return false
		}
		holds[id][v] = true
		return true
	}
	changed = true
	for changed {
		changed = false
		for _, x := range d.records {
			work++
			if work > 1048576 || limit {
				return &projectionLimit{}
			}
			if x.rec.Header.Type.IsControl() {
				continue
			}
			deps := append([]string(nil), x.deps...)
			if p := x.rec.Header.Links.Origin; p != "" {
				deps = append(deps, p)
			}
			for _, p := range deps {
				for token := range holds[p] {
					if addHold(x.rec.ID, token) {
						changed = true
					}
				}
			}
			for root := range d.semantic[x.rec.ID] {
				for t := range causes[root] {
					if addHold(x.rec.ID, root+"/"+t.Cause) {
						changed = true
					}
				}
				for token := range holds[root] {
					if addHold(x.rec.ID, token) {
						changed = true
					}
				}
			}

		}
	}
	for id, all := range holds {
		d.eval.HoldCauses[id] = nil
		for token := range all {
			d.eval.HoldCauses[id] = append(d.eval.HoldCauses[id], token)
		}
		sort.Strings(d.eval.HoldCauses[id])
		if len(all) > 0 && d.eval.Status[id] != invalidate.Invalidated {
			d.eval.Status[id] = invalidate.LineageHold
		}
	}
	if limit {
		return &projectionLimit{}
	}
	return nil
}
