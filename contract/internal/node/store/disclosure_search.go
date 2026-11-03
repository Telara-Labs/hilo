package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/hilo/contract/record"
)

func resourceSet(kinds []string) map[string]bool {
	out := map[string]bool{}
	for _, k := range kinds {
		switch k {
		case "checkpoint":
			out[string(record.KindCheckpoint)] = true
		case "session":
			out[string(record.KindSession)] = true
		case "evidence":
			out[string(record.KindChunk)] = true
		case "task_summary":
			out[string(record.KindConclusion)] = true
		}
	}
	return out
}
func (e *DisclosureEngine) countProjection(ctx context.Context, d *databaseState, c *credentialState, sc scopeState, resources []string, pool *disclosureEntropy) (*countSnapshot, error) {
	id, err := pool.uuid(ctx, e.store, "snapshot", "projection_count_snapshot", "id")
	if err != nil {
		return nil, err
	}
	snapshot := &countSnapshot{id: id, state: "known", generation: d.generation, scopeKey: record.H("authorized-count-scope", c.id, strconv.FormatInt(c.epoch, 10), sc.id, strconv.FormatInt(sc.evidence, 10), sc.repoState, sc.repo, strings.Join(resources, ","))}
	var nr, nu, ns, ne, nn, nre int64
	heads, eventUnits, err := projectionUniverse(d)
	if err != nil {
		return nil, err
	}
	types := resourceSet(resources)
	bytes := 0
	for _, x := range d.records {
		if !heads[x.rec.ID] || !resourceMember(types, x) || !readPermitted(d, c, sc, x) {
			continue
		}
		fields := d.fields[x.rec.ID]
		if len(fields) == 0 {
			continue
		}
		units := map[string]string{}
		for i, f := range fields {
			if f.event != "" && !eventUnits[x.rec.ID][f.event+"/"+f.revision] {
				continue
			}
			key := strconv.Itoa(i)
			if f.event != "" {
				key = f.event + "/" + f.revision
			}
			if classRank(f.class) > classRank(units[key]) {
				units[key] = f.class
			}
		}
		if len(units) == 0 {
			continue
		}
		nr++
		if nr > 8192 {
			snapshot.state = "unknown"
			snapshot.reason = "count_record_limit"
			break
		}
		bytes += len(x.rec.BodyJCS)
		if bytes > 64<<20 {
			snapshot.state = "unknown"
			snapshot.reason = "count_body_limit"
			break
		}
		restricted := false
		for _, class := range units {
			nu++
			if nu > disclosureCountUnitLimit {
				snapshot.state = "unknown"
				snapshot.reason = "count_unit_limit"
				break
			}
			switch class {
			case disclosuretext.NoDetectedMarker:
				ns++
			case disclosuretext.InjectedSource, disclosuretext.PossibleMemoryFrame:
				ne++
				restricted = true
			default:
				nn++
				restricted = true
			}
		}
		if restricted {
			nre++
		}
		if snapshot.state == "unknown" {
			break
		}
	}
	if snapshot.state == "known" {
		snapshot.records = ptr64(nr)
		snapshot.total = ptr64(nu)
		snapshot.searchable = ptr64(ns)
		snapshot.excluded = ptr64(ne)
		snapshot.unclassified = ptr64(nn)
		snapshot.recordsExcluded = ptr64(nre)
	}
	return snapshot, nil
}
func countWarnings(c *countSnapshot, current bool) []string {
	if c == nil || c.state == "not_requested" {
		return nil
	}
	if c.state == "unknown" {
		if current {
			return []string{"current_count_unknown"}
		}
		return []string{"fresh_projection_counts_unknown"}
	}
	var out []string
	if c.excluded != nil && *c.excluded > 0 {
		out = append(out, "fresh_projection_exclusions_present")
	}
	if c.unclassified != nil && *c.unclassified > 0 {
		out = append(out, "fresh_projection_unclassified_present")
	}
	return out
}

type selectionPlan struct {
	id, query                 string
	resources                 []string
	ids                       []string
	limit, start, end         int
	known                     bool
	inputCursor, outputCursor string
	deadline                  time.Time
}

func (e *DisclosureEngine) prepareSearch(ctx context.Context, d *databaseState, c *credentialState, sc scopeState, n disclosuretext.NormalizedCommand, o *operationOutcome, pool *disclosureEntropy, now time.Time) (*selectionPlan, error) {
	p := &selectionPlan{query: n.Args.Query, resources: append([]string(nil), n.Args.ResourceTypes...), limit: n.Args.Limit, known: true, deadline: now.Add(300 * time.Second)}
	if n.Tool == "local.next_page" {
		p.inputCursor = n.Args.CursorID
		var engine, credential, scope, state, selection string
		var generation, epoch, expected, evidence int64
		err := e.store.conn.QueryRowContext(ctx, "SELECT q.id,q.credential,q.scope,q.generation,q.grant_epoch,q.engine,c.state,c.expected_generation,c.offset,q.universe_known,q.evidence FROM query_cursor c JOIN query_selection q ON q.id=c.selection WHERE c.id=?", p.inputCursor).Scan(&selection, &credential, &scope, &generation, &epoch, &engine, &state, &expected, &p.start, &p.known, &evidence)
		if err == sql.ErrNoRows {
			return nil, failure("cursor_expired")
		}
		if err != nil {
			return nil, failure("storage_error")
		}
		if state == "consumed" {
			return nil, failure("cursor_consumed")
		}
		deadline, ok := e.deadlines[selection]
		if !ok || !now.Before(deadline) || engine != e.id || credential != c.id || scope != sc.id || generation != sc.generation || epoch != c.epoch || expected != d.generation || evidence != sc.evidence || state != "ready" {
			return nil, failure("cursor_expired")
		}
		p.id = selection
		p.deadline = deadline
		var resources string
		if e.store.conn.QueryRowContext(ctx, "SELECT query,resource_types,page_size FROM selection_payload WHERE selection=?", p.id).Scan(&p.query, &resources, &p.limit) != nil {
			return nil, failure("cursor_expired")
		}
		p.resources = nil
		if resources != "" {
			p.resources = strings.Split(resources, ",")
		}
		rows, err := e.store.conn.QueryContext(ctx, "SELECT id FROM selection_item WHERE selection=? ORDER BY ordinal LIMIT 301", p.id)
		if err != nil {
			return nil, failure("storage_error")
		}
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil {
				rows.Close()
				return nil, failure("storage_error")
			}
			p.ids = append(p.ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, failure("storage_error")
		}
		if len(p.ids) > 300 {
			return nil, failure("corrupt_database")
		}
	} else {
		if p.query == "" {
			o.kind = "empty_result"
			o.renderer = "empty_v1"
			o.result = "query_required"
			o.total = nil
			return nil, nil
		}
		var err error
		p.id, err = pool.uuid(ctx, e.store, "selection", "query_selection", "id")
		if err != nil {
			return nil, err
		}
		types := resourceSet(p.resources)
		head, _, err := projectionUniverse(d)
		if err != nil {
			return nil, err
		}
		rows, err := e.store.conn.QueryContext(ctx, "SELECT p.id FROM search JOIN passage p ON p.rowid=search.rowid WHERE search MATCH ? ORDER BY p.id", lexicalFTSQuery(p.query))
		if err != nil {
			return nil, failure("query_failed")
		}
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil {
				rows.Close()
				return nil, failure("query_failed")
			}
			x := d.byID[id]
			if !head[id] || x == nil || !resourceMember(types, x) || !readPermitted(d, c, sc, x) || len(freshFields(d, id)) == 0 {
				continue
			}
			matched, err := currentQueryMatch(ctx, e.store, d, id, p.query)
			if err != nil {
				rows.Close()
				return nil, err
			}
			if !matched {
				continue
			}
			if len(p.ids) == 300 {
				p.known = false
				break
			}
			p.ids = append(p.ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, failure("query_failed")
		}
	}
	if p.start < 0 || p.start > len(p.ids) || p.limit < 1 || p.limit > 50 {
		return nil, failure("cursor_expired")
	}
	p.end = min(len(p.ids), p.start+p.limit)
	o.selection = p.id
	o.start = p.start
	o.end = p.end
	o.universeKnown = p.known
	o.kind = "search_page"
	o.renderer = "lexical_page_v1"
	o.result = "hits"
	o.total = ptr64(int64(len(p.ids)))
	o.warnings = []string{"lexical_subset", "embeddings_unavailable"}
	for _, id := range p.ids[p.start:p.end] {
		x := d.byID[id]
		if !readPermitted(d, c, sc, x) || len(freshFields(d, id)) == 0 {
			return nil, failure("unavailable")
		}
		o.members = append(o.members, outcomeMember{id: id, owner: x.owner, role: "search_hit", mode: "fresh_projection", required: true})
	}
	o.selected = int64(len(o.members))
	var err error
	o.count, err = e.countProjection(ctx, d, c, sc, p.resources, pool)
	if err != nil {
		return nil, err
	}
	o.warnings = append(o.warnings, countWarnings(o.count, false)...)
	if p.end < len(p.ids) {
		var count int
		if e.store.conn.QueryRowContext(ctx, "SELECT count(*) FROM query_cursor c JOIN query_selection s ON s.id=c.selection WHERE s.credential=? AND c.state='ready'", c.id).Scan(&count) != nil {
			return nil, failure("storage_error")
		}
		if count >= 16 {
			return nil, failure("cursor_limit")
		}
		p.outputCursor, err = pool.uuid(ctx, e.store, "cursor", "query_cursor", "id")
		if err != nil {
			return nil, err
		}
		o.cursor = p.outputCursor
		o.warnings = appendUnique(o.warnings, "selection_truncated")
	}
	if o.selected == 0 {
		o.kind = "empty_result"
		o.renderer = "empty_v1"
		o.result = "no_hits"
		if o.count.state == "unknown" {
			o.result = "no_hits_projection_counts_unknown"
		} else if *o.count.excluded > 0 || *o.count.unclassified > 0 {
			o.result = "no_searchable_fresh_hits"
		}
	}
	return p, nil
}
func (e *DisclosureEngine) persistSelection(ctx context.Context, d *databaseState, c *credentialState, sc scopeState, o *operationOutcome, p *selectionPlan) error {
	if p == nil {
		return nil
	}
	if p.inputCursor == "" {
		_, err := e.store.conn.ExecContext(ctx, "INSERT INTO query_selection VALUES(?,?,?,?,?,?,'lexical-order/1',?,?,?,?)", p.id, c.id, sc.id, sc.generation, c.epoch, "", e.id, len(p.ids), boolInt(p.known), sc.evidence)
		if err != nil {
			return failure("storage_error")
		}
		if _, err = e.store.conn.ExecContext(ctx, "INSERT INTO selection_payload VALUES(?,?,?,?)", p.id, p.query, strings.Join(p.resources, ","), p.limit); err != nil {
			return failure("storage_error")
		}
		for i, id := range p.ids {
			if _, err = e.store.conn.ExecContext(ctx, "INSERT INTO selection_item VALUES(?,?,?)", p.id, i, id); err != nil {
				return failure("storage_error")
			}
		}
	} else {
		r, err := e.store.conn.ExecContext(ctx, "UPDATE query_cursor SET state='consumed',consumed_by=? WHERE id=? AND state='ready'", o.op, p.inputCursor)
		if err != nil {
			return failure("storage_error")
		}
		changed, _ := r.RowsAffected()
		if changed != 1 {
			return failure("cursor_consumed")
		}
	}
	if p.outputCursor != "" {
		if _, err := e.store.conn.ExecContext(ctx, "INSERT INTO query_cursor VALUES(?,?,?,?,'ready','')", p.outputCursor, p.id, p.end, d.generation); err != nil {
			return failure("storage_error")
		}
	}
	return nil
}
