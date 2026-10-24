package store

import (
	"context"
	"database/sql"
	"sort"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/heads"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

type outcomeMember struct {
	id, owner, task, role, mode string
	required                    bool
	deps                        []string
}
type operationOutcome struct {
	budget                                                                                                          int
	owner, credential, op, tool, argsHash, callRef, callID, schema, ruleset, builder, kind, renderer, result, scope string
	selected                                                                                                        int64
	total                                                                                                           *int64
	isError                                                                                                         bool
	createdSeq, grantEpoch, scopeGeneration, evidence, dbGeneration                                                 int64
	members                                                                                                         []outcomeMember
	warnings                                                                                                        []string
	task, action, selection, cursor                                                                                 string
	start, end                                                                                                      int
	universeKnown                                                                                                   bool
	count                                                                                                           *countSnapshot
	listFilter                                                                                                      bool
	includeCompleted                                                                                                bool
	queryRequired                                                                                                   bool
	query                                                                                                           string
	lookup                                                                                                          bool
	includeContent                                                                                                  bool
	recordKind                                                                                                      record.Kind
}
type countSnapshot struct {
	id, state, reason, scopeKey                                         string
	generation                                                          int64
	records, total, searchable, excluded, unclassified, recordsExcluded *int64
}

func ptr64(n int64) *int64 { return &n }
func nullInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
func (s *Store) loadOutcome(ctx context.Context, credential, op string) (*operationOutcome, error) {
	o := &operationOutcome{owner: s.opts.PinnedGenesisID, credential: credential, op: op}
	var total sql.NullInt64
	var isError int
	err := s.conn.QueryRowContext(ctx, "SELECT tool,args_hash,call_ref,call_id,arg_schema,ruleset,builder,kind,renderer,selected,total,result,is_error,created_seq,scope,grant_epoch,scope_generation,evidence,db_generation,max_bytes FROM operation WHERE owner=? AND credential=? AND op=?", o.owner, credential, op).Scan(&o.tool, &o.argsHash, &o.callRef, &o.callID, &o.schema, &o.ruleset, &o.builder, &o.kind, &o.renderer, &o.selected, &total, &o.result, &isError, &o.createdSeq, &o.scope, &o.grantEpoch, &o.scopeGeneration, &o.evidence, &o.dbGeneration, &o.budget)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, failure("storage_error")
	}
	if total.Valid {
		o.total = ptr64(total.Int64)
	}
	o.isError = isError != 0
	err = s.conn.QueryRowContext(ctx, "SELECT record_kind,include_content FROM outcome_lookup WHERE owner=? AND credential=? AND op=?", o.owner, credential, op).Scan(&o.recordKind, &o.includeContent)
	if err == nil {
		o.lookup = true
	} else if err != sql.ErrNoRows {
		return nil, failure("storage_error")
	}
	rows, err := s.conn.QueryContext(ctx, "SELECT role,required,record_owner,id,task,presentation FROM outcome_member WHERE owner=? AND credential=? AND op=? ORDER BY ordinal", o.owner, credential, op)
	if err != nil {
		return nil, failure("storage_error")
	}
	for rows.Next() {
		var m outcomeMember
		var required int
		if rows.Scan(&m.role, &required, &m.owner, &m.id, &m.task, &m.mode) != nil {
			rows.Close()
			return nil, failure("storage_error")
		}
		m.required = required != 0
		o.members = append(o.members, m)
		if len(o.members) > 128 {
			rows.Close()
			return nil, failure("corrupt_database")
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, failure("storage_error")
	}
	for i := range o.members {
		rows, err = s.conn.QueryContext(ctx, "SELECT id FROM outcome_dependency WHERE owner=? AND credential=? AND op=? AND member=? ORDER BY id", o.owner, credential, op, i)
		if err != nil {
			return nil, failure("storage_error")
		}
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil {
				rows.Close()
				return nil, failure("storage_error")
			}
			if !record.IsHex64(id) || len(o.members[i].deps) >= 8192 {
				rows.Close()
				return nil, failure("corrupt_database")
			}
			o.members[i].deps = append(o.members[i].deps, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, failure("storage_error")
		}
	}
	rows, err = s.conn.QueryContext(ctx, "SELECT code FROM outcome_warning WHERE owner=? AND credential=? AND op=? ORDER BY ordinal", o.owner, credential, op)
	if err != nil {
		return nil, failure("storage_error")
	}
	for rows.Next() {
		var code string
		if rows.Scan(&code) != nil {
			rows.Close()
			return nil, failure("storage_error")
		}
		if len(o.warnings) >= 32 {
			rows.Close()
			return nil, failure("corrupt_database")
		}
		o.warnings = append(o.warnings, code)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, failure("storage_error")
	}
	err = s.conn.QueryRowContext(ctx, "SELECT task,action FROM outcome_task WHERE owner=? AND credential=? AND op=?", o.owner, credential, op).Scan(&o.task, &o.action)
	if err != nil && err != sql.ErrNoRows {
		return nil, failure("storage_error")
	}
	err = s.conn.QueryRowContext(ctx, "SELECT selection,start_offset,end_offset,universe_known FROM outcome_page WHERE owner=? AND credential=? AND op=?", o.owner, credential, op).Scan(&o.selection, &o.start, &o.end, &o.universeKnown)
	if err != nil && err != sql.ErrNoRows {
		return nil, failure("storage_error")
	}
	err = s.conn.QueryRowContext(ctx, "SELECT cursor FROM outcome_continuation WHERE owner=? AND credential=? AND op=?", o.owner, credential, op).Scan(&o.cursor)
	if err != nil && err != sql.ErrNoRows {
		return nil, failure("storage_error")
	}
	err = s.conn.QueryRowContext(ctx, "SELECT include_completed,query_required FROM outcome_filter WHERE owner=? AND credential=? AND op=?", o.owner, credential, op).Scan(&o.includeCompleted, &o.queryRequired)
	if err == nil {
		o.listFilter = true
		if o.queryRequired {
			err = s.conn.QueryRowContext(ctx, "SELECT query FROM outcome_query WHERE owner=? AND credential=? AND op=?", o.owner, credential, op).Scan(&o.query)
			if err != nil && err != sql.ErrNoRows {
				return nil, failure("storage_error")
			}
		}
	} else if err != sql.ErrNoRows {
		return nil, failure("storage_error")
	}
	return o, nil
}
func (s *Store) persistOutcome(ctx context.Context, o *operationOutcome) error {
	_, err := s.conn.ExecContext(ctx, "INSERT INTO operation VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", o.owner, o.credential, o.op, o.tool, o.argsHash, o.callRef, o.callID, o.schema, o.ruleset, o.builder, "outcome/1", o.kind, o.renderer, "lexical-subset/1", o.selected, nullInt(o.total), o.result, boolInt(o.isError), o.createdSeq, o.scope, o.grantEpoch, o.scopeGeneration, o.evidence, o.dbGeneration, o.budget)
	if err != nil {
		return failure("storage_error")
	}
	if o.lookup {
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO outcome_lookup VALUES(?,?,?,?,?)", o.owner, o.credential, o.op, string(o.recordKind), boolInt(o.includeContent)); err != nil {
			return failure("storage_error")
		}
	}
	for i, m := range o.members {
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO outcome_member VALUES(?,?,?,?,?,?,?,?,?,?)", o.owner, o.credential, o.op, i, m.role, boolInt(m.required), m.owner, m.id, m.task, m.mode); err != nil {
			return failure("storage_error")
		}
		for _, id := range m.deps {
			role := "copied"
			if id == m.id {
				role = "selected_root"
			}
			if _, err = s.conn.ExecContext(ctx, "INSERT INTO outcome_dependency VALUES(?,?,?,?,?,?)", o.owner, o.credential, o.op, i, id, role); err != nil {
				return failure("storage_error")
			}
		}
	}
	for i, w := range o.warnings {
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO outcome_warning VALUES(?,?,?,?,?)", o.owner, o.credential, o.op, i, w); err != nil {
			return failure("storage_error")
		}
	}
	if o.listFilter {
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO outcome_filter VALUES(?,?,?,?,?)", o.owner, o.credential, o.op, boolInt(o.includeCompleted), boolInt(o.queryRequired)); err != nil {
			return failure("storage_error")
		}
		if o.queryRequired {
			if _, err = s.conn.ExecContext(ctx, "INSERT INTO outcome_query VALUES(?,?,?,?)", o.owner, o.credential, o.op, o.query); err != nil {
				return failure("storage_error")
			}
		}
	}
	if o.task != "" {
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO outcome_task VALUES(?,?,?,?,?,?)", o.owner, o.credential, o.op, o.owner, o.task, o.action); err != nil {
			return failure("storage_error")
		}
	}
	if o.selection != "" {
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO outcome_page VALUES(?,?,?,?,?,?,?)", o.owner, o.credential, o.op, o.selection, o.start, o.end, boolInt(o.universeKnown)); err != nil {
			return failure("storage_error")
		}
	}
	if o.cursor != "" {
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO outcome_continuation VALUES(?,?,?,?,?,?)", o.owner, o.credential, o.op, o.cursor, o.selection, o.end); err != nil {
			return failure("storage_error")
		}
	}
	if o.count != nil {
		if err = s.persistCount(ctx, o.owner, o.credential, o.count); err != nil {
			return err
		}
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO outcome_projection_summary VALUES(?,?,?,?)", o.owner, o.credential, o.op, o.count.id); err != nil {
			return failure("storage_error")
		}
	}
	return nil
}
func (s *Store) persistCount(ctx context.Context, owner, credential string, c *countSnapshot) error {
	if c == nil || !record.IsUUIDv4(c.id) || !record.IsKeyID(owner) || !record.IsUUIDv4(credential) {
		return failure("count_unavailable")
	}
	values := []*int64{c.records, c.total, c.searchable, c.excluded, c.unclassified, c.recordsExcluded}
	switch c.state {
	case "known":
		for _, p := range values {
			if p == nil || *p < 0 || *p > disclosureCountUnitLimit {
				return failure("count_unavailable")
			}
		}
		if c.reason != "" || *c.records > 8192 || *c.recordsExcluded > *c.records || *c.total != *c.searchable+*c.excluded+*c.unclassified {
			return failure("count_unavailable")
		}
	case "unknown":
		if c.reason != "count_record_limit" && c.reason != "count_body_limit" && c.reason != "count_unit_limit" {
			return failure("count_unavailable")
		}
		for _, p := range values {
			if p != nil {
				return failure("count_unavailable")
			}
		}
	case "not_requested":
		if c.reason != "" {
			return failure("count_unavailable")
		}
		for _, p := range values {
			if p != nil {
				return failure("count_unavailable")
			}
		}
	default:
		return failure("count_unavailable")
	}
	var reason any
	if c.reason != "" {
		reason = c.reason
	}
	_, err := s.conn.ExecContext(ctx, "INSERT INTO projection_count_snapshot VALUES(?,?,?,?,?,'resource-filter/1','fresh-projection/1',?,?,?,?,?,?,?,?,?)", c.id, owner, credential, c.scopeKey, "S", c.generation, c.state, reason, nullInt(c.records), nullInt(c.total), nullInt(c.searchable), nullInt(c.excluded), nullInt(c.unclassified), nullInt(c.recordsExcluded))
	if err != nil {
		return failure("storage_error")
	}
	return nil
}
func currentHeads(d *databaseState) map[string]bool {
	return d.groupedHeads()
}
func readPermitted(d *databaseState, c *credentialState, sc scopeState, x *stored) bool {
	if d.blocked || x == nil || x.owner == "" || !available(x) || !c.channels[S] || x.rec.Header.Type.IsControl() {
		return false
	}
	if !d.policyReadAllowed(x) {
		return false
	}
	if c.readKind == "all-local" {
		return true
	}
	a, ok := d.attrs[x.rec.ID]
	return c.readKind == "concrete" && ok && a.repoState == "known" && c.repos[a.repo]
}
func dependencyClosure(d *databaseState, id string) ([]string, error) {
	seen := map[string]bool{}
	todo := []string{id}
	edges := 0
	for len(todo) > 0 {
		xid := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if seen[xid] {
			continue
		}
		seen[xid] = true
		if len(seen) > 8192 {
			return nil, &projectionLimit{}
		}
		x := d.byID[xid]
		if x == nil || !available(x) {
			return nil, failure("unavailable")
		}
		for _, p := range x.deps {
			todo = append(todo, p)
			edges++
		}
		if p := x.rec.Header.Links.Origin; p != "" {
			todo = append(todo, p)
			edges++
		}
		for _, p := range d.trustDeps[xid] {
			todo = append(todo, p)
			edges++
		}
		for p := range d.semantic[xid] {
			todo = append(todo, p)
			edges++
		}
		if edges > 65536 {
			return nil, &projectionLimit{}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}
func taskHeader(d *databaseState, owner, task string) *stored {
	heads := currentHeads(d)
	for _, x := range d.records {
		if x.owner == owner && x.rec.Header.Type == record.KindTask && x.rec.Header.Subj.TaskID == task && heads[x.rec.ID] {
			return x
		}
	}
	return nil
}
func (e *DisclosureEngine) writeAllowed(ctx context.Context, c *credentialState, sc scopeState, action TaskMutation, task string) error {
	if !c.channels[S] || !c.actions[action] {
		return failure("write_not_permitted")
	}
	if action == Create && task == "" {
		if sc.repoState == "known" {
			if c.writeKind == "all-local" || c.writeKind == "concrete" && c.writeRepos[sc.repo] {
				return nil
			}
		} else if c.writeKind == "all-local" && c.unscoped {
			return nil
		}
		return failure("write_not_permitted")
	}
	var state, repo string
	err := e.store.conn.QueryRowContext(ctx, "SELECT repo_state,repo FROM task_write_scope WHERE owner=? AND task=?", e.config.OwnerGenesis, task).Scan(&state, &repo)
	if err == sql.ErrNoRows {
		return failure("write_not_permitted")
	}
	if err != nil {
		return failure("storage_error")
	}
	if state == "known" && sc.repoState == "known" && sc.repo == repo && (c.writeKind == "all-local" || c.writeKind == "concrete" && c.writeRepos[repo]) {
		return nil
	}
	if state == "explicitly_unscoped" && sc.repoState != "known" && c.writeKind == "all-local" && c.unscoped {
		return nil
	}
	return failure("write_not_permitted")
}
func taskBrief(d *databaseState, c *credentialState, sc scopeState, owner, task string) ([]outcomeMember, error) {
	root := taskHeader(d, owner, task)
	if !readPermitted(d, c, sc, root) {
		return nil, failure("not_found")
	}
	out := []outcomeMember{{id: root.rec.ID, owner: owner, task: task, role: "task_header", mode: "quoted_source", required: true}}
	var checkpoints, pauses, conclusions []*stored
	head := currentHeads(d)
	for _, x := range d.records {
		if x.owner != owner || x.rec.Header.Subj.TaskID != task || !readPermitted(d, c, sc, x) {
			continue
		}
		switch x.rec.Header.Type {
		case record.KindCheckpoint:
			checkpoints = append(checkpoints, x)
		case record.KindPause:
			pauses = append(pauses, x)
		case record.KindConclusion:
			if head[x.rec.ID] {
				conclusions = append(conclusions, x)
			}
		}
	}
	less := func(xs []*stored) {
		sort.Slice(xs, func(i, j int) bool {
			a, b := xs[i], xs[j]
			return heads.Less(heads.FromHeader(a.rec.ID, &a.rec.Header, a.owner, true), heads.FromHeader(b.rec.ID, &b.rec.Header, b.owner, true))
		})
	}
	less(checkpoints)
	less(pauses)
	less(conclusions)
	if len(checkpoints) > 2 {
		checkpoints = checkpoints[len(checkpoints)-2:]
	}
	if len(pauses) > 1 {
		pauses = pauses[len(pauses)-1:]
	}
	for _, pair := range []struct {
		role string
		xs   []*stored
	}{{"checkpoint", checkpoints}, {"conclusion", conclusions}, {"pause", pauses}} {
		for _, x := range pair.xs {
			out = append(out, outcomeMember{id: x.rec.ID, owner: owner, task: task, role: pair.role, mode: "quoted_source", required: true})
		}
	}
	if len(out) > 64 {
		return nil, failure("history_limit")
	}
	return out, nil
}
func (e *DisclosureEngine) selectRead(ctx context.Context, d *databaseState, c *credentialState, sc scopeState, n disclosuretext.NormalizedCommand, o *operationOutcome) error {
	a := n.Args
	o.kind = "empty_result"
	o.renderer = "empty_v1"
	o.result = "no_hits"
	o.total = ptr64(0)
	head := currentHeads(d)
	switch n.Tool {
	case "local.lookup_record":
		o.lookup, o.includeContent, o.recordKind = true, a.IncludeContent, a.RecordKind
		x := d.byID[a.RecordID]
		if !readPermitted(d, c, sc, x) || a.RecordKind != "" && x.rec.Header.Type != a.RecordKind {
			o.kind = "error_result"
			o.renderer = "error_v1"
			o.result = "not_found"
			o.isError = true
			break
		}
		o.kind = "record_found"
		o.renderer = "record_v1"
		o.result = "found"
		o.members = []outcomeMember{{id: x.rec.ID, owner: x.owner, role: "lookup_root", mode: "quoted_source", required: true}}
		o.total = ptr64(1)
	case "local.resume_task":
		ms, err := taskBrief(d, c, sc, e.config.OwnerGenesis, a.TaskID)
		if err != nil {
			return err
		}
		o.members = ms
		o.task = a.TaskID
		o.action = "resume"
		o.kind = "task_resumed"
		o.renderer = "task_brief_v1"
		o.result = "resumed"
		o.total = ptr64(int64(len(ms)))
	case "local.list_tasks":
		o.listFilter = true
		o.includeCompleted = a.IncludeCompleted
		o.queryRequired = a.Query != ""
		o.query = a.Query
		var roots []*stored
		for _, x := range d.records {
			if x.rec.Header.Type != record.KindTask || !head[x.rec.ID] || !readPermitted(d, c, sc, x) {
				continue
			}
			task := x.rec.Header.Subj.TaskID
			if !a.IncludeCompleted && d.taskStatus(x.owner, task) == "completed" {
				continue
			}
			if a.Query != "" {
				matched, err := currentQueryMatch(ctx, e.store, d, x.rec.ID, a.Query)
				if err != nil {
					return err
				}
				if !matched {
					continue
				}
			}
			roots = append(roots, x)
		}
		sort.Slice(roots, func(i, j int) bool { return roots[i].seq > roots[j].seq })
		o.total = ptr64(int64(len(roots)))
		if len(roots) > a.Limit {
			roots = roots[:a.Limit]
			o.warnings = append(o.warnings, "selection_truncated")
		}
		for _, x := range roots {
			var ms []outcomeMember
			if a.Mode == "detail" {
				var err error
				ms, err = taskBrief(d, c, sc, x.owner, x.rec.Header.Subj.TaskID)
				if err != nil {
					return err
				}
			} else {
				ms = []outcomeMember{{id: x.rec.ID, owner: x.owner, task: x.rec.Header.Subj.TaskID, role: "task_header", mode: "quoted_source", required: true}}
			}
			if len(o.members)+len(ms) > 64 {
				o.warnings = appendUnique(o.warnings, "selection_truncated")
				break
			}
			o.members = append(o.members, ms...)
			o.selected++
		}
		o.kind = "tasks_listed"
		o.renderer = "task_list_" + a.Mode + "_v1"
		o.result = "listed"
		if o.selected == 0 {
			o.kind = "empty_result"
			o.renderer = "empty_v1"
			o.result = "no_visible_tasks"
		}
	default:
		return failure("unsupported_tool")
	}
	if n.Tool != "local.list_tasks" {
		o.selected = int64(len(o.members))
	}
	return nil
}
func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}
func lexicalFTSQuery(q string) string {
	q = strings.TrimSpace(q)
	if q == "" {
		return ""
	}
	if strings.HasPrefix(q, "\"") && strings.HasSuffix(q, "\"") && len(q) > 1 {
		return "\"" + strings.ReplaceAll(q[1:len(q)-1], "\"", "\"\"") + "\""
	}
	var terms []string
	for _, t := range strings.Fields(q) {
		terms = append(terms, "\""+strings.ReplaceAll(t, "\"", "\"\"")+"\"")
	}
	return strings.Join(terms, " AND ")
}
