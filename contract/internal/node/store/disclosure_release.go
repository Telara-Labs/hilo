package store

import (
	"context"
	"database/sql"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/replay"
	"github.com/Telara-Labs/hilo/contract/view"
)

type renderPlan struct {
	id, nonce, text, version, empty string
	unavailable                     bool
	result                          disclosuretext.RenderResult
	items                           []disclosuretext.RenderItem
	count                           *countSnapshot
	warnings                        []string
	continuation                    string
	units                           map[[2]int]string
	deps                            map[string]bool
}

// Populate current trust dependencies for the complete reachable graph, including
// binding/session nodes discovered by an earlier pass. Original outcome members
// are immutable; this calculation is only a current render view.
func completeRenderTrust(d *databaseState, roots []string) error {
	work := 0
	charge := func(n int) error {
		if n < 0 || n > 1048576-work {
			return failure("render_limit")
		}
		work += n
		return nil
	}
	if err := charge(len(d.records)); err != nil {
		return err
	}
	callOps := map[string]bool{}
	for _, x := range d.records {
		if _, ok := x.rec.Body.(*record.CallBody); ok && available(x) {
			callOps[x.rec.Header.Op] = true
		}
	}
	includeTrust := false
	previous := map[string]bool{}
	for {
		seen := map[string]bool{}
		pending := append([]string(nil), roots...)
		edges := 0
		for len(pending) > 0 {
			id := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			if err := charge(1); err != nil {
				return err
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			if len(seen) > 8192 {
				return failure("render_limit")
			}
			x := d.byID[id]
			if x == nil {
				continue
			}
			nodeEdges := map[string]bool{}
			add := func(p string) error {
				if nodeEdges[p] {
					return nil
				}
				nodeEdges[p] = true
				edges++
				if edges > 65536 {
					return failure("render_limit")
				}
				pending = append(pending, p)
				return nil
			}
			for _, p := range x.deps {
				if err := add(p); err != nil {
					return err
				}
			}
			if p := x.rec.Header.Links.Origin; p != "" {
				if err := add(p); err != nil {
					return err
				}
			}
			for p := range d.semantic[id] {
				if err := add(p); err != nil {
					return err
				}
			}
			if includeTrust {
				for _, p := range d.trustDeps[id] {
					if err := add(p); err != nil {
						return err
					}
				}
			}
		}
		if includeTrust && len(seen) == len(previous) {
			same := true
			for id := range seen {
				if !previous[id] {
					same = false
					break
				}
			}
			if same {
				return nil
			}
		}
		ids := make([]string, 0, len(seen))
		// The next trust calculation also visits the reached nodes and their
		// ordinary/semantic edges; charge it to this same multi-pass budget.
		if err := charge(edges + len(seen)); err != nil {
			return err
		}
		// Charge the bounded inputs to current binding/session scans before doing
		// them. Unrelated ordinary records are not all made trust roots.
		if err := charge(len(d.records)); err != nil {
			return err
		}
		for id := range seen {
			ids = append(ids, id)
			if x := d.byID[id]; x != nil && (x.rec.Header.Subj.SessionKey != "" || callOps[x.rec.Header.Op]) {
				if err := charge(8 * len(d.records)); err != nil {
					return err
				}
			}
		}
		sort.Strings(ids)
		if err := d.computeTrust(ids); err != nil {
			return err
		}
		previous = seen
		includeTrust = true
	}
}

func (e *DisclosureEngine) prepareRender(ctx context.Context, d *databaseState, c *credentialState, sc scopeState, o *operationOutcome, pool *disclosureEntropy, budget ByteBudget, before int64, isNew bool) (*renderPlan, error) {
	r := &renderPlan{units: map[[2]int]string{}, deps: map[string]bool{}}
	ids := make([]string, 0, len(o.members))
	for _, m := range o.members {
		ids = append(ids, m.id)
		ids = append(ids, m.deps...)
	}
	if err := completeRenderTrust(d, ids); err != nil {
		return nil, err
	}
	if isMutationTool(o.tool) {
		task := o.task
		if isNew && o.tool == "local.create_task" {
			task = ""
		}
		if err := e.writeAllowed(ctx, c, sc, fixedToolAction(o.tool), task); err != nil {
			if Code(err) == "storage_error" {
				return nil, err
			}
			r.unavailable = true
		}
	}
	if !c.channels[S] || c.readKind == "deny" {
		r.unavailable = true
	}
	head := currentHeads(d)
	var query string
	var resources []string
	if o.selection != "" {
		var raw string
		err := e.store.conn.QueryRowContext(ctx, "SELECT query,resource_types FROM selection_payload WHERE selection=?", o.selection).Scan(&query, &raw)
		if err != nil {
			if err != sql.ErrNoRows {
				return nil, failure("storage_error")
			}
			if !isNew {
				r.unavailable = true
			}
		} else if raw != "" {
			resources = strings.Split(raw, ",")
		}
	}
	for _, m := range o.members {
		x := d.byID[m.id]
		eligible := readPermitted(d, c, sc, x)
		var currentDeps []string
		if eligible {
			var err error
			currentDeps, err = dependencyClosure(d, m.id)
			if err != nil {
				if Code(err) != "unavailable" {
					return nil, err
				}
				eligible = false
			}
		}
		if eligible && o.listFilter {
			if !o.includeCompleted && x.rec.Header.Subj.TaskID != "" && d.taskStatus(x.owner, x.rec.Header.Subj.TaskID) == "completed" {
				eligible = false
			}
			if o.queryRequired {
				if o.query == "" {
					eligible = false
				} else if x.rec.Header.Type == record.KindTask {
					match, err := currentQueryMatch(ctx, e.store, d, m.id, o.query)
					if err != nil {
						return nil, err
					}
					eligible = eligible && match
				}
			}
		}
		if eligible && m.role != "lookup_root" && !head[m.id] {
			eligible = false
		}
		if eligible {
			for _, id := range append(append([]string(nil), m.deps...), currentDeps...) {
				if !readPermitted(d, c, sc, d.byID[id]) {
					eligible = false
					break
				}
			}
		}
		fields := d.fields[m.id]
		if o.lookup && !o.includeContent {
			fields = nil
		}
		if m.mode == "fresh_projection" {
			fields = freshFields(d, m.id)
			if len(fields) == 0 {
				eligible = false
			}
			if !isNew && eligible {
				matched, err := currentQueryMatch(ctx, e.store, d, m.id, query)
				if err != nil {
					return nil, err
				}
				if !matched {
					eligible = false
				}
			}
		}
		if !eligible {
			if m.required {
				r.unavailable = true
			} else {
				r.warnings = appendUnique(r.warnings, "optional_evidence_unavailable")
			}
			continue
		}
		r.deps[m.id] = true
		for _, id := range m.deps {
			r.deps[id] = true
		}
		for _, id := range currentDeps {
			r.deps[id] = true
		}
		labels, err := releaseLabels(d, x)
		if err != nil {
			return nil, err
		}
		item := disclosuretext.RenderItem{LID: x.rec.Header.LID, ID: x.rec.ID, Labels: labels}
		item.TaskID = x.rec.Header.Subj.TaskID
		if o.lookup && o.recordKind != "" && x.rec.Header.Type != o.recordKind {
			return nil, failure("unavailable")
		}
		if m.mode == "quoted_source" {
			unavailableFresh := false
			possible := false
			for _, f := range fields {
				if f.class == disclosuretext.ClassificationUnavailable {
					unavailableFresh = true
				}
				if f.class == disclosuretext.InjectedSource || f.class == disclosuretext.PossibleMemoryFrame {
					possible = true
				}
			}
			if unavailableFresh {
				item.Labels.Evidence = "fresh_projection_unavailable"
			}
			if possible {
				item.Labels.Evidence = "possible_recalled_context"
			}
		}
		ordinals := map[string]int{}
		itemIndex := len(r.items)
		for _, f := range fields {
			value := f.value
			if m.mode == "fresh_projection" {
				value = f.projection
			}
			fieldIndex := len(item.Fields)
			ordinal := ordinals[f.family]
			ordinals[f.family]++
			if fieldIndex >= 4096 || ordinal > 4095 {
				return nil, failure("render_limit")
			}
			// Presentation ordinals are local to this rendered item. The
			// private unit map keeps exact event/revision identity even when
			// multiple events have equal field values and source ordinals.
			unit := x.rec.ID + "/" + strconv.Itoa(fieldIndex)
			if f.event != "" {
				unit = x.rec.ID + "/" + f.event + "/" + f.revision
			}
			r.units[[2]int{itemIndex, fieldIndex}] = unit
			item.Fields = append(item.Fields, disclosuretext.RenderField{Family: f.family, Ordinal: ordinal, Value: value})
		}
		if x.rec.Header.Type == record.KindCall {
			item.Fields = []disclosuretext.RenderField{{Family: "text", Value: "Recorded local call."}}
		}
		r.items = append(r.items, item)
	}
	if len(r.items) > 64 {
		return nil, failure("render_limit")
	}
	if r.unavailable {
		// An unavailable proposal cannot discard newly verified restrictive
		// facts about already retained bodies. Settle only the minimal hold.
		if lateErasureCause(d) != "" {
			if _, err := e.store.effectDelta(ctx, d); err != nil {
				return nil, e.store.refuseBulk(ctx, d, err)
			}
			return nil, e.store.refuseVerified(ctx, d, failure("privacy_hold_required"))
		}
		r.text = replay.Unavailable
		return r, nil
	}
	var err error
	r.id, err = pool.uuid(ctx, e.store, "attempt", "render_attempt", "id")
	if err != nil {
		return nil, err
	}
	for _, nonce := range pool.nonces {
		var n int
		if e.store.conn.QueryRowContext(ctx, "SELECT count(*) FROM render_attempt WHERE owner=? AND nonce=?", e.config.OwnerGenesis, nonce).Scan(&n) != nil {
			return nil, failure("storage_error")
		}
		if n == 0 {
			r.nonce = nonce
			break
		}
	}
	if r.nonce == "" {
		return nil, failure("entropy_collision")
	}
	// Count summaries are always current and query-independent. Original wider
	// summaries/categories never become a replay serializer.
	if o.tool == "local.lexical_search" || o.tool == "local.next_page" {
		if o.result != "query_required" {
			if isNew && o.count != nil && len(resources) == 0 { // Resources may be explicitly empty; copy only the original count identity.
				r.count = &countSnapshot{id: "", state: o.count.state, reason: o.count.reason, scopeKey: o.count.scopeKey, generation: d.generation, records: o.count.records, total: o.count.total, searchable: o.count.searchable, excluded: o.count.excluded, unclassified: o.count.unclassified, recordsExcluded: o.count.recordsExcluded}
				r.count.id, err = pool.uuid(ctx, e.store, "snapshot", "projection_count_snapshot", "id")
			} else {
				r.count, err = e.countProjection(ctx, d, c, sc, resources, pool)
			}
			if err != nil {
				return nil, err
			}
			r.warnings = append(r.warnings, countWarnings(r.count, true)...)
		}
	}
	sameFence := isNew || (o.grantEpoch == c.epoch && o.scopeGeneration == sc.generation && o.evidence == sc.evidence && o.dbGeneration == before && o.scope == sc.id)
	for _, w := range o.warnings {
		switch w {
		case "lexical_subset", "embeddings_unavailable", "no_summary_supplied":
			r.warnings = appendUnique(r.warnings, w)
		case "selection_truncated", "count_unknown":
			if sameFence {
				r.warnings = appendUnique(r.warnings, w)
			}
		}
	}
	if !sameFence {
		r.warnings = appendUnique(r.warnings, "counts_withheld")
	}
	if o.kind == "empty_result" {
		r.empty, err = emptyDisplay(o.result)
		if err != nil {
			return nil, err
		}
	}
	if o.cursor != "" {
		var state, engine string
		var expected, generation, epoch, evidence int64
		err = e.store.conn.QueryRowContext(ctx, "SELECT c.state,c.expected_generation,s.generation,s.grant_epoch,s.engine,s.evidence FROM query_cursor c JOIN query_selection s ON s.id=c.selection WHERE c.id=?", o.cursor).Scan(&state, &expected, &generation, &epoch, &engine, &evidence)
		deadline, ok := e.deadlines[o.selection]
		if isNew {
			r.continuation = o.cursor
		} else if err == nil && ok && time.Now().Before(deadline) && state == "ready" && expected == before && generation == sc.generation && epoch == c.epoch && engine == e.id && evidence == sc.evidence {
			r.continuation = o.cursor
		} else {
			r.warnings = appendUnique(r.warnings, "cursor_expired")
		}
	}
	overlay, err := disclosuretext.NewAssemblyPolicy(d.tenant.body())
	if err != nil {
		return nil, failure("policy_violation")
	}
	input := disclosuretext.RenderInput{Overlay: overlay, CallRef: o.callRef, Nonce: r.nonce, Items: r.items, Budget: budget, EmptyDisplayCode: r.empty, Warnings: r.warnings, SelectionCount: ptr64(o.selected), SelectionAsOf: o.createdSeq, Continuation: r.continuation}
	if r.count != nil {
		input.Counts = &disclosuretext.CountSummary{State: r.count.state, AsOfGeneration: r.count.generation, RecordUnits: r.count.records, TotalUnits: r.count.total, SearchableUnits: r.count.searchable, ExcludedUnits: r.count.excluded, UnclassifiedUnits: r.count.unclassified, RecordsWithExclusions: r.count.recordsExcluded}
	}
	if o.kind == "error_result" {
		input.FixedErrorCode = o.result
		input.Warnings = nil
		input.Counts = nil
		input.Continuation = ""
		r.warnings = nil
		r.count = nil
	}
	result, err := disclosuretext.Render(input)
	if err != nil {
		return nil, failure(disclosuretext.Code(err))
	}
	seen := map[int]bool{}
	for _, i := range result.ShownIndices {
		if i < 0 || i >= len(r.items) || seen[i] {
			return nil, failure("outcome_render_unavailable")
		}
		seen[i] = true
	}
	r.result = result
	r.text = result.Text
	r.version = record.H("render-freshness", record.ContractVersion, disclosuretext.RendererVersion, strconv.FormatInt(d.generation, 10), strconv.FormatInt(d.authorityEpoch, 10), strconv.FormatInt(c.epoch, 10), strconv.FormatInt(sc.generation, 10), strconv.FormatInt(sc.evidence, 10), e.ruleset.Fingerprint(), strconv.Itoa(budget.MaxBytes))
	// A new, still-unreleased proposal does not create an owner-wide hold
	// merely because no further exposure root can be retained.
	if len(d.exposures)+len(result.ShownIndices) > 8192 {
		return nil, failure("exposure_limit")
	}
	// Establish the complete current candidate against durable exposures before
	// any discardable proposal mutates its reduction state. Every candidate
	// relation, including post-purge facts, is checked before ordinary SQL.
	if err = d.prepareRelations(); err != nil {
		return nil, err
	}
	settlePrior := func() (*renderPlan, error) {
		if _, err := e.store.effectDelta(ctx, d); err != nil {
			return nil, e.store.refuseBulk(ctx, d, err)
		}
		return nil, e.store.refuseVerified(ctx, d, failure("exposure_limit"))
	}
	if len(result.ShownIndices) == 0 {
		if _, err = e.store.effectDelta(ctx, d); err != nil {
			return nil, e.store.refuseBulk(ctx, d, err)
		}
		return r, nil
	}
	prior, checkpointErr := d.checkpointVerified()
	if checkpointErr != nil {
		if _, limited := checkpointErr.(*projectionLimit); limited {
			return settlePrior()
		}
		return nil, checkpointErr
	}
	priorExposureCount := len(d.exposures)
	for _, i := range result.ShownIndices {
		item := r.items[i]
		id, err := pool.uuid(ctx, e.store, "exposure", "exposure", "id")
		if err != nil {
			return nil, err
		}
		evidenceSet := map[string]bool{}
		for _, eid := range d.directEvidence[item.ID] {
			evidenceSet[eid] = true
		}
		if len(evidenceSet) > 64 {
			return nil, failure("evidence_limit")
		}
		var evidence []string
		for eid := range evidenceSet {
			evidence = append(evidence, eid)
		}
		sort.Strings(evidence)
		d.exposures = append(d.exposures, &exposureFact{evidence: evidence, id: id, owner: e.config.OwnerGenesis, machine: e.config.MachineID, credential: c.id, scope: sc.id, root: item.ID, source: o.callRef, attempt: r.id, fence: d.nextSeq - 1, affects: map[string]bool{}})
	}
	err = d.rebuild(e.store.opts)
	if err == nil {
		err = d.prepareRelations()
	}
	if err != nil {
		if _, limited := err.(*projectionLimit); limited && len(d.exposures) > priorExposureCount {
			// Preserve spent budgets. The exact prior candidate was already
			// reconstructed completely in this same writer; rebuilding it after
			// proposal exhaustion could manufacture an unrelated owner hold.
			d.restoreVerified(prior)
			return settlePrior()
		}
		return nil, err
	}
	for _, m := range o.members {
		if m.required && !readPermitted(d, c, sc, d.byID[m.id]) {
			return nil, failure("unavailable")
		}
	}
	if _, err = e.store.effectDelta(ctx, d); err != nil {
		return nil, e.store.refuseBulk(ctx, d, err)
	}
	return r, nil
}
func (e *DisclosureEngine) persistRender(ctx context.Context, d *databaseState, c *credentialState, sc scopeState, o *operationOutcome, r *renderPlan) error {
	if r.unavailable {
		if _, err := e.store.conn.ExecContext(ctx, "DELETE FROM render_body WHERE attempt IN(SELECT id FROM render_attempt WHERE owner=? AND credential=? AND op=?)", o.owner, c.id, o.op); err != nil {
			return failure("storage_error")
		}
		return nil
	}
	if _, err := e.store.conn.ExecContext(ctx, "INSERT INTO render_attempt VALUES(?,?,?,?,?,?,?,?,?,?,?,1)", r.id, o.owner, c.id, o.op, sc.id, sc.generation, r.nonce, r.version, d.generation, c.epoch, sc.evidence); err != nil {
		return failure("storage_error")
	}
	for ordinal, i := range r.result.ShownIndices {
		item := r.items[i]
		if _, err := e.store.conn.ExecContext(ctx, "INSERT INTO render_item VALUES(?,?,?,?,?)", r.id, ordinal, o.owner, item.LID, item.ID); err != nil {
			return failure("storage_error")
		}
	}
	for id := range r.deps {
		if _, err := e.store.conn.ExecContext(ctx, "INSERT INTO render_dep VALUES(?,?)", r.id, id); err != nil {
			return failure("storage_error")
		}
	}
	if _, err := e.store.conn.ExecContext(ctx, "INSERT INTO render_body VALUES(?,?)", r.id, []byte(r.text)); err != nil {
		return failure("storage_error")
	}
	for i, w := range r.warnings {
		if _, err := e.store.conn.ExecContext(ctx, "INSERT INTO render_warning VALUES(?,?,?)", r.id, i, w); err != nil {
			return failure("storage_error")
		}
	}
	if r.empty != "" {
		if _, err := e.store.conn.ExecContext(ctx, "INSERT INTO render_empty_result VALUES(?,?)", r.id, r.empty); err != nil {
			return failure("storage_error")
		}
	}
	units := map[string]bool{}
	for _, u := range r.result.ShownUnits {
		if u.ItemIndex < 0 || u.ItemIndex >= len(r.items) || u.FieldIndex < 0 || u.FieldIndex >= len(r.items[u.ItemIndex].Fields) {
			return failure("outcome_render_unavailable")
		}
		unit, ok := r.units[[2]int{u.ItemIndex, u.FieldIndex}]
		if !ok {
			unit = strconv.Itoa(u.ItemIndex) + "/" + strconv.Itoa(u.FieldIndex)
		}
		units[unit] = true
	}
	originalState := "withheld"
	var total any
	if o.dbGeneration == d.generation-1 && o.grantEpoch == c.epoch && o.scope == sc.id && o.scopeGeneration == sc.generation && o.evidence == sc.evidence {
		originalState = "shown"
		total = nullInt(o.total)
	}
	if o.total == nil {
		originalState = "not_requested"
		total = nil
	}
	if _, err := e.store.conn.ExecContext(ctx, "INSERT INTO render_visible_counts VALUES(?,?,?,?,?,?)", r.id, len(r.result.ShownIndices), len(units), r.result.Omitted, originalState, total); err != nil {
		return failure("storage_error")
	}
	if r.count != nil {
		if err := e.store.persistCount(ctx, o.owner, c.id, r.count); err != nil {
			return err
		}
		if _, err := e.store.conn.ExecContext(ctx, "INSERT INTO render_projection_summary VALUES(?,?)", r.id, r.count.id); err != nil {
			return failure("storage_error")
		}
	}
	return nil
}
func currentQueryMatch(ctx context.Context, s *Store, d *databaseState, id, query string) (bool, error) {
	if query == "" {
		return false, nil
	}
	text := freshText(d, id)
	if text == "" {
		return false, nil
	}
	var indexed string
	err := s.conn.QueryRowContext(ctx, "SELECT text FROM passage WHERE id=?", id).Scan(&indexed)
	if err == sql.ErrNoRows {
		return false, failure("projection_unavailable")
	}
	if err != nil {
		return false, failure("storage_error")
	}
	if indexed != text {
		return false, failure("projection_unavailable")
	}
	var n int
	if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM search JOIN passage p ON p.rowid=search.rowid WHERE search MATCH ? AND p.id=?", lexicalFTSQuery(query), id).Scan(&n) != nil {
		return false, failure("query_failed")
	}
	return n > 0, nil
}
func (e *DisclosureEngine) Acknowledge(ctx context.Context, h ClientHandle, ack ACK) (ACKReceipt, error) {
	var out ACKReceipt
	if e == nil || e.store == nil || len(ack.Nonce) != 20 || len(ack.Items) > 64 {
		return out, failure("invalid_ack")
	}
	for _, c := range ack.Nonce {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return out, failure("invalid_ack")
		}
	}
	got := make([]string, 0, len(ack.Items))
	seen := map[string]bool{}
	for _, m := range ack.Items {
		if !record.IsHex64(m.LID) || !record.IsHex64(m.ID) {
			return out, failure("invalid_ack")
		}
		key := m.LID + "@" + m.ID
		if seen[key] {
			return out, failure("invalid_ack")
		}
		seen[key] = true
		got = append(got, key)
	}
	sort.Strings(got)
	err := e.store.writeMode(ctx, true, func() error {
		if _, err := e.client(ctx, h); err != nil {
			return err
		}
		var attempt, scope string
		var generation int64
		err := e.store.conn.QueryRowContext(ctx, "SELECT id,scope,original_generation FROM render_attempt WHERE owner=? AND credential=? AND nonce=?", e.config.OwnerGenesis, h.credential, ack.Nonce).Scan(&attempt, &scope, &generation)
		if err == sql.ErrNoRows {
			return failure("invalid_ack")
		}
		if err != nil {
			return failure("storage_error")
		}
		rows, err := e.store.conn.QueryContext(ctx, "SELECT lid,id FROM render_item WHERE attempt=? ORDER BY lid,id", attempt)
		if err != nil {
			return failure("storage_error")
		}
		var expected []string
		for rows.Next() {
			var lid, id string
			if rows.Scan(&lid, &id) != nil {
				rows.Close()
				return failure("storage_error")
			}
			expected = append(expected, lid+"@"+id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return failure("storage_error")
		}
		sort.Strings(expected)
		if strings.Join(got, "\n") != strings.Join(expected, "\n") {
			return failure("invalid_ack")
		}
		var current int64
		if e.store.conn.QueryRowContext(ctx, "SELECT generation FROM local_scope WHERE id=? AND credential=?", scope, h.credential).Scan(&current) != nil {
			return failure("invalid_ack")
		}
		var existing int
		if e.store.conn.QueryRowContext(ctx, "SELECT count(*) FROM attempt_ack WHERE attempt=?", attempt).Scan(&existing) != nil {
			return failure("storage_error")
		}
		for _, m := range ack.Items {
			if _, err = e.store.conn.ExecContext(ctx, "INSERT OR IGNORE INTO delivery_confirmation VALUES(?,?,?,?,?,?)", h.credential, scope, generation, m.LID, m.ID, attempt); err != nil {
				return failure("storage_error")
			}
		}
		// Exact confirmation changes no source or selection eligibility. It is
		// generation-neutral and never renews or rebases a cursor.
		if existing == 0 {
			if _, err = e.store.conn.ExecContext(ctx, "INSERT INTO attempt_ack VALUES(?)", attempt); err != nil {
				return failure("storage_error")
			}
		}
		out.Status = "confirmed"
		if existing > 0 {
			out.Status = "already_confirmed"
		}
		if current != generation {
			out.Status = "stale_generation"
		}
		return nil
	})
	if err != nil {
		return ACKReceipt{}, err
	}
	return out, nil
}

// releaseLabels computes the effective label of one released record. A
// record whose trust was not computed, or whose computed coverage is not a
// known value, refuses the release instead of rendering without a label.
func releaseLabels(d *databaseState, x *stored) (disclosuretext.Labels, error) {
	trust, ok := d.trust[x.rec.ID]
	if !ok || (trust.Coverage != "complete" && trust.Coverage != "incomplete") {
		return disclosuretext.Labels{}, failure("label_unavailable")
	}
	if !view.Eligible(view.ReadContext{Channel: "S", Kind: x.rec.Header.Type, Verified: true, OwnGenesis: true, GrantAllowed: true, Trust: trust}) {
		return disclosuretext.Labels{}, failure("label_unavailable")
	}
	return disclosuretext.Labels{Source: "local", Kind: string(x.rec.Header.Type), Signature: "verified", Coverage: trust.Coverage, Trust: strings.Join(trust.Effective(), ","), Evidence: "agent-declared"}, nil
}
