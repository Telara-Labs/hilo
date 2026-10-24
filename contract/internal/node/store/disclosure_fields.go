package store

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

const disclosureBuilderVersion = "local-task-builder/1"

// Count work is optional and can become unknown independently of complete
// authoritative field classification. Neither limit truncates retained facts.
const disclosureCountUnitLimit = 65536
const disclosureProjectionFieldLimit = 131072

func taintValues(tags map[string]bool) []string {
	out := make([]string, 0, len(tags))
	for tag := range tags {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

type projectionField struct {
	family, value, event, revision, eventKind string
	ordinal                                   int
	class, reason, projection                 string
}

func enumerateFields(r *record.Record) []projectionField {
	var out []projectionField
	add := func(family, value string, n int) {
		if value != "" {
			out = append(out, projectionField{family: family, value: value, ordinal: n})
		}
	}
	switch b := r.Body.(type) {
	case *record.TaskBody:
		add("name", b.Name, 0)
		add("goal", b.Goal, 0)
		if b.Anchors != nil {
			for i, v := range b.Anchors.Files {
				add("anchor_file", v, i)
			}
		}
	case *record.CheckpointBody:
		add("milestone", b.Milestone, 0)
		add("next_steps", b.NextSteps, 0)
		for i, v := range b.TaskTree {
			add("step_title", v.Title, i)
		}
	case *record.PauseBody:
		add("resume_context", b.ResumeContext, 0)
		add("progress_notes", b.ProgressNotes, 0)
		add("handoff_hint", b.HandoffHint, 0)
	case *record.ConclusionBody:
		add("request", b.Request, 0)
		family := "text"
		if b.Source == "explicit" {
			family = "final_summary"
		}
		add(family, b.Text, 0)
		for i, v := range b.ChangesMade {
			add("change_made", v, i)
		}
	case *record.SessionBody:
		add("title", b.Title, 0)
		add("cwd", b.Cwd, 0)
		if b.Repo != nil {
			for i, v := range []string{b.Repo.Remote, b.Repo.Branch, b.Repo.CommitStart, b.Repo.CommitEnd, b.Repo.CommitBasis} {
				add("repo", v, i)
			}
		}
	case *record.DigestBody:
		for i, v := range append(append(append(append([]string{}, b.Requests...), b.Outcome), b.Touched...), b.Failures...) {
			add("digest_text", v, i)
		}
	case *record.RollupBody:
		add("rollup_text", b.Text, 0)
	case *record.ChunkBody:
		for _, e := range b.Events {
			start := len(out)
			if e.Text != nil {
				add("text_body", e.Text.Body, 0)
			}
			if e.Call != nil {
				add("call_tool", e.Call.Tool, 0)
				add("call_server", e.Call.MCPServer, 0)
				add("call_tool", e.Call.MCPTool, 1)
				add("call_command", e.Call.Command, 0)
				keys := make([]string, 0, len(e.Call.Args))
				for k := range e.Call.Args {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for i, k := range keys {
					add("call_argument", e.Call.Args[k], i)
				}
			}
			if e.Result != nil {
				add("result_excerpt", e.Result.Excerpt, 0)
				add("result_error", e.Result.ErrorClass, 0)
				for i, v := range e.Result.OutPaths {
					add("result_path", v, i)
				}
				for i, v := range e.Result.OutTokens {
					add("result_token", v, i)
				}
			}
			keys := make([]string, 0, len(e.Meta))
			for k := range e.Meta {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for i, k := range keys {
				add("meta", e.Meta[k], i)
			}
			for i := start; i < len(out); i++ {
				out[i].event = e.ID
				out[i].revision = e.Revision
				out[i].eventKind = e.Kind
			}
		}
	}
	return out
}
func completeField(d *databaseState, x *stored, f projectionField) bool {
	fact, ok := d.completeness[fieldKey{x.rec.ID, f.event, f.revision, f.family, f.ordinal}]
	if !ok || !fact.trusted || x.rec.Header.Prov != record.ProvMCPExplicit || fact.full < 0 || fact.retained != int64(len(f.value)) || fact.builder != disclosureBuilderVersion || f.event != "" {
		return false
	}
	a, ok := d.attrs[x.rec.ID]
	if !ok || a.kind != "fixed-mcp-builder" || a.owner != x.owner {
		return false
	}
	schema := ""
	switch x.rec.Header.Type {
	case record.KindTask:
		schema = "create_task_args_v1"
	case record.KindCheckpoint:
		schema = "checkpoint_task_args_v1"
	case record.KindPause:
		schema = "pause_task_args_v1"
	case record.KindConclusion:
		schema = "complete_task_args_v1"
	default:
		return false
	}
	if fact.schema != schema {
		return false
	}
	switch fact.sourceKind {
	case "mcp_argument":
		return fact.sourceSlot == f.family && fact.sourceOrdinal == f.ordinal && fact.full == fact.retained
	case "mcp_generated":
		return f.family == "name" && f.value == "Local task" && fact.sourceSlot == "constant_task_name" && fact.full == fact.retained
	case "mcp_generated_name_from_goal":
		b, ok := x.rec.Body.(*record.TaskBody)
		if !ok || f.family != "name" || fact.sourceSlot != "goal" || fact.full != int64(len(b.Goal)) {
			return false
		}
		goal := []rune(strings.TrimSpace(b.Goal))
		if len(goal) > 100 {
			goal = goal[:100]
		}
		return f.value == string(goal) && len(goal) > 0
	}
	return false
}
func (d *databaseState) classifyFields() error {
	d.fields = map[string][]projectionField{}
	work := &disclosuretext.WorkBudget{}
	rules, e := localpolicy.Ruleset()
	if e != nil {
		return failure("ruleset_unavailable")
	}
	overlay, e := localpolicy.TenantOverlay(d.tenant.body())
	if e != nil {
		return failure("policy_violation")
	}
	totalFields := 0
	for _, x := range d.records {
		if !d.policyReadAllowed(x) {
			d.fields[x.rec.ID] = nil
			continue
		}
		fields := enumerateFields(x.rec)
		totalFields += len(fields)
		if totalFields > disclosureProjectionFieldLimit {
			return &projectionLimit{}
		}
		for i := range fields {
			f := &fields[i]
			f.class = disclosuretext.ClassificationUnavailable
			f.reason = "completeness_unavailable"
			if f.eventKind == "injected_context" {
				f.class = disclosuretext.InjectedSource
				f.reason = "injected_context"
				continue
			}
			fact := d.completeness[fieldKey{x.rec.ID, f.event, f.revision, f.family, f.ordinal}]
			if !completeField(d, x, *f) || fact.ruleset != rules.Fingerprint() {
				continue
			}
			p, err := disclosuretext.PrepareField(disclosuretext.FieldInput{Family: f.family, EventKind: f.eventKind, Value: f.value, Ordinal: f.ordinal, Overlay: overlay}, work)
			if err != nil {
				f.reason = disclosuretext.Code(err)
				continue
			}
			var matched []int
			lookupComplete := true
			for j, n := range p.NonceCandidates() {
				known, exists := d.nonces[n]
				if !exists {
					if d.nonceLookups >= 8192 {
						f.class = disclosuretext.ClassificationUnavailable
						f.reason = "classification_limit"
						lookupComplete = false
						break
					}
					d.nonceLookups++
					var count int
					if d.store == nil || d.store.conn.QueryRowContext(d.ctx, "SELECT count(*) FROM render_attempt WHERE owner=? AND nonce=?", x.owner, n).Scan(&count) != nil {
						return failure("storage_error")
					}
					known = count > 0
					d.nonces[n] = known
				}
				if known {
					matched = append(matched, j)
				}
			}
			if !lookupComplete {
				continue
			}
			c := disclosuretext.ClassifyField(p, matched)
			f.class = c.Class
			f.reason = c.Reason
			if f.class == disclosuretext.NoDetectedMarker {
				f.projection = p.ProjectionValue()
			}
		}
		for i := range fields {
			f := &fields[i]
			fact := d.completeness[fieldKey{x.rec.ID, f.event, f.revision, f.family, f.ordinal}]
			if fact.sourceKind == "mcp_generated_name_from_goal" {
				found := false
				for _, source := range fields {
					if source.family == "goal" {
						found = true
						if source.class != disclosuretext.NoDetectedMarker {
							f.class = source.class
							f.reason = "derived_source_restricted"
							f.projection = ""
						}
					}
				}
				if !found {
					f.class = disclosuretext.ClassificationUnavailable
					f.reason = "derived_source_unavailable"
					f.projection = ""
				}
			}
		}
		// A native content event is one projection unit; one restricted field excludes
		// every sibling field of that event, without changing any admitted seal.
		classes := map[string]string{}
		for _, f := range fields {
			if f.event == "" {
				continue
			}
			old := classes[f.event]
			if classRank(f.class) > classRank(old) {
				classes[f.event] = f.class
			}
		}
		for i := range fields {
			if c := classes[fields[i].event]; fields[i].event != "" && c != disclosuretext.NoDetectedMarker {
				fields[i].class = c
				fields[i].projection = ""
			}
		}
		// Individual fields can be safe while their normalized join matches a
		// tenant shape. Apply the same assembled-text gate as the renderer, and
		// retain its source mapping when excluding the contributing fields.
		values := make([]string, len(fields))
		for i, f := range fields {
			if f.class == disclosuretext.NoDetectedMarker {
				values[i] = f.projection
			}
		}
		assembly, err := disclosuretext.CheckAssembly(values, overlay, work)
		if err != nil || assembly.Restricted {
			exclude := func(i int) {
				fields[i].class = disclosuretext.ClassificationUnavailable
				fields[i].reason = "assembled_policy_restricted"
				if err != nil {
					fields[i].reason = disclosuretext.Code(err)
				}
				fields[i].projection = ""
			}
			if err != nil {
				for i, value := range values {
					if value != "" {
						exclude(i)
					}
				}
			} else {
				for _, span := range assembly.Spans {
					exclude(span.Field)
				}
			}
		}
		d.fields[x.rec.ID] = fields
	}
	return nil
}
func classRank(c string) int {
	switch c {
	case disclosuretext.InjectedSource:
		return 4
	case disclosuretext.ClassificationUnavailable:
		return 3
	case disclosuretext.PossibleMemoryFrame:
		return 2
	case disclosuretext.NoDetectedMarker:
		return 1
	}
	return 0
}
func (s *Store) persistFieldProjection(ctx context.Context, d *databaseState) error {
	if err := d.classifyFields(); err != nil {
		return err
	}
	if err := d.projectObservedTaint(); err != nil {
		return err
	}
	previous := map[string][]string{}
	rows, err := s.conn.QueryContext(ctx, "SELECT owner,id,event,revision,family,ordinal,classifier,class,reason FROM record_field_projection LIMIT 131073")
	if err != nil {
		return failure("storage_error")
	}
	n := 0
	for rows.Next() {
		var owner, id, event, revision, family, version, class, reason string
		var ordinal int
		if rows.Scan(&owner, &id, &event, &revision, &family, &ordinal, &version, &class, &reason) != nil {
			rows.Close()
			return failure("storage_error")
		}
		n++
		if n > disclosureProjectionFieldLimit {
			rows.Close()
			return &projectionLimit{}
		}
		if owner != s.opts.PinnedGenesisID || d.byID[id] == nil {
			rows.Close()
			return failure("corrupt_database")
		}
		previous[id] = append(previous[id], projectionFieldKey(event, revision, family, ordinal, version, class, reason))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failure("storage_error")
	}
	changedFields := map[string]bool{}
	for _, x := range d.records {
		var current []string
		for _, f := range d.fields[x.rec.ID] {
			current = append(current, projectionFieldKey(f.event, f.revision, f.family, f.ordinal, disclosuretext.ClassifierVersion, f.class, f.reason))
		}
		sort.Strings(current)
		sort.Strings(previous[x.rec.ID])
		if strings.Join(current, "\n") != strings.Join(previous[x.rec.ID], "\n") {
			changedFields[x.rec.ID] = true
			x.generation = d.generation
			for _, table := range []string{"vector", "projection_job"} {
				if _, err = s.conn.ExecContext(ctx, "DELETE FROM "+table+" WHERE id=?", x.rec.ID); err != nil {
					return failure("storage_error")
				}
			}
		}
	}
	// Every authoritative row is recomputed above. Retain byte-identical
	// classifications and replace complete changed record projections only.
	for id, fields := range d.fields {
		if !changedFields[id] {
			continue
		}
		if _, err := s.conn.ExecContext(ctx, "DELETE FROM record_field_projection WHERE owner=? AND id=?", s.opts.PinnedGenesisID, id); err != nil {
			return failure("storage_error")
		}
		for _, f := range fields {
			if _, err := s.conn.ExecContext(ctx, "INSERT INTO record_field_projection VALUES(?,?,?,?,?,?,?,?,?)", s.opts.PinnedGenesisID, id, f.event, f.revision, f.family, f.ordinal, disclosuretext.ClassifierVersion, f.class, f.reason); err != nil {
				return failure("storage_error")
			}
		}
	}
	for id, tags := range d.taint {
		for tag := range tags {
			if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO record_observed_taint VALUES(?,?,?)", s.opts.PinnedGenesisID, id, tag); err != nil {
				return failure("storage_error")
			}
		}
	}
	for w := range d.taintWitnesses {
		if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO record_taint_evidence VALUES(?,?,?,?,?,?,?)", s.opts.PinnedGenesisID, w.id, w.tag, w.kind, w.evidence, w.source, w.boundary); err != nil {
			return failure("storage_error")
		}
	}
	return nil
}
func freshFields(d *databaseState, id string) []projectionField {
	var out []projectionField
	for _, f := range d.fields[id] {
		if f.class == disclosuretext.NoDetectedMarker && f.projection != "" {
			out = append(out, f)
		}
	}
	return out
}
func freshText(d *databaseState, id string) string {
	var v []string
	for _, f := range freshFields(d, id) {
		v = append(v, f.projection)
	}
	return strings.Join(v, "\n")
}

func projectionFieldKey(event, revision, family string, ordinal int, version, class, reason string) string {
	return strings.Join([]string{event, revision, family, strconv.Itoa(ordinal), version, class, reason}, "/")
}
