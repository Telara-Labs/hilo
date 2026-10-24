package store

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/heads"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

func (e *DisclosureEngine) buildRecord(d *databaseState, sc scopeState, o *operationOutcome, k record.Kind, lid string, body any, links record.Links, at int64) (*stored, error) {
	h := record.Header{Type: k, LID: lid, At: at, Author: record.Author{MachineID: e.config.MachineID, KeyID: e.authority.keyID}, Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: o.task}, Red: record.Redact{Profile: record.ProfileLocal, Epoch: e.ruleset.Epoch, Fingerprint: e.ruleset.Fingerprint()}, Trust: record.Trust{Coverage: "incomplete", Taint: []string{"taint-unknown"}}, Op: o.op, Links: links}
	if d.tenant != nil {
		if !d.tenant.sealAllowed("", h.Red.Epoch) {
			return nil, failure("policy_violation")
		}
		h.Pol = d.tenant.chain.HighestID
	}
	r, err := record.Build(h, body)
	if err != nil {
		return nil, failure("builder_refused")
	}
	sg, err := sig.SignRecord(e.authority.private[:], r.ID)
	if err != nil {
		return nil, failure("builder_refused")
	}
	r, signatures, err := parse(SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: []record.Signature{sg}, AdvisoryID: r.ID})
	if err != nil {
		return nil, err
	}
	if d.byID[r.ID] != nil {
		return nil, failure("builder_identity_conflict")
	}
	repoState, repo := sc.repoState, sc.repo
	if repoState != "known" {
		repoState = "explicitly_unscoped"
		repo = ""
	}
	d.attrs[r.ID] = attributionFact{owner: e.config.OwnerGenesis, machine: e.config.MachineID, scope: sc.id, kind: "fixed-mcp-builder", repoState: repoState, repo: repo}
	return e.store.prepareNew(d, r, signatures)
}
func (e *DisclosureEngine) prepareMutation(ctx context.Context, d *databaseState, c *credentialState, sc scopeState, n disclosuretext.NormalizedCommand, o *operationOutcome, pool *disclosureEntropy, at int64) ([]*stored, error) {
	var k record.Kind
	var body any
	var lid string
	var links record.Links
	nameKind := ""
	a := n.Args
	action := TaskMutation(strings.TrimSuffix(strings.TrimPrefix(n.Tool, "local."), "_task"))
	if err := e.writeAllowed(ctx, c, sc, action, a.TaskID); err != nil {
		return nil, err
	}
	o.action = string(action)
	o.task = a.TaskID
	if action == Create {
		var err error
		o.task, err = pool.uuid(ctx, e.store, "task", "task_write_scope", "task")
		if err != nil {
			return nil, err
		}
		name := ""
		if a.Name != nil {
			name = *a.Name
		} else {
			runes := []rune(strings.TrimSpace(a.Goal))
			if len(runes) > 100 {
				runes = runes[:100]
			}
			name = string(runes)
			nameKind = "mcp_generated_name_from_goal"
			if name == "" {
				name = "Local task"
				nameKind = "mcp_generated"
			}
		}
		b := &record.TaskBody{Name: name, Goal: a.Goal, Status: "active"}
		if len(a.FilePaths) > 0 {
			b.Anchors = &record.Anchors{Files: append([]string(nil), a.FilePaths...)}
		}
		k = record.KindTask
		body = b
		lid = record.TaskLID(e.config.OwnerGenesis, o.task)
		o.kind = "task_created"
		o.renderer = "task_mutation_v1"
		o.result = "created"
	} else {
		root := taskHeader(d, e.config.OwnerGenesis, o.task)
		if !readPermitted(d, c, sc, root) {
			return nil, failure("not_found")
		}
		if d.taskStatus(e.config.OwnerGenesis, o.task) == "completed" {
			return nil, failure("task_completed")
		}
		switch action {
		case Checkpoint:
			b := &record.CheckpointBody{Milestone: a.Milestone, NextSteps: a.NextSteps, KnowledgeRefs: append([]string(nil), a.KnowledgeRefs...)}
			for _, step := range a.TaskTree {
				b.TaskTree = append(b.TaskTree, record.Step{Title: step.Step, Status: wireStepStatus(step.Status)})
			}
			for _, id := range a.KnowledgeRefs {
				if !readPermitted(d, c, sc, d.byID[id]) {
					return nil, failure("not_found")
				}
			}
			k = record.KindCheckpoint
			body = b
			lid = record.CheckpointLID(e.config.OwnerGenesis, o.task, e.config.MachineID, o.op)
			o.kind = "task_checkpointed"
			o.result = "checkpointed"
		case Pause:
			k = record.KindPause
			body = &record.PauseBody{ResumeContext: a.ResumeContext, ProgressNotes: a.ProgressNotes, HandoffHint: a.HandoffHint, TokenEstimate: a.TokenEstimate}
			lid = record.PauseLID(e.config.OwnerGenesis, o.task, e.config.MachineID, o.op)
			o.kind = "task_paused"
			o.result = "paused"
		case Complete:
			b := &record.ConclusionBody{Source: "explicit", State: "answered", ChangesMade: append([]string(nil), a.ChangesMade...), TokenEstimate: a.TokenEstimate}
			if a.FinalSummary != nil {
				b.Text = *a.FinalSummary
			} else {
				o.warnings = append(o.warnings, "no_summary_supplied")
			}
			k = record.KindConclusion
			body = b
			lid = record.ExplicitConclusionLID(e.config.OwnerGenesis, o.task)
			var vs []heads.Version
			for _, x := range d.records {
				vs = append(vs, heads.FromHeader(x.rec.ID, &x.rec.Header, x.owner, available(x)))
			}
			for _, h := range heads.HeadsForOwner(vs, nil, lid, k, e.config.OwnerGenesis) {
				links.Supersedes = append(links.Supersedes, h.ID)
			}
			if len(links.Supersedes) > 8 {
				return nil, failure("history_limit")
			}
			o.kind = "task_completed"
			o.result = "completed"
		default:
			return nil, failure("unsupported_tool")
		}
		o.renderer = "task_mutation_v1"
	}
	x, err := e.buildRecord(d, sc, o, k, lid, body, links, at)
	if err != nil {
		return nil, err
	}
	for _, f := range enumerateFields(x.rec) {
		fact := completenessFact{owner: x.owner, id: x.rec.ID, family: f.family, ordinal: f.ordinal, instance: e.instance, credential: o.credential, op: o.op, sourceKind: "mcp_argument", sourceSlot: f.family, sourceOrdinal: f.ordinal, builder: disclosureBuilderVersion, schema: n.SchemaID, ruleset: n.RulesetFingerprint, full: int64(len(f.value)), retained: int64(len(f.value)), trusted: true}
		if f.family == "name" && nameKind != "" {
			fact.sourceKind = nameKind
			if nameKind == "mcp_generated_name_from_goal" {
				fact.sourceSlot = "goal"
				fact.full = int64(len(a.Goal))
			} else {
				fact.sourceSlot = "constant_task_name"
			}
		}
		d.completeness[fieldKey{x.rec.ID, "", "", f.family, f.ordinal}] = fact
	}
	if err = d.rebuild(e.store.opts); err != nil {
		return nil, err
	}
	o.members = []outcomeMember{{id: x.rec.ID, owner: x.owner, task: o.task, role: "mutation", mode: "quoted_source", required: true}}
	o.selected = 1
	o.total = ptr64(1)
	return []*stored{x}, nil
}
func (e *DisclosureEngine) persistBuilderFacts(ctx context.Context, d *databaseState, added []*stored, o *operationOutcome, sc scopeState) error {
	for _, x := range added {
		a := d.attrs[x.rec.ID]
		if _, err := e.store.conn.ExecContext(ctx, "INSERT INTO record_attribution VALUES(?,?,?,?,?,?,?)", x.rec.ID, a.owner, a.machine, a.scope, a.kind, a.repoState, a.repo); err != nil {
			return failure("storage_error")
		}
		for key, f := range d.completeness {
			if key.id != x.rec.ID {
				continue
			}
			if _, err := e.store.conn.ExecContext(ctx, "INSERT INTO field_completeness VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", f.owner, f.id, f.event, f.revision, f.family, f.ordinal, f.instance, f.credential, f.op, f.sourceKind, f.sourceSlot, f.sourceOrdinal, f.builder, f.schema, f.ruleset, f.full, f.retained); err != nil {
				return failure("storage_error")
			}
		}
	}
	if o.action == "create" {
		state, repo := sc.repoState, sc.repo
		if state != "known" {
			state = "explicitly_unscoped"
			repo = ""
		}
		if _, err := e.store.conn.ExecContext(ctx, "INSERT INTO task_write_scope VALUES(?,?,?,?,?,?,?)", o.owner, o.task, state, repo, o.credential, o.op, sc.evidence); err != nil {
			return failure("storage_error")
		}
	}
	return nil
}

// This transient logical result is committed only under the original call key.
// Its selected signed roots cover every result field and all comparison copies.
func logicalOutcomeBytes(o *operationOutcome) ([]byte, error) {
	ids := []string{}
	for _, m := range o.members {
		ids = append(ids, m.id)
	}
	b, err := jcs.MarshalRecord(map[string]any{"schema": "outcome/2", "kind": o.kind, "task": o.task, "action": o.action, "result": o.result, "members": ids, "is_error": o.isError})
	if err != nil {
		return nil, failure("outcome_unavailable")
	}
	return b, nil
}
func wireStepStatus(status string) string {
	if status == "done" {
		return "completed"
	}
	return "active"
}
func (e *DisclosureEngine) buildCall(d *databaseState, sc scopeState, o *operationOutcome, body record.CallBody, args, result json.RawMessage, at int64) (*stored, error) {
	if len(body.CommitmentDeps) > 128 {
		return nil, failure("render_limit")
	}
	h := record.Header{Type: record.KindCall, LID: record.CallLID(body.CallRef), At: at, Author: record.Author{MachineID: e.config.MachineID, KeyID: e.authority.keyID}, Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: o.task}, Red: record.Redact{Profile: record.ProfileLocal, Epoch: e.ruleset.Epoch, Fingerprint: e.ruleset.Fingerprint()}, Trust: record.Trust{Coverage: "incomplete", Taint: []string{"taint-unknown"}}, Op: o.op, Links: record.Links{DerivedFrom: body.CommitmentDeps}}
	if d.tenant != nil {
		h.Pol = d.tenant.chain.HighestID
	}
	r, err := record.BuildCall(h, body, args, result)
	if err != nil {
		return nil, failure("builder_refused")
	}
	sg, err := sig.SignRecord(e.authority.private[:], r.ID)
	if err != nil {
		return nil, failure("builder_refused")
	}
	repoState, repo := sc.repoState, sc.repo
	if repoState != "known" {
		repoState = "explicitly_unscoped"
		repo = ""
	}
	d.attrs[r.ID] = attributionFact{owner: e.config.OwnerGenesis, machine: e.config.MachineID, scope: sc.id, kind: "fixed-mcp-builder", repoState: repoState, repo: repo}
	return e.store.prepareNew(d, r, []record.Signature{sg})
}
func (e *DisclosureEngine) comparatorLive(d *databaseState, o *operationOutcome) bool {
	x := d.byID[o.callID]
	if !available(x) {
		return false
	}
	b, ok := x.rec.Body.(*record.CallBody)
	if !ok || b.ArgsHash == "" || b.Salt == "" {
		return false
	}
	if record.ValidateCommitmentDependencies(x.rec, nil) != nil {
		return false
	}
	_, err := dependencyClosure(d, x.rec.ID)
	return err == nil
}

func (e *DisclosureEngine) comparatorPermitted(d *databaseState, c *credentialState, sc scopeState, o *operationOutcome) bool {
	if !e.comparatorLive(d, o) {
		return false
	}
	x := d.byID[o.callID]
	if !d.policyReadAllowed(x) {
		return false
	}
	// Authorization follows the signed commitment inputs. Later conservative
	// exposure fences on the call itself are erasure ancestry (already checked
	// by comparatorLive), not additional values in the committed args/result.
	for _, root := range x.rec.Body.(*record.CallBody).CommitmentDeps {
		deps, err := dependencyClosure(d, root)
		if err != nil {
			return false
		}
		for _, id := range deps {
			if !readPermitted(d, c, sc, d.byID[id]) {
				return false
			}
		}
	}
	return true
}
