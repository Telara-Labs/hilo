package store

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/replay"
)

func (e *DisclosureEngine) Execute(ctx context.Context, h ClientHandle, sh ScopeHandle, call CallIdentity, command TypedCommand, budget ByteBudget) (out CommittedReplyHandle, retErr error) {
	if e == nil || e.store == nil {
		return out, failure("unauthorized")
	}
	// Validation and entropy failures precede the writer too. An unidentified
	// invocation must retire its scope on every refusal, not only SQL failures.
	defer func() {
		if retErr != nil {
			e.retireEphemeral(h)
		}
	}()
	if call.SuppliedOpID != "" && disclosuretext.ValidateIdentity(disclosuretext.ExternalOpID, call.SuppliedOpID) != nil {
		return out, failure("unsafe_identity")
	}
	var rpc []byte
	var err error
	if len(call.JSONRPCID) > 0 {
		rpc, err = disclosuretext.CanonicalRPCID(call.JSONRPCID)
		if err != nil {
			return out, failure("unsafe_identity")
		}
	} else if call.SuppliedOpID == "" {
		return out, failure("unsafe_identity")
	}
	if budget.MaxBytes == 0 {
		budget.MaxBytes = e.config.MaxReplyBytes
	}
	if budget.MaxBytes < 2048 || budget.MaxBytes > e.config.MaxReplyBytes {
		return out, failure("invalid_budget")
	}
	pool, err := newDisclosureEntropy()
	if err != nil {
		return out, err
	}
	defer pool.clear()
	now := time.Now()
	var deadlineSelection string
	var deadline time.Time
	err = e.store.writeMode(ctx, true, func() error {
		c, err := e.client(ctx, h)
		if err != nil {
			return err
		}
		if !c.channels[S] || c.readKind == "deny" {
			return failure("read_not_permitted")
		}
		sc, err := e.scope(ctx, h, sh)
		if err != nil {
			return err
		}
		op := ""
		if call.SuppliedOpID != "" {
			op, err = e.suppliedOperation(ctx, h, call.SuppliedOpID)
		} else {
			op, err = e.fallbackOperation(h, sc, rpc, command.Tool())
		}
		if err != nil {
			return err
		}
		prior, err := e.store.loadOutcome(ctx, h.credential, op)
		if err != nil {
			return err
		}
		if prior == nil && call.SuppliedOpID != "" {
			var consumed bool
			if e.store.conn.QueryRowContext(ctx, "SELECT consumed FROM operation_token WHERE token=? AND credential=?", call.SuppliedOpID, h.credential).Scan(&consumed) != nil {
				return failure("storage_error")
			}
			if consumed {
				return failure("unavailable")
			}
		}
		d, err := e.store.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked {
			return failure("owner_blocked")
		}
		// Missing or ineligible original keys return one uniform result before
		// normalizing, hashing or comparing matching/different retry arguments.
		if prior != nil && !e.comparatorPermitted(d, c, sc, prior) {
			out = CommittedReplyHandle{e, h.credential, op, sc.id}
			return nil
		}
		schema := disclosuretext.CurrentSchema(command.Tool())
		fingerprint := e.ruleset.Fingerprint()
		if prior != nil {
			if prior.tool != command.Tool() {
				return failure("op_conflict")
			}
			schema, fingerprint = prior.schema, prior.ruleset
		}
		n, err := disclosuretext.NormalizeTenantCommand(command, budget, schema, fingerprint, d.tenant.body())
		if err != nil {
			return failure(disclosuretext.Code(err))
		}
		defer clear(n.Canonical)
		if prior != nil {
			body := d.byID[prior.callID].rec.Body.(*record.CallBody)
			hash, err := record.CallCommitment(body.Salt, "args", body.Tool, n.Canonical)
			if err != nil {
				return failure("unavailable")
			}
			if hash != body.ArgsHash {
				return failure("op_conflict")
			}
		}
		before := d.generation
		if before == math.MaxInt64 {
			return failure("ordinal_limit")
		}
		var o *operationOutcome
		var added []*stored
		var selection *selectionPlan
		if prior != nil {
			o = prior
		} else {
			if sh.generation != sc.generation || sh.evidence != sc.evidence {
				return failure("stale_scope")
			}
			o = &operationOutcome{budget: budget.MaxBytes, owner: e.config.OwnerGenesis, credential: h.credential, op: op, tool: n.Tool, schema: n.SchemaID, ruleset: n.RulesetFingerprint, builder: disclosureBuilderVersion, scope: sc.id, grantEpoch: c.epoch, scopeGeneration: sc.generation, evidence: sc.evidence, dbGeneration: before + 1}
			o.callRef, err = e.uniqueCallRef(ctx, pool)
			if err != nil {
				return err
			}
			switch n.Tool {
			case "local.create_task", "local.checkpoint_task", "local.pause_task", "local.complete_task":
				added, err = e.prepareMutation(ctx, d, c, sc, n, o, pool, now.UnixMilli())
			case "local.lexical_search", "local.next_page":
				selection, err = e.prepareSearch(ctx, d, c, sc, n, o, pool, now)
			default:
				err = e.selectRead(ctx, d, c, sc, n, o)
			}
			if err != nil {
				return e.refuseTrusted(ctx, d, err)
			}
			ids := make([]string, 0, len(o.members))
			for _, m := range o.members {
				ids = append(ids, m.id)
			}
			if err = d.computeTrust(ids); err != nil {
				return e.refuseTrusted(ctx, d, err)
			}
			for i := range o.members {
				deps, err := dependencyClosure(d, o.members[i].id)
				if err != nil {
					return e.refuseTrusted(ctx, d, err)
				}
				o.members[i].deps = deps
			}
			result, err := logicalOutcomeBytes(o)
			if err != nil {
				return err
			}
			defer clear(result)
			outcome, errorCode := "ok", ""
			if o.isError {
				outcome = "error"
				errorCode = o.result
			}
			deps := map[string]bool{}
			for _, m := range o.members {
				deps[m.id] = true
				for _, id := range m.deps {
					deps[id] = true
				}
			}
			roots := make([]string, 0, len(deps))
			for id := range deps {
				roots = append(roots, id)
			}
			sort.Strings(roots)
			body := record.CallBody{CallRef: o.callRef, ScopeID: sc.id, Tool: receiptTool(n.Tool), TaskID: o.task, Outcome: outcome, Err: errorCode, CommitmentDeps: roots}
			x, err := e.buildCall(d, sc, o, body, n.Canonical, result, now.UnixMilli())
			if err != nil {
				return e.refuseTrusted(ctx, d, err)
			}
			o.argsHash = x.rec.Body.(*record.CallBody).ArgsHash
			added = append(added, x)
			o.callID = x.rec.ID
			o.createdSeq = x.seq
		}
		// One disclosure transaction has one generation, independently of its count
		// of signed records. Original per-record ordinals remain unique and checked.
		d.generation = before + 1
		for _, x := range added {
			x.generation = d.generation
		}
		render, err := e.prepareRender(ctx, d, c, sc, o, pool, budget, before, prior == nil)
		if err != nil {
			return e.refuseTrusted(ctx, d, err)
		}
		if err = e.store.persistPrepared(ctx, d, added); err != nil {
			return err
		}
		if prior == nil {
			if call.SuppliedOpID != "" {
				res, err := e.store.conn.ExecContext(ctx, "UPDATE operation_token SET consumed=1 WHERE token=? AND credential=? AND consumed=0", call.SuppliedOpID, h.credential)
				if err != nil {
					return failure("storage_error")
				}
				n, _ := res.RowsAffected()
				if n != 1 {
					return failure("outcome_unknown")
				}
			}
			if err = e.persistBuilderFacts(ctx, d, added, o, sc); err != nil {
				return err
			}
			if err = e.persistOutcomeAndSelection(ctx, d, c, sc, o, selection); err != nil {
				return err
			}
		}
		if err = e.persistRender(ctx, d, c, sc, o, render); err != nil {
			return err
		}
		if err = e.renewContinuation(ctx, c, sc, o, before, d.generation); err != nil {
			return err
		}
		out = CommittedReplyHandle{e, h.credential, op, sc.id}
		if selection != nil && selection.inputCursor == "" {
			deadlineSelection = selection.id
			deadline = selection.deadline
		}
		return nil
	})
	if err != nil {
		return CommittedReplyHandle{}, err
	}
	if deadlineSelection != "" {
		e.store.mu.Lock()
		e.deadlines[deadlineSelection] = deadline
		e.store.mu.Unlock()
	}
	return out, nil
}
func (e *DisclosureEngine) refuseTrusted(ctx context.Context, d *databaseState, err error) error {
	return e.store.refuseVerified(ctx, d, err)
}
func (s *Store) refuseVerified(ctx context.Context, d *databaseState, err error) error {
	// The private Store-only refusal already performed its exact metadata
	// transaction. Its known-commit result must never be settled twice.
	if _, settled := err.(*postCommitRefusal); settled {
		return err
	}
	if _, ok := err.(*projectionLimit); ok {
		for _, f := range d.exposures {
			if f.persisted {
				return s.commitProjectionHold(ctx)
			}
		}
		for _, x := range d.records {
			if x.persisted && (x.rec.Header.Type == record.KindErasure || x.rec.Header.Type == record.KindRetraction) {
				return s.commitProjectionHold(ctx)
			}
		}
		return failure("lineage_evaluation_required")
	}
	if d.eval != nil {
		if cause := lateErasureCause(d); cause != "" {
			return s.commitPrivacyBarrier(ctx, cause, "late_erasure_discovery", "privacy_hold_required")
		}
	}
	return err
}
func (e *DisclosureEngine) uniqueCallRef(ctx context.Context, p *disclosureEntropy) (string, error) {
	for _, ref := range p.calls {
		var n int
		if e.store.conn.QueryRowContext(ctx, "SELECT count(*) FROM record WHERE json_extract(CAST(header AS TEXT),'$.lid')=?", record.CallLID(ref)).Scan(&n) != nil {
			return "", failure("storage_error")
		}
		if n == 0 {
			return ref, nil
		}
	}
	return "", failure("entropy_collision")
}
func (e *DisclosureEngine) persistOutcomeAndSelection(ctx context.Context, d *databaseState, c *credentialState, sc scopeState, o *operationOutcome, p *selectionPlan) error {
	if err := e.persistSelection(ctx, d, c, sc, o, p); err != nil {
		return err
	}
	return e.store.persistOutcome(ctx, o)
}
func (e *DisclosureEngine) Next(ctx context.Context, h ClientHandle, sc ScopeHandle, call CallIdentity, cursor string, budget ByteBudget) (out CommittedReplyHandle, retErr error) {
	defer func() {
		if retErr != nil && e != nil && e.store != nil {
			e.retireEphemeral(h)
		}
	}()
	raw, err := json.Marshal(struct {
		Cursor string `json:"cursor_id"`
	}{cursor})
	if err != nil {
		return CommittedReplyHandle{}, failure("invalid_cursor")
	}
	cmd, err := disclosuretext.DecodeCommand("local.next_page", raw)
	if err != nil {
		return CommittedReplyHandle{}, failure(disclosuretext.Code(err))
	}
	return e.Execute(ctx, h, sc, call, cmd, budget)
}
func (e *DisclosureEngine) Release(ctx context.Context, h ClientHandle, reply CommittedReplyHandle) (ReleasedText, error) {
	if e != nil && e.store != nil {
		defer e.retireEphemeral(h)
	}
	var out ReleasedText
	if e == nil || e.store == nil || reply.engine != e || reply.credential != h.credential {
		return out, failure("unauthorized")
	}
	pool, err := newDisclosureEntropy()
	if err != nil {
		return out, err
	}
	defer pool.clear()
	err = e.store.writeMode(ctx, true, func() error {
		c, err := e.client(ctx, h)
		if err != nil {
			return err
		}
		if !c.channels[S] || c.readKind == "deny" {
			return failure("read_not_permitted")
		}
		var generation, evidence int64
		if e.store.conn.QueryRowContext(ctx, "SELECT generation,evidence FROM local_scope WHERE id=? AND credential=?", reply.scope, h.credential).Scan(&generation, &evidence) != nil {
			return failure("invalid_scope")
		}
		sc, err := e.scope(ctx, h, ScopeHandle{e, h.credential, reply.scope, generation, evidence})
		if err != nil {
			return err
		}
		o, err := e.store.loadOutcome(ctx, h.credential, reply.op)
		if err != nil {
			return err
		}
		if o == nil {
			return failure("invalid_reply")
		}
		d, err := e.store.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked {
			return failure("owner_blocked")
		}
		if !e.comparatorPermitted(d, c, sc, o) {
			out = ReleasedText{text: replay.Unavailable}
			return nil
		}
		before := d.generation
		if before == math.MaxInt64 {
			return failure("ordinal_limit")
		}
		d.generation++
		render, err := e.prepareRender(ctx, d, c, sc, o, pool, ByteBudget{MaxBytes: min(o.budget, e.config.MaxReplyBytes)}, before, false)
		if err != nil {
			return e.refuseTrusted(ctx, d, err)
		}
		if err = e.store.persistPrepared(ctx, d, nil); err != nil {
			return err
		}
		if err = e.persistRender(ctx, d, c, sc, o, render); err != nil {
			return err
		}
		if err = e.renewContinuation(ctx, c, sc, o, before, d.generation); err != nil {
			return err
		}
		out = ReleasedText{text: render.text, isError: o.isError}
		if render.unavailable {
			out = ReleasedText{text: replay.Unavailable}
		}
		return nil
	})
	if err != nil {
		return ReleasedText{}, err
	}
	return out, nil
}
func (e *DisclosureEngine) renewContinuation(ctx context.Context, c *credentialState, sc scopeState, o *operationOutcome, before, after int64) error {
	if o.cursor == "" {
		return nil
	}
	deadline, ok := e.deadlines[o.selection]
	// A newly inserted continuation has no published monotonic deadline yet;
	// its expected generation already equals this transaction's generation.
	if !ok {
		var generation int64
		if e.store.conn.QueryRowContext(ctx, "SELECT expected_generation FROM query_cursor WHERE id=?", o.cursor).Scan(&generation) == nil && generation == after {
			return nil
		}
	}
	if !ok || !time.Now().Before(deadline) || o.scopeGeneration != sc.generation || o.evidence != sc.evidence {
		if _, err := e.store.conn.ExecContext(ctx, "UPDATE query_cursor SET state='expired' WHERE id=? AND state='ready'", o.cursor); err != nil {
			return failure("storage_error")
		}
		return nil
	}
	result, err := e.store.conn.ExecContext(ctx, "UPDATE query_cursor SET expected_generation=? WHERE id=? AND state='ready' AND expected_generation=? AND selection IN(SELECT id FROM query_selection WHERE credential=? AND scope=? AND generation=? AND grant_epoch=? AND engine=? AND evidence=?)", after, o.cursor, before, c.id, sc.id, sc.generation, c.epoch, e.id, sc.evidence)
	if err != nil {
		return failure("storage_error")
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		if _, err = e.store.conn.ExecContext(ctx, "UPDATE query_cursor SET state='expired' WHERE id=? AND state='ready'", o.cursor); err != nil {
			return failure("storage_error")
		}
	}

	return nil
}
func emptyDisplay(code string) (string, error) {
	switch code {
	case "query_required":
		return "query_required", nil
	case "no_hits", "no_searchable_fresh_hits", "no_hits_projection_counts_unknown", "no_visible_tasks":
		return "recorded_empty_selection", nil
	}
	return "", failure("outcome_render_unavailable")
}
func isMutationTool(tool string) bool {
	return tool == "local.create_task" || tool == "local.checkpoint_task" || tool == "local.pause_task" || tool == "local.complete_task"
}
func fixedToolAction(tool string) TaskMutation {
	return TaskMutation(strings.TrimSuffix(strings.TrimPrefix(tool, "local."), "_task"))
}
