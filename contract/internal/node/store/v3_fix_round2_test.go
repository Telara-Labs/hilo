package store

import (
	"context"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/hilo/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/replay"
)

var round2Inputs = map[string]string{
	"recomposition": "tenant-secret-cafe\u200b\u0301", "fullwidth": "tenant-secret-１２３", "ligature": "tenant-secret-oﬃce",
	"zero-width": "tenant-secret-\u200b123", "control": "tenant-\x01secret-123",
	"terminal": "tenant-secret-\x1b[31m123\x1b[0m",
}

func round2Policy() *record.PolicyBody {
	return &record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "secret", RE2: `tenant-secret-(123|office|café)`}}}}
}
func round2SafeReply(t *testing.T, text string) {
	t.Helper()
	for _, secret := range []string{`tenant\u002dsecret\u002d123`, `tenant\u002dsecret\u002doffice`, "tenant-secret-123", "tenant-secret-office", `tenant\u002dsecret\u002dcafé`, "tenant-secret-café"} {
		if strings.Contains(text, secret) {
			t.Fatal("normalized forbidden value released", text)
		}
	}
}
func round2NoIndexMatch(t *testing.T, k *kernelWorld) {
	t.Helper()
	ctx := context.Background()
	var n int
	if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM passage WHERE instr(text,'tenant-secret-123')>0 OR instr(text,'tenant-secret-office')>0 OR instr(text,'tenant-secret-café')>0").Scan(&n); err != nil || n != 0 {
		t.Fatal("forbidden passage", n, err)
	}
	for _, term := range []string{"123", "office", "café"} {
		if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM search WHERE search MATCH ?", lexicalFTSQuery(term)).Scan(&n); err != nil || n != 0 {
			t.Fatal("forbidden FTS match", n, err)
		}
	}
}
func TestV3Round2NormalizedAdmissionAndHiddenNames(t *testing.T) {
	for name, input := range round2Inputs {
		t.Run(name, func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			_, build := tenantFixture(t, k)
			p := build(1, round2Policy())
			k.append(p)
			full := governedFixture(k.world, k.task(8201, input), p.AdvisoryID)
			if _, err := k.s.Append(ctx, full); Code(err) != "policy_violation" {
				t.Fatal("normalized admission allowed", err)
			}
			header := full
			header.BodyJCS = nil
			k.append(header)
			before := k.snapshot().Generation
			if _, err := k.s.Append(ctx, full); Code(err) != "policy_violation" {
				t.Fatal("normalized enrichment allowed", err)
			}
			if snap := k.snapshot(); snap.Generation != before || len(find(snap, full.AdvisoryID).BodyJCS) != 0 {
				t.Fatal("refusal mutated body/generation")
			}
			round2NoIndexMatch(t, k)
		})
	}
	overlay, err := localpolicy.TenantOverlay(round2Policy())
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []any{
		&record.TaskBody{Goal: "safe", Anchors: &record.Anchors{Refs: []string{"tenant-secret-１２３"}}},
		&record.ChunkBody{Events: []record.Event{{Meta: map[string]string{"pass\u200bword": "innocent-looking"}}}},
		&record.ChunkBody{Events: []record.Event{{Call: &record.ToolCall{RawArgs: map[string]bool{"tenant-secret-oﬃce": true}}}}},
		&record.TaskBody{Goal: strings.Repeat("x", disclosuretext.MaxViewValue+1)},
	} {
		if bodyPolicyAllowed(body, overlay) {
			t.Fatal("normalized hidden field or unsupported bound allowed")
		}
	}
}
func TestV3Round2MutationLookupSearchReplay(t *testing.T) {
	for name, input := range round2Inputs {
		t.Run(name, func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			_, build := tenantFixture(t, k)
			k.append(build(1, round2Policy()))
			created := k.execute("round2-create", "local.create_task", map[string]any{"goal": "roundtwoprobe " + input, "file_paths": []string{input}})
			task := k.taskID(created)
			round2SafeReply(t, k.release(created))
			checkpointArgs := map[string]any{"task_id": task, "milestone": "roundtwoprobe " + input, "next_steps": input, "task_tree": []map[string]string{{"step": input, "status": "done"}}}
			cp := k.execute("round2-checkpoint", "local.checkpoint_task", checkpointArgs)
			var id string
			if err := k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=? AND role='mutation'", cp.op).Scan(&id); err != nil {
				t.Fatal(err)
			}
			for _, r := range []CommittedReplyHandle{cp,
				k.execute("round2-pause", "local.pause_task", map[string]any{"task_id": task, "resume_context": input, "progress_notes": input, "handoff_hint": input, "token_estimate": 1}),
				k.execute("round2-complete", "local.complete_task", map[string]any{"task_id": task, "final_summary": input, "changes_made": []string{input}, "token_estimate": 1}),
			} {
				text := k.release(r)
				round2SafeReply(t, text)
				if !strings.Contains(text, "REDACTED") {
					t.Fatal("sanitized mutation missing", text)
				}
			}
			lookup := k.execute("round2-lookup", "local.lookup_record", map[string]any{"record_id": id, "include_content": true})
			search := k.execute("round2-search", "local.lexical_search", map[string]any{"query": "roundtwoprobe", "resource_types": []string{"checkpoint"}})
			for _, r := range []CommittedReplyHandle{lookup, search, k.execute("round2-checkpoint", "local.checkpoint_task", checkpointArgs), created, cp} {
				text := k.release(r)
				round2SafeReply(t, text)
				if !strings.Contains(text, "REDACTED") {
					t.Fatal("sanitized lookup/search/replay missing", text)
				}
			}
			round2NoIndexMatch(t, k)
		})
	}
}
func TestV3Round2PolicyChangeSuppressesExistingProjections(t *testing.T) {
	for name, input := range round2Inputs {
		t.Run(name, func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			_, build := tenantFixture(t, k)
			k.append(build(1, &record.PolicyBody{}))
			created := k.execute("old-create", "local.create_task", map[string]any{"goal": "safe root"})
			task := k.taskID(created)
			// Build the unaffected control before exposing any forbidden content.
			safe := k.execute("safe-checkpoint", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "safeotherprobe"})
			k.release(safe)
			args := map[string]any{"task_id": task, "milestone": "roundtwoprobe " + input}
			cp := k.execute("old-checkpoint", "local.checkpoint_task", args)
			var id string
			if err := k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=? AND role='mutation'", cp.op).Scan(&id); err != nil {
				t.Fatal(err)
			}
			original := k.release(cp)
			if !strings.Contains(original, "roundtwoprobe") {
				t.Fatal("missing permissive control")
			}
			search := k.execute("old-search", "local.lexical_search", map[string]any{"query": "roundtwoprobe", "resource_types": []string{"checkpoint"}})
			if text := k.release(search); !strings.Contains(text, "roundtwoprobe") {
				t.Fatal("no positive old FTS control", text)
			}
			lookup := k.execute("old-lookup", "local.lookup_record", map[string]any{"record_id": id, "include_content": true})
			k.release(lookup)
			k.append(build(2, round2Policy()))
			round2NoIndexMatch(t, k) // Assert atomic suppression BEFORE any ordinary operation.
			for _, table := range []string{"vector", "projection_job", "record_field_projection", "render_body"} {
				var n int
				if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 0 {
					t.Fatal("stale policy projection", table, n, err)
				}
			}
			for _, r := range []CommittedReplyHandle{cp, lookup, search} {
				if text := k.release(r); text != replay.Unavailable {
					t.Fatal("old governed result remained available", text)
				}
			}
			retry := k.execute("old-checkpoint", "local.checkpoint_task", args)
			if text := k.release(retry); text != replay.Unavailable {
				t.Fatal("replay remutated old body", text)
			}
			fresh := k.execute("new-search", "local.lexical_search", map[string]any{"query": "roundtwoprobe", "resource_types": []string{"checkpoint"}})
			text := k.release(fresh)
			round2SafeReply(t, text)
			if strings.Contains(text, "roundtwoprobe") {
				t.Fatal("post-policy search returned forbidden body", text)
			}
			safeSearch := k.execute("safe-search", "local.lexical_search", map[string]any{"query": "safeotherprobe", "resource_types": []string{"checkpoint"}})
			if text := k.release(safeSearch); !strings.Contains(text, "safeotherprobe") {
				t.Fatal("safe projection did not rebuild", text)
			}
			snap, err := k.s.Snapshot(ctx, ReadRequest{IDs: []string{id}})
			if err != nil || len(snap.Entries) != 1 || len(snap.Entries[0].BodyJCS) != 0 {
				t.Fatal("inspection bypass", err)
			}
			round2NoIndexMatch(t, k)
			reopenDisclosureKernel(t, k)
			after := k.execute("reopened-search", "local.lexical_search", map[string]any{"query": "roundtwoprobe", "resource_types": []string{"checkpoint"}})
			if text := k.release(after); strings.Contains(text, "roundtwoprobe") {
				t.Fatal("reopen resurrected forbidden projection", text)
			}
			round2NoIndexMatch(t, k)
		})
	}
}

func TestV3Round2PolicyProjectionFailureRollsBackAuthority(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	_, build := tenantFixture(t, k)
	first := build(1, &record.PolicyBody{})
	k.append(first)
	r := k.execute("atomic-create", "local.create_task", map[string]any{"goal": "tenant-secret-１２３"})
	k.release(r)
	var before int
	if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM passage").Scan(&before); err != nil || before == 0 {
		t.Fatal("missing positive projection control", err)
	}
	if _, err := k.s.conn.ExecContext(ctx, `CREATE TRIGGER fail_policy_projection BEFORE DELETE ON passage BEGIN SELECT RAISE(ABORT,'injected projection deletion failure'); END`); err != nil {
		t.Fatal(err)
	}
	next := build(2, round2Policy())
	if _, err := k.s.Append(ctx, next); Code(err) != "storage_error" {
		t.Fatal("policy acknowledged with stale projection", err)
	}
	var seq int64
	var id string
	var after int
	if err := k.s.conn.QueryRowContext(ctx, "SELECT highest_seq,highest_id FROM tenant_context WHERE active=1").Scan(&seq, &id); err != nil || seq != 1 || id != first.AdvisoryID {
		t.Fatal("authority partially committed", seq, id, err)
	}
	if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM passage").Scan(&after); err != nil || after != before {
		t.Fatal("projection partially committed", after, err)
	}
	if _, err := k.s.conn.ExecContext(ctx, "DROP TRIGGER fail_policy_projection"); err != nil {
		t.Fatal(err)
	}
	k.append(next)
	round2NoIndexMatch(t, k)
	if text := k.release(r); text != replay.Unavailable {
		t.Fatal("retry did not enforce restrictive policy", text)
	}
}
