package store

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
)

func round3Policy() *record.PolicyBody {
	return &record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "split", RE2: `tenant-\s*secret-\s*123`}}}}
}
func round3ReplySafe(t *testing.T, text string) {
	t.Helper()
	for _, s := range []string{"tenant", "secret", "１２３", "\n    | 123\n"} {
		if strings.Contains(text, s) {
			t.Fatal("split policy fragment released", text)
		}
	}
}
func round3NoProjection(t *testing.T, k *kernelWorld, id string) {
	t.Helper()
	ctx := context.Background()
	for _, table := range []string{"passage", "projection_job", "vector"} {
		var n int
		if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE id=?", id).Scan(&n); err != nil || n != 0 {
			t.Fatal("restricted projection persisted", table, n, err)
		}
	}
	var n int
	if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM search WHERE search MATCH ?", lexicalFTSQuery("tenant secret 123")).Scan(&n); err != nil || n != 0 {
		t.Fatal("split secret indexed", n, err)
	}
}
func TestV3Round3AssembledPolicyProjection(t *testing.T) {
	for _, kind := range []string{"checkpoint", "title-goal", "three-way"} {
		for _, replacement := range []bool{false, true} {
			name := kind + "/active"
			if replacement {
				name = kind + "/replacement"
			}
			t.Run(name, func(t *testing.T) {
				k := newKernel(t)
				ctx := context.Background()
				_, build := tenantFixture(t, k)
				policy := round3Policy()
				if replacement {
					policy = &record.PolicyBody{}
				}
				k.append(build(1, policy))
				safe := k.execute("safe-create", "local.create_task", map[string]any{"name": "safecontrol", "goal": "safecontrol"})
				task := k.taskID(safe)
				controlReply := k.execute("safe-checkpoint", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "safecontrol"})
				k.release(controlReply)
				var r CommittedReplyHandle
				switch kind {
				case "checkpoint":
					r = k.execute("split-write", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "tenant-secret-", "next_steps": "１２３"})
				case "title-goal":
					r = k.execute("split-write", "local.create_task", map[string]any{"name": "tenant-secret-", "goal": "１２３"})
				case "three-way":
					r = k.execute("split-write", "local.pause_task", map[string]any{"task_id": task, "resume_context": "tenant-", "progress_notes": "secret-", "handoff_hint": "１２３", "token_estimate": 1})
				}
				var id string
				if err := k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=? AND role='mutation'", r.op).Scan(&id); err != nil {
					t.Fatal(err)
				}
				before := find(k.snapshot(), id)
				if replacement {
					var n int
					if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM passage WHERE id=?", id).Scan(&n); err != nil || n != 1 {
						t.Fatal("no permissive positive control", n, err)
					}
					// Keep a previously selected search and lookup to exercise release-time revalidation.
					oldSearch := k.execute("old-search", "local.lexical_search", map[string]any{"query": "tenant secret 123"})
					if text := k.release(oldSearch); kind == "checkpoint" && !strings.Contains(text, "tenant") {
						t.Fatal("no positive public search", text)
					}
					oldLookup := k.execute("old-lookup", "local.lookup_record", map[string]any{"record_id": id, "include_content": true})
					if text := k.release(oldLookup); !strings.Contains(text, "tenant") {
						t.Fatal("no positive public lookup", text)
					}
					k.append(build(2, round3Policy()))
					round3NoProjection(t, k, id)
					for _, h := range []CommittedReplyHandle{r, oldSearch, oldLookup} {
						round3ReplySafe(t, k.release(h))
					}
				}
				round3NoProjection(t, k, id)
				for i := 0; i < 3; i++ {
					if i == 1 {
						if err := k.s.Reindex(ctx); err != nil {
							t.Fatal(err)
						}
					}
					if i == 2 {
						reopenDisclosureKernel(t, k)
					}
					round3NoProjection(t, k, id)
					search := k.execute("search-"+string(rune('a'+i)), "local.lexical_search", map[string]any{"query": "tenant secret 123"})
					round3ReplySafe(t, k.release(search))
					var selected int
					if err := k.s.conn.QueryRowContext(ctx, "SELECT selected FROM operation WHERE op=?", search.op).Scan(&selected); err != nil || selected != 0 {
						t.Fatal("search returned restricted record", selected, err)
					}
					lookup := k.execute("lookup-"+string(rune('a'+i)), "local.lookup_record", map[string]any{"record_id": id, "include_content": true})
					round3ReplySafe(t, k.release(lookup))
					if i == 0 {
						round3ReplySafe(t, k.release(r))
					}
					control := k.execute("control-"+string(rune('a'+i)), "local.lexical_search", map[string]any{"query": "safecontrol"})
					if text := k.release(control); !strings.Contains(text, "safecontrol") {
						t.Fatal("safe record suppressed", text)
					}
					round3NoProjection(t, k, id)
				}
				after := find(k.snapshot(), id)
				if !bytes.Equal(before.HeaderJCS, after.HeaderJCS) || !bytes.Equal(before.BodyJCS, after.BodyJCS) {
					t.Fatal("policy projection changed signed source")
				}
			})
		}
	}
}
