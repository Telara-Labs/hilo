package store

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

func round4Policy(three bool) *record.PolicyBody {
	shape := `tenantsecret(?s:.*)123`
	if three {
		shape = `tenantsecret(?s:.*)parttwo(?s:.*)123`
	}
	return &record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "assembled", RE2: shape}}}}
}

func round4Safe(t *testing.T, text string) {
	t.Helper()
	for _, s := range []string{"tenantsecret", "parttwo", "１２３", "| 123"} {
		if strings.Contains(text, s) {
			t.Fatal("assembled source released", text)
		}
	}
	if !strings.Contains(text, "safecontrol") {
		t.Fatal("safe sibling missing", text)
	}
}

func round4StoredSafe(t *testing.T, k *kernelWorld, r CommittedReplyHandle) {
	t.Helper()
	rows, err := k.s.conn.QueryContext(context.Background(), "SELECT b.text FROM render_body b JOIN render_attempt a ON a.id=b.attempt WHERE a.credential=? AND a.op=?", r.credential, r.op)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			t.Fatal(err)
		}
		round4Safe(t, text)
		n++
	}
	if err := rows.Err(); err != nil || n == 0 {
		t.Fatal("missing persisted render", n, err)
	}
}

func TestV3Round4CompleteTaskBriefLifecycle(t *testing.T) {
	for _, three := range []bool{false, true} {
		for _, replacement := range []bool{false, true} {
			t.Run(fmt.Sprintf("three=%v/replacement=%v", three, replacement), func(t *testing.T) {
				k := newKernel(t)
				ctx := context.Background()
				_, build := tenantFixture(t, k)
				policy := round4Policy(three)
				if replacement {
					policy = &record.PolicyBody{}
				}
				k.append(build(1, policy))
				goal := "safecontrol"
				if three {
					goal = "tenantsecret"
				}
				r := k.execute("create", "local.create_task", map[string]any{"name": "safecontrol", "goal": goal})
				task := k.taskID(r)
				first := "tenantsecret"
				if three {
					first = "parttwo"
				}
				k.execute("first", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": first})
				k.execute("second", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "１２３", "next_steps": "safecontrol"})
				args := map[string]any{"task_id": task}
				reply := k.execute("resume", "local.resume_task", args)
				if replacement {
					positive := k.release(reply)
					if !regexp.MustCompile(round4Policy(three).Redaction.Shapes[0].RE2).MatchString(positive) {
						t.Fatal("no complete-reply positive control", positive)
					}
					k.append(build(2, round4Policy(three)))
				}
				// Release-time revalidation and Execute replay both use the current gate.
				round4Safe(t, k.release(reply))
				for i := 0; i < 3; i++ {
					if i == 1 {
						if err := k.s.Reindex(ctx); err != nil {
							t.Fatal(err)
						}
					}
					if i == 2 {
						reopenDisclosureKernel(t, k)
					}
					replay := k.execute("resume", "local.resume_task", args)
					round4StoredSafe(t, k, replay) // before Release, not only transport output
					round4Safe(t, k.release(replay))
					fresh := k.execute(fmt.Sprintf("fresh-%d", i), "local.resume_task", args)
					round4StoredSafe(t, k, fresh)
					round4Safe(t, k.release(fresh))
				}
			})
		}
	}
}

func TestV3Round4CompleteTaskListAndSearchPage(t *testing.T) {
	for _, surface := range []string{"task-list", "search-page"} {
		t.Run(surface, func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			_, build := tenantFixture(t, k)
			k.append(build(1, &record.PolicyBody{}))
			var tool string
			var args map[string]any
			if surface == "task-list" {
				// List releases newest task first.
				k.execute("tail", "local.create_task", map[string]any{"name": "safecontrol", "goal": "１２３"})
				k.execute("head", "local.create_task", map[string]any{"name": "safecontrol", "goal": "tenantsecret"})
				tool = "local.list_tasks"
				args = map[string]any{"mode": "summary", "limit": 10}
			} else {
				task := k.taskID(k.execute("create", "local.create_task", map[string]any{"name": "safecontrol", "goal": "safecontrol"}))
				k.execute("head", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "needle tenantsecret", "next_steps": "safecontrol"})
				k.execute("tail", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "１２３ needle", "next_steps": "safecontrol"})
				tool = "local.lexical_search"
				args = map[string]any{"query": "needle", "limit": 10}
			}
			old := k.execute("page", tool, args)
			positive := k.release(old)
			// Search ordering uses stable record identity. Match either endpoint order.
			p := round4Policy(false)
			if surface == "search-page" {
				p.Redaction.Shapes[0].RE2 = `tenantsecret(?s:.*)123|123(?s:.*)tenantsecret`
			}
			if !regexp.MustCompile(p.Redaction.Shapes[0].RE2).MatchString(positive) {
				t.Fatal("no multi-record positive page", positive)
			}
			k.append(build(2, p))
			if surface == "search-page" {
				// Policy replacement deliberately removes old projections. An old
				// search may refuse until rebuild, but must never release old text.
				v, err := k.e.Release(ctx, k.h, old)
				if err == nil {
					round4Safe(t, v.Text())
				} else if Code(err) != "projection_unavailable" {
					t.Fatal(err)
				}
				if err := k.s.Reindex(ctx); err != nil {
					t.Fatal(err)
				}
			}
			round4Safe(t, k.release(old))
			for i := 0; i < 3; i++ {
				if i == 1 {
					if err := k.s.Reindex(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if i == 2 {
					reopenDisclosureKernel(t, k)
				}
				replay := k.execute("page", tool, args)
				round4StoredSafe(t, k, replay)
				round4Safe(t, k.release(replay))
				fresh := k.execute(fmt.Sprintf("page-%d", i), tool, args)
				round4StoredSafe(t, k, fresh)
				round4Safe(t, k.release(fresh))
			}
		})
	}
}

func TestV3Round4SafeSiblingProjectionAndShownUnits(t *testing.T) {
	for _, rejoin := range []bool{false, true} {
		t.Run(fmt.Sprintf("removal-rejoin=%v", rejoin), func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			_, build := tenantFixture(t, k)
			policy := round3Policy()
			args := map[string]any{"milestone": "tenant-secret-", "next_steps": "１２３", "task_tree": []map[string]string{{"step": "retainthissafecontrol", "status": "done"}}}
			if rejoin {
				policy = &record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "first", RE2: "x\\ny"}, {Name: "second", RE2: "a\\nz"}}}}
				args = map[string]any{"milestone": "a", "next_steps": "x", "task_tree": []map[string]string{{"step": "y", "status": "done"}, {"step": "z", "status": "done"}, {"step": "retainthissafecontrol", "status": "done"}}}
			}
			k.append(build(1, policy))
			task := k.taskID(k.execute("create", "local.create_task", map[string]any{"name": "safecontrol", "goal": "safecontrol"}))
			args["task_id"] = task
			r := k.execute("checkpoint", "local.checkpoint_task", args)
			var id string
			if err := k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=? AND role='mutation'", r.op).Scan(&id); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ {
				if i == 1 {
					if err := k.s.Reindex(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if i == 2 {
					reopenDisclosureKernel(t, k)
				}
				var passage string
				if err := k.s.conn.QueryRowContext(ctx, "SELECT text FROM passage WHERE id=?", id).Scan(&passage); err != nil || passage != "retainthissafecontrol" {
					t.Fatal("safe sibling projection", passage, err)
				}
				lookup := k.execute(fmt.Sprintf("lookup-%d", i), "local.lookup_record", map[string]any{"record_id": id, "include_content": true})
				text := k.release(lookup)
				round3ReplySafe(t, text)
				if !strings.Contains(text, "retainthissafecontrol") {
					t.Fatal("safe sibling not released", text)
				}
				var units int
				if err := k.s.conn.QueryRowContext(ctx, "SELECT v.shown_units FROM render_visible_counts v JOIN render_attempt a ON a.id=v.attempt WHERE a.credential=? AND a.op=? ORDER BY a.db_generation DESC LIMIT 1", lookup.credential, lookup.op).Scan(&units); err != nil || units != 1 {
					t.Fatal("inaccurate shown units", units, err)
				}
				search := k.execute(fmt.Sprintf("search-%d", i), "local.lexical_search", map[string]any{"query": "retainthissafecontrol"})
				if text := k.release(search); !strings.Contains(text, "retainthissafecontrol") {
					t.Fatal("safe sibling not searchable", text)
				}
			}
		})
	}
}
