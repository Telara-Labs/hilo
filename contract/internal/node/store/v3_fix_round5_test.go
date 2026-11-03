package store

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
)

func round5Execute(t *testing.T, k *kernelWorld, op, tool string, args any) CommittedReplyHandle {
	t.Helper()
	r, err := k.e.Execute(context.Background(), k.h, k.sc, CallIdentity{SuppliedOpID: k.issued(op)}, commandFor(t, tool, args), ByteBudget{MaxBytes: 2048})
	if err != nil {
		t.Fatal(op, err)
	}
	return r
}
func round5Safe(t *testing.T, k *kernelWorld, r CommittedReplyHandle, shape string) {
	t.Helper()
	re := regexp.MustCompile(shape)
	rows, err := k.s.conn.QueryContext(context.Background(), "SELECT b.text,v.shown_units FROM render_body b JOIN render_attempt a ON a.id=b.attempt JOIN render_visible_counts v ON v.attempt=a.id WHERE a.credential=? AND a.op=?", r.credential, r.op)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var text string
		var units int
		if err := rows.Scan(&text, &units); err != nil {
			t.Fatal(err)
		}
		// Count accepted source fields. A replay can safely retain a goal fragment
		// when current framing hides the match; suppressed goals contribute no unit.
		expected := 2
		if strings.Contains(text, "Content withheld by current policy.") {
			expected = 1
		}
		if re.MatchString(text) || !strings.Contains(text, "safecontrol") || units != expected {
			t.Fatal("unsafe persisted fitted reply or metadata", units, text)
		}
		n++
	}
	err = rows.Err()
	rows.Close()
	if err != nil || n == 0 {
		t.Fatal(n, err)
	}
	text := k.release(r)
	if re.MatchString(text) || !strings.Contains(text, "safecontrol") {
		t.Fatal("unsafe release", text)
	}
	// Every accepted item marker must have its corresponding exposure root.
	var mismatch int
	if err := k.s.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM render_item i JOIN render_attempt a ON a.id=i.attempt WHERE a.credential=? AND a.op=? AND NOT EXISTS(SELECT 1 FROM exposure x WHERE x.root=i.id AND x.attempt=i.attempt)`, r.credential, r.op).Scan(&mismatch); err != nil {
		t.Fatal(err)
	}
	if mismatch != 0 {
		t.Fatal("accepted roots missing exposure", mismatch)
	}
}
func round5Fixture(t *testing.T, k *kernelWorld, shape string) string {
	t.Helper()
	probe := k.taskID(k.execute("probe-create", "local.create_task", map[string]any{"name": "safecontrol", "goal": strings.Repeat("x", 6000)}))
	text := k.release(round5Execute(t, k, "probe-resume", "local.resume_task", map[string]any{"task_id": probe}))
	runs := regexp.MustCompile(`x{20,}`).FindAllString(text, -1)
	if len(runs) != 2 {
		t.Fatal("missing fit calibration", text)
	}
	h, tail := len(runs[0]), len(runs[1])
	goal := strings.Repeat("x", h-5) + "START" + strings.Repeat("z", 4096) + "END" + strings.Repeat("x", tail-3)
	if shape == `tenantsecret\b` {
		goal = strings.Repeat("x", h-len("tenantsecret")) + "tenantsecretTAIL" + strings.Repeat("z", 4096) + strings.Repeat("x", tail)
	}
	if regexp.MustCompile(shape).MatchString(goal) {
		t.Fatal("fixture already forbidden before fitting")
	}
	return goal
}
func TestV3Round5FittedPolicyLifecycle(t *testing.T) {
	for _, shape := range []string{`START(?s:.{0,100})END`, `tenantsecret\b`} {
		t.Run(shape, func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			_, build := tenantFixture(t, k)
			k.append(build(1, &record.PolicyBody{}))
			goal := round5Fixture(t, k, shape)
			task := k.taskID(k.execute("evil-create", "local.create_task", map[string]any{"name": "safecontrol", "goal": goal}))
			args := map[string]any{"task_id": task}
			old := round5Execute(t, k, "old", "local.resume_task", args)
			positive := k.release(old)
			if !regexp.MustCompile(shape).MatchString(positive) {
				t.Fatal("no real Store fitting-only positive control", positive)
			}
			k.append(build(2, &record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "fitted", RE2: shape}}}}))
			// Old handle release re-renders under the replacement current policy.
			text := k.release(old)
			if regexp.MustCompile(shape).MatchString(text) {
				t.Fatal(text)
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
				replay := round5Execute(t, k, "old", "local.resume_task", args)
				round5Safe(t, k, replay, shape)
				fresh := round5Execute(t, k, fmt.Sprint("fresh", i), "local.resume_task", args)
				round5Safe(t, k, fresh, shape)
			}
		})
	}
}

func TestV3Round5FittedPolicyNextPage(t *testing.T) {
	for _, shape := range []string{`START(?s:.{0,100})END`, `tenantsecret\b`} {
		t.Run(shape, func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			_, build := tenantFixture(t, k)
			k.append(build(1, &record.PolicyBody{}))
			task := k.taskID(k.execute("create", "local.create_task", map[string]any{"name": "safecontrol", "goal": "safecontrol"}))
			value := strings.Repeat("START", 160) + strings.Repeat("z", 4096) + strings.Repeat("END", 240)
			if shape == `tenantsecret\b` {
				value = strings.Repeat("tenantsecretTAIL", 120) + strings.Repeat("z", 4096) + strings.Repeat("x", 500)
			}
			if regexp.MustCompile(shape).MatchString(value) {
				t.Fatal("fixture matched before fitting")
			}
			for i := 0; i < 2; i++ {
				k.execute(fmt.Sprint("checkpoint", i), "local.checkpoint_task", map[string]any{"task_id": task, "milestone": value, "next_steps": "needle safecontrol"})
			}
			calls := map[string]string{}
			budgets := map[string]int{}
			page := func(op string, budget int) CommittedReplyHandle {
				t.Helper()
				first, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued(op + "-search")}, commandFor(t, "local.lexical_search", map[string]any{"query": "needle", "resource_types": []string{"checkpoint"}, "limit": 1}), ByteBudget{MaxBytes: budget})
				if err != nil {
					t.Fatal(err)
				}
				k.release(first)
				var cursor string
				if err := k.s.conn.QueryRowContext(ctx, "SELECT cursor FROM outcome_continuation WHERE credential=? AND op=?", first.credential, first.op).Scan(&cursor); err != nil {
					t.Fatal(err)
				}
				second, err := k.e.Next(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued(op + "-next")}, cursor, ByteBudget{MaxBytes: budget})
				if err != nil {
					t.Fatal(err)
				}
				calls[second.op] = op + "-next"
				budgets[second.op] = budget
				return second
			}
			re := regexp.MustCompile(shape)
			var old CommittedReplyHandle
			matched := false
			for delta := 0; delta < 36; delta++ {
				r := page(fmt.Sprint("positive", delta), 2048+delta)
				if re.MatchString(k.release(r)) {
					old = r
					matched = true
					break
				}
			}
			if !matched {
				t.Fatal("no actual next-page fitting-only positive control")
			}
			k.append(build(2, &record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "fitted", RE2: shape}}}}))
			if err := k.s.Reindex(ctx); err != nil {
				t.Fatal(err)
			}
			if text := k.release(old); re.MatchString(text) {
				t.Fatal("old page handle leaked", text)
			}
			// Find the boundary under current count/selection framing. Budgets remain
			// near 2048; all attempts are real Execute/Next calls and must remain safe.
			suppressed := false
			var accepted CommittedReplyHandle
			for delta := 0; delta < 36; delta++ {
				r := page(fmt.Sprint("current", delta), 2048+delta)
				text := k.release(r)
				if re.MatchString(text) {
					t.Fatal("new next-page leaked", text)
				}
				if strings.Contains(text, "Content withheld by current policy.") {
					accepted = r
					suppressed = true
					break
				}
			}
			if !suppressed {
				t.Fatal("next-page never exercised final suppression")
			}
			// Exactly one checkpoint sibling survives, rather than the withheld milestone.
			round5Safe(t, k, accepted, shape)
			var cursor string
			if err := k.s.conn.QueryRowContext(ctx, "SELECT id FROM query_cursor WHERE consumed_by=?", accepted.op).Scan(&cursor); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if i == 1 {
					reopenDisclosureKernel(t, k)
				}
				replay, err := k.e.Next(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued(calls[accepted.op])}, cursor, ByteBudget{MaxBytes: budgets[accepted.op]})
				if err != nil {
					t.Fatal("stored next-page replay", err)
				}
				round5Safe(t, k, replay, shape)
			}
		})
	}
}

func TestV3Round5UnattributableFinalMatchRollsBack(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	_, build := tenantFixture(t, k)
	k.append(build(1, &record.PolicyBody{Redaction: record.PolicyRedact{Shapes: []record.Shape{{Name: "frame", RE2: "Evidence only"}}}}))
	var before int
	if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM operation").Scan(&before); err != nil {
		t.Fatal(err)
	}
	r, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued("refused")}, commandFor(t, "local.create_task", map[string]any{"goal": "safecontrol"}), ByteBudget{MaxBytes: 2048})
	if Code(err) != "assembled_policy_unavailable" || r.op != "" {
		t.Fatal("unattributable reply did not refuse", r, err)
	}
	var after, rendered, exposed int
	if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM operation").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM render_body").Scan(&rendered); err != nil {
		t.Fatal(err)
	}
	if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM exposure").Scan(&exposed); err != nil {
		t.Fatal(err)
	}
	if after != before || rendered != 0 || exposed != 0 {
		t.Fatal("refusal retained partial operation/text/exposure", before, after, rendered, exposed)
	}
}
