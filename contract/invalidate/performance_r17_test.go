package invalidate

import (
	"context"
	"fmt"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
)

func amplificationModelR17(t testing.TB, overlap bool) *Model {
	m := NewModel()
	for i := 0; i < 1000; i++ {
		it := Item{ID: fmt.Sprint(i), Kind: record.KindTask, Owner: G, EventMembershipComplete: true}
		if overlap && i > 0 {
			it.Deps = []string{fmt.Sprint(i - 1)}
		}
		m.Admit(it)
	}
	n := 250
	if overlap {
		n = 1000
	}
	for i := 0; i < n; i++ {
		c := Control{ID: fmt.Sprint("c", i), Kind: record.KindErasure, Owner: G, Erasure: &record.ErasureBody{EventCoverage: "complete", Selectors: record.Selectors{IDs: []string{fmt.Sprint(i)}}}}
		if overlap {
			c.Kind = record.KindRetraction
			c.Erasure = nil
			c.Retraction = &record.RetractionBody{IDs: []string{"0"}}
		}
		parityNoError(t, m.Apply(c))
	}
	return m
}
func TestInvalidationAmplificationR17(t *testing.T) {
	for _, overlap := range []bool{false, true} {
		t.Run(fmt.Sprint(overlap), func(t *testing.T) {
			m := amplificationModelR17(t, overlap)
			ctx := &workContextR16{Context: context.Background()}
			for n := 0; n <= 64; n++ {
				ev, err := m.EvaluateContext(ctx)
				parityNoError(t, err)
				if overlap {
					parityLen(t, ev.Tombs, 1000)
					parityLen(t, ev.CausesOf("999"), 1000)
					parityEqual(t, 1000, ev.CauseCount("c999"))
					// One shared set on the single root; no per-descendant cause storage.
					parityEmpty(t, ev.causeRefs)
					parityLen(t, ev.rootSets, 1)
					parityLen(t, ev.rootSets["0"], 1)
				} else {
					parityLen(t, ev.Tombs, 250)
					parityLen(t, ev.CausesOf("249"), 1)
					parityEqual(t, 1, ev.CauseCount("c249"))
					parityTrue(t, ev.ControlComplete["c249"])
				}
				m.Admit(Item{ID: fmt.Sprint("unrelated", n), Kind: record.KindTask, Owner: G, EventMembershipComplete: true})
			}
			parityLess(t, ctx.checks, 3_500_000, "work must be graph plus distinct closures, not controls times all descendants")
			// Test allocations of the expanded evaluation rather than copied wire facts.
			allocations := testing.AllocsPerRun(1, func() { m.cached = nil; _, err := m.EvaluateContext(context.Background()); parityNoError(t, err) })
			parityLess(t, allocations, 25000.0)
			t.Logf("overlap=%v batch=64 checkpoints=%d eval_allocations=%.0f", overlap, ctx.checks, allocations)
		})
	}
}
func TestEvaluationBudgetsR17(t *testing.T) {
	t.Run("preflight-memory", func(t *testing.T) {
		m := NewModel()
		for n := 0; n < 66000; n++ {
			m.Admit(Item{ID: fmt.Sprint(n), Kind: record.KindTask})
		}
		ev, err := m.EvaluateContext(context.Background())
		parityErrorIs(t, err, ErrEvaluationBudget)
		parityNil(t, ev)
		parityNil(t, m.cached)
	})
	t.Run("runtime-work", func(t *testing.T) {
		b := &evaluationBudget{Context: context.Background(), work: maxEvaluationWork}
		parityErrorIs(t, b.Err(), ErrEvaluationBudget)
	})
	t.Run("before-expansion", func(t *testing.T) {
		b := &evaluationBudget{Context: context.Background(), bytes: maxEvaluationBytes - 64}
		out, err := closureContext(b, map[string][]string{}, []string{"root"})
		parityErrorIs(t, err, ErrEvaluationBudget)
		parityNil(t, out)
	})
}
func BenchmarkInvalidationBatch64R17(b *testing.B) {
	for _, overlap := range []bool{false, true} {
		name := "250DisjointErasures1000Items"
		if overlap {
			name = "1000Retractions1000Chain"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				b.StopTimer()
				m := amplificationModelR17(b, overlap)
				b.StartTimer()
				for i := 0; i <= 64; i++ {
					_, err := m.EvaluateContext(context.Background())
					parityNoError(b, err)
					if i < 64 {
						m.Admit(Item{ID: fmt.Sprint("new", i), Kind: record.KindTask, Owner: G, EventMembershipComplete: true})
					}
				}
			}
		})
	}
}

// Overlapping controls that are NOT byte-identical (distinct extra targets or
// distinct roots on one chain) must share reachability too: tombs cost the graph
// size, not controls times descendants, and no per-descendant cause is stored.
func distinctOverlapModelR17(t testing.TB, distinctRoots bool) *Model {
	m := NewModel()
	for i := 0; i < 1000; i++ {
		it := Item{ID: fmt.Sprint(i), Kind: record.KindTask, Owner: G, EventMembershipComplete: true}
		if i > 0 {
			it.Deps = []string{fmt.Sprint(i - 1)}
		}
		m.Admit(it)
	}
	for i := 0; i < 1000; i++ {
		ids := []string{"0", fmt.Sprint("absent-", i)}
		if distinctRoots {
			ids = []string{fmt.Sprint(i)}
		}
		parityNoError(t, m.Apply(Control{ID: fmt.Sprint("c", i), Kind: record.KindRetraction, Owner: G, Retraction: &record.RetractionBody{IDs: ids}}))
	}
	return m
}
func TestDistinctOverlappingRetractionsR17(t *testing.T) {
	for _, distinctRoots := range []bool{false, true} {
		t.Run(fmt.Sprint("distinct-roots=", distinctRoots), func(t *testing.T) {
			m := distinctOverlapModelR17(t, distinctRoots)
			ctx := &workContextR16{Context: context.Background()}
			for n := 0; n <= 64; n++ {
				ev, err := m.EvaluateContext(ctx)
				parityNoError(t, err)
				parityEmpty(t, ev.causeRefs)
				parityLen(t, ev.CausesOf("999"), 1000)
				parityEqual(t, Tomb{Kind: Retracted, Cause: "c0"}, ev.Tombs["999"])
				if distinctRoots {
					parityLen(t, ev.Tombs, 1000)
					parityLen(t, ev.CausesOf("0"), 1)
					parityEqual(t, 1000, ev.CauseCount("c0"))
					parityEqual(t, 1, ev.CauseCount("c999"))
					parityLen(t, ev.CausesOf("500"), 501)
				} else {
					parityLen(t, ev.Tombs, 2000)
					parityEqual(t, 1001, ev.CauseCount("c999"))
					parityLen(t, ev.CausesOf("absent-7"), 1)
				}
				m.Admit(Item{ID: fmt.Sprint("unrelated", n), Kind: record.KindTask, Owner: G, EventMembershipComplete: true})
			}
			parityLess(t, ctx.checks, 3_500_000, "tombs must be one visit per record, not controls times descendants")
			allocations := testing.AllocsPerRun(1, func() { m.cached = nil; _, err := m.EvaluateContext(context.Background()); parityNoError(t, err) })
			parityLess(t, allocations, 40000.0)
			t.Logf("distinct_roots=%v batch=64 checkpoints=%d eval_allocations=%.0f", distinctRoots, ctx.checks, allocations)
		})
	}
}
func BenchmarkDistinctOverlapBatch64R17(b *testing.B) {
	for _, distinctRoots := range []bool{false, true} {
		name := "1000RetractionsRootPlusDistinctAbsent"
		if distinctRoots {
			name = "1000RetractionsDistinctChainRoots"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				b.StopTimer()
				m := distinctOverlapModelR17(b, distinctRoots)
				b.StartTimer()
				for i := 0; i <= 64; i++ {
					_, err := m.EvaluateContext(context.Background())
					parityNoError(b, err)
					if i < 64 {
						m.Admit(Item{ID: fmt.Sprint("new", i), Kind: record.KindTask, Owner: G, EventMembershipComplete: true})
					}
				}
			}
		})
	}
}
