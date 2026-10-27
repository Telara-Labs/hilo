package invalidate

import (
	"context"
	"fmt"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// Counts the cancellation checkpoints actually traversed, without timing or a
// production test hook. A cache hit must do only its initial context check.
type workContextR16 struct {
	context.Context
	checks, cancelAt int
}

func (c *workContextR16) Err() error {
	c.checks++
	if c.cancelAt > 0 && c.checks >= c.cancelAt {
		return context.Canceled
	}
	return c.Context.Err()
}

func TestEvaluationWorkAndCacheR16(t *testing.T) {
	for _, controls := range []int{0, 25, 250} {
		t.Run(fmt.Sprint(controls), func(t *testing.T) {
			m := NewModel()
			for n := 0; n < 1000; n++ {
				m.Admit(Item{ID: fmt.Sprint(n), Kind: record.KindTask, Owner: G})
			}
			for n := 0; n < controls; n++ {
				parityNoError(t, m.Apply(Control{ID: fmt.Sprint("c", n), Kind: record.KindRetraction, Owner: G, Retraction: &record.RetractionBody{IDs: []string{"0"}}}))
			}
			ctx := &workContextR16{Context: context.Background()}
			ev, err := m.evaluateContext(ctx)
			parityNoError(t, err)
			parityLess(t, ctx.checks, 15000+controls*15, "exact selectors must not rescan all items per control")
			first := ctx.checks
			for n := 0; n < 200; n++ {
				next, err := m.evaluateContext(ctx)
				parityNoError(t, err)
				paritySame(t, ev, next)
			}
			parityEqual(t, first+200, ctx.checks, "dependency lookups reuse the evaluation")
			m.Admit(Item{ID: "999", Kind: record.KindTask, Owner: G}) // no new facts
			paritySame(t, ev, privateEvaluationR16(t, m))
			m.Admit(Item{ID: "late", Kind: record.KindTask, Owner: G, Deps: []string{"0"}})
			next := privateEvaluationR16(t, m)
			parityNotSame(t, ev, next)
			if controls > 0 {
				parityEqual(t, Invalidated, next.StatusOf("late"))
			}
			parityNoError(t, m.Apply(Control{ID: "new-control", Kind: record.KindRetraction, Owner: G, Retraction: &record.RetractionBody{IDs: []string{"999"}}}))
			parityEqual(t, Invalidated, privateEvaluationR16(t, m).StatusOf("999"))
		})
	}
}

func TestEvaluationCancellationDoesNotCachePartialResultR16(t *testing.T) {
	for _, cancelAt := range []int{1, 100, 2000, 5000} {
		m := NewModel()
		for n := 0; n < 1000; n++ {
			m.Admit(Item{ID: fmt.Sprint(n), Kind: record.KindTask, Owner: G})
		}
		ctx := &workContextR16{Context: context.Background(), cancelAt: cancelAt}
		ev, err := m.evaluateContext(ctx)
		parityErrorIs(t, err, context.Canceled)
		parityNil(t, ev)
		parityNil(t, m.cached)
		parityEqual(t, Live, privateEvaluationR16(t, m).StatusOf("999"))
		ctx.cancelAt = ctx.checks + 1
		ev, err = m.evaluateContext(ctx) // cancellation also wins over a cache hit
		parityErrorIs(t, err, context.Canceled)
		parityNil(t, ev)
	}
}

func TestClosureCancellationR16(t *testing.T) {
	deps := map[string][]string{}
	for n := 1; n < 1000; n++ {
		deps[fmt.Sprint(n)] = []string{fmt.Sprint(n - 1)}
	}
	ctx := &workContextR16{Context: context.Background(), cancelAt: 2100}
	out, err := ClosureContext(ctx, deps, []string{"0"})
	parityErrorIs(t, err, context.Canceled)
	parityNil(t, out)
	out, err = ClosureContext(context.Background(), deps, []string{"0"})
	parityNoError(t, err)
	parityLen(t, out, 1000)
}

func TestEvaluationCacheTracksSupplementalFactsAndExposureR16(t *testing.T) {
	m := NewModel()
	m.Admit(Item{ID: "call", Kind: record.KindCall, Owner: G})
	before := privateEvaluationR16(t, m)
	parityEqual(t, AncestryPending, before.StatusOf("call"))
	m.Admit(Item{ID: "call", BodyAvailable: true})
	parityNotSame(t, before, privateEvaluationR16(t, m))
	parityEqual(t, Live, privateEvaluationR16(t, m).StatusOf("call"))
	m.Admit(Item{ID: "session", Kind: record.KindSession, Owner: G})
	parityNoError(t, m.Apply(Control{ID: "erase", Kind: record.KindErasure, Owner: G, Erasure: &record.ErasureBody{EventCoverage: "complete", Selectors: record.Selectors{IDs: []string{"session"}}}}))
	parityTrue(t, privateEvaluationR16(t, m).OwnerPending[G])
	m.Admit(Item{ID: "session", EventMembershipComplete: true})
	parityFalse(t, privateEvaluationR16(t, m).OwnerPending[G])
	m.Admit(Item{ID: "source", Kind: record.KindTask, Owner: "other"})
	m.Admit(Item{ID: "recaller", Kind: record.KindTask, Owner: "other"})
	before = privateEvaluationR16(t, m)
	m.Expose(Exposure{ID: "source", AffectsIDs: []string{"recaller"}})
	parityNotSame(t, before, privateEvaluationR16(t, m))
	parityNoError(t, m.Apply(Control{ID: "retract", Kind: record.KindRetraction, Owner: "other", Retraction: &record.RetractionBody{IDs: []string{"source"}}}))
	parityEqual(t, LineageHold, privateEvaluationR16(t, m).StatusOf("recaller"))
	m.Release("recaller")
	parityEqual(t, Live, privateEvaluationR16(t, m).StatusOf("recaller"))
	before = privateEvaluationR16(t, m)
	m.Admit(Item{ID: "recaller", Route: record.RouteHostedPull, RouteTenant: "tenant", GrantGeneration: 1})
	parityNotSame(t, before, privateEvaluationR16(t, m))
	parityLen(t, m.Grants("recaller"), 1)
	before = privateEvaluationR16(t, m)
	m.Admit(Item{ID: "recaller", Route: record.RouteHostedPull, RouteTenant: "tenant", GrantGeneration: 1})
	paritySame(t, before, privateEvaluationR16(t, m), "an unchanged grant does not invalidate the cache")
}

// Cache identity/checkpoint assertions belong to the private engine. Public
// results are deliberately detached and tested by the snapshot regressions.
func privateEvaluationR16(t *testing.T, m *Model) *Eval {
	t.Helper()
	ev, err := m.evaluateContext(context.Background())
	parityNoError(t, err)
	return ev
}
