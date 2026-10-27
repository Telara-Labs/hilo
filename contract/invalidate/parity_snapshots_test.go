package invalidate

import (
	"context"
	"fmt"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

func snapshotModel(t *testing.T) *Model {
	t.Helper()
	m := NewModel()
	m.Admit(item("root"))
	m.Admit(item("child", "root"))
	m.Admit(item("recaller"))
	m.Expose(Exposure{ID: hx("root"), AffectsIDs: []string{hx("recaller")}})
	parityNoError(t, m.Apply(Control{ID: hx("retract"), Kind: record.KindRetraction, Owner: G, Retraction: &record.RetractionBody{IDs: []string{hx("root")}}}))
	return m
}
func TestPublicEvaluationsDetachMapsSlicesAndCompactMembership(t *testing.T) {
	m := snapshotModel(t)
	for _, legacy := range []bool{false, true} {
		var ev *Eval
		if legacy {
			ev = m.Evaluate()
			parityNoError(t, ev.Err())
		} else {
			var err error
			ev, err = m.EvaluateContext(context.Background())
			parityNoError(t, err)
		}
		causes := ev.CausesOf(hx("child"))
		parityLen(t, causes, 1)
		causes[0].Cause = "forged"
		ev.Status[hx("child")] = Live
		ev.OwnerPending[G] = true
		ev.ControlComplete["forged"] = true
		ev.EventBans["forged"] = true
		ev.Tombs[hx("child")] = Tomb{}
		parityPositive(t, len(ev.HoldCauses[hx("recaller")]))
		ev.HoldCauses[hx("recaller")][0] = "forged"
		if legacy {
			ev.Causes[hx("child")][0].Cause = "forged"
			ev.Causes = map[string][]Tomb{}
		}
		for _, sets := range ev.rootSets {
			for _, set := range sets {
				set.causes[0].Cause = "forged"
				set.seeds[0] = "forged"
			}
		}
		ev.reverse[hx("root")][0] = "forged"
		ev.deps[hx("child")][0] = "forged"
		fresh, err := m.EvaluateContext(context.Background())
		parityNoError(t, err)
		parityEqual(t, Invalidated, fresh.StatusOf(hx("child")))
		parityFalse(t, fresh.OwnerPending[G])
		parityFalse(t, fresh.EventBans["forged"])
		parityFalse(t, fresh.ControlComplete["forged"])
		if fresh.HoldCauses[hx("recaller")][0] == "forged" {
			t.Fatal("nested hold slice aliases model cache")
		}
		parityEqual(t, hx("retract"), fresh.CausesOf(hx("child"))[0].Cause)
		parityEqual(t, 2, fresh.CauseCount(hx("retract")))
	}
}
func TestLegacyCauseMaterializationIsCompleteAndDetached(t *testing.T) {
	m := snapshotModel(t)
	ev, err := m.EvaluateDetachedContext(context.Background())
	parityNoError(t, err)
	parityLen(t, ev.Causes, 2)
	parityLen(t, ev.Causes[hx("root")], 1)
	parityLen(t, ev.Causes[hx("child")], 1)
	ev.Causes[hx("child")][0].Kind = Erased
	ev.Tombs = map[string]Tomb{}
	next, err := m.EvaluateDetachedContext(context.Background())
	parityNoError(t, err)
	parityEqual(t, Retracted, next.Causes[hx("child")][0].Kind)
	parityEqual(t, Invalidated, next.StatusOf(hx("child")))
}
func TestLegacyEvaluationRefusalIsNonNilAndNeverLive(t *testing.T) {
	m := NewModel()
	m.Admit(Item{ID: "oversize", Kind: record.KindTask, Owner: G, Deps: make([]string, maxEvaluationBytes/96+1)})
	ev := m.Evaluate()
	if ev == nil {
		t.Fatal("legacy refusal returned nil")
	}
	parityErrorIs(t, ev.Err(), ErrEvaluationBudget)
	parityEqual(t, LineageHold, ev.StatusOf("oversize"))
	parityFalse(t, m.ExportEligible("oversize"))
	parityEmpty(t, ev.Causes)
	parityNil(t, m.cached)
}
func TestLegacyCauseCopyBudgetDoesNotPublishPartialOrPoisonCache(t *testing.T) {
	m := snapshotModel(t)
	_, err := m.EvaluateContext(context.Background())
	parityNoError(t, err)
	cached := m.cached
	set := &causeSet{causes: make([]Tomb, maxEvaluationBytes/64+1)}
	cached.causeRefs["oversize"] = []*causeSet{set}
	_, err = m.EvaluateDetachedContext(context.Background())
	parityErrorIs(t, err, ErrEvaluationBudget)
	paritySame(t, cached, m.cached)
	delete(cached.causeRefs, "oversize")
	fresh, err := m.EvaluateDetachedContext(context.Background())
	parityNoError(t, err)
	parityLen(t, fresh.Causes[hx("child")], 1)
}

func TestPublicEvaluationCancellationWinsOverCachedSnapshots(t *testing.T) {
	m := snapshotModel(t)
	_, err := m.EvaluateContext(context.Background())
	parityNoError(t, err)
	cached := m.cached
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, get := range []func(context.Context) (*Eval, error){m.EvaluateContext, m.EvaluateDetachedContext} {
		ev, err := get(ctx)
		parityErrorIs(t, err, context.Canceled)
		parityNil(t, ev)
		paritySame(t, cached, m.cached)
	}
}

func TestEventErasedFailsClosedOnEvaluationAndMaterializationRefusal(t *testing.T) {
	for _, refusal := range []string{"evaluation", "legacy-materialization"} {
		t.Run(refusal, func(t *testing.T) {
			m := NewModel()
			session, eventID := "sk1:"+hx("ban-session"), "ev1:"+hx("ban-event")
			parityNoError(t, m.Apply(erase("event-only", record.Selectors{Events: []record.EventSelector{{Owner: G, SessionKey: session, EventID: eventID}}})))
			// No whole-session selector can bypass the evaluation under review.
			parityTrue(t, m.EventErased(G, session, eventID))
			parityFalse(t, m.EventErased(G, session, "ev1:"+hx("other-event")))
			if refusal == "evaluation" {
				m.Admit(Item{ID: "oversize", Kind: record.KindTask, Owner: G, Deps: make([]string, maxEvaluationBytes/96+1)})
				parityErrorIs(t, m.Evaluate().Err(), ErrEvaluationBudget)
				parityNil(t, m.cached)
			} else {
				// Actual retained facts keep the compact fold bounded while a
				// complete legacy Causes map would expand to one million tombs.
				for i := 0; i < 1000; i++ {
					it := Item{ID: fmt.Sprint(i), Kind: record.KindTask, Owner: G, EventMembershipComplete: true}
					if i > 0 {
						it.Deps = []string{fmt.Sprint(i - 1)}
					}
					m.Admit(it)
					parityNoError(t, m.Apply(Control{ID: fmt.Sprint("cause-", i), Kind: record.KindRetraction, Owner: G, Retraction: &record.RetractionBody{IDs: []string{"0"}}}))
				}
				compact, err := m.EvaluateContext(context.Background())
				parityNoError(t, err)
				parityTrue(t, compact.EventBans[eventBanKey(G, session, eventID)])
				parityLen(t, compact.CausesOf("999"), 1000)
				cached := m.cached
				parityErrorIs(t, m.Evaluate().Err(), ErrEvaluationBudget)
				paritySame(t, cached, m.cached)
				parityTrue(t, m.EventErased(G, session, eventID))
				paritySame(t, cached, m.cached)
				return
			}
			parityTrue(t, m.EventErased(G, session, eventID))
			parityNil(t, m.cached)
		})
	}
}
