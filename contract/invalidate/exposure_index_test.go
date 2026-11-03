package invalidate

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
)

func TestExposureIndexPreservesMatchingAndBounds(t *testing.T) {
	m := NewModel()
	m.Admit(Item{ID: "a", SessionKey: "session", SessionSeq: 2, Scope: "scope", OriginMachine: "machine", Explicit: true})
	m.Admit(Item{ID: "b", SessionKey: "other", Scope: "scope", OriginMachine: "other", Explicit: true})
	for _, e := range []Exposure{
		{ID: "same", AffectsIDs: []string{"a", "a"}},
		{ID: "same", AffectsIDs: []string{"b"}},
		{ID: "session-root", SessionKey: "session", Seq: 1},
		{ID: "scope-root", Scope: "scope", OriginMachine: "machine", UnknownOrder: true},
	} {
		m.Expose(e)
	}
	b := &evaluationBudget{Context: context.Background(), affects: make([]map[string]struct{}, len(m.exposures))}
	for i, e := range m.exposures {
		b.affects[i] = make(map[string]struct{})
		for _, id := range e.AffectsIDs {
			b.affects[i][id] = struct{}{}
		}
	}
	for _, item := range m.items {
		for i, e := range m.exposures {
			if got, want := m.downstreamContext(b, item, i), m.downstream(item, e); got != want {
				t.Fatalf("exposure %d item %s: got %v want %v", i, item.ID, got, want)
			}
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := m.downstreamContext(&evaluationBudget{Context: canceled, affects: b.affects}, m.items["a"], 0); got {
		t.Fatal("canceled lookup returned a match")
	}
	if !errors.Is((&evaluationBudget{Context: context.Background(), work: maxEvaluationWork}).Err(), ErrEvaluationBudget) {
		t.Fatal("work limit did not refuse")
	}
}

func TestExposureIndexAllowsBoundedSparseGraph(t *testing.T) {
	m := NewModel()
	for i := 0; i < 100; i++ {
		m.Admit(Item{ID: fmt.Sprintf("item-%d", i), Kind: record.KindTask})
	}
	ids := make([]string, 300)
	for i := range ids {
		ids[i] = fmt.Sprintf("absent-%d", i)
	}
	for i := 0; i < 100; i++ {
		m.Expose(Exposure{ID: "item-0", AffectsIDs: ids})
	}
	if _, err := m.EvaluateContext(context.Background()); err != nil {
		t.Fatalf("bounded sparse exposure graph refused: %v", err)
	}
}

func TestExposureIndexPreflightChargesConstruction(t *testing.T) {
	m := NewModel()
	m.Admit(Item{ID: "a"})
	ids := make([]string, maxEvaluationWork+1)
	m.Expose(Exposure{ID: "root", AffectsIDs: ids})
	if _, err := m.EvaluateContext(context.Background()); !errors.Is(err, ErrEvaluationBudget) {
		t.Fatalf("oversized index was not refused: %v", err)
	}
}

func TestExposureRootsUnionPreservesDistinctRootsAndRefusesBudget(t *testing.T) {
	m := NewModel()
	m.Admit(Item{ID: "item", SessionKey: "s", SessionSeq: 2})
	m.Expose(Exposure{ID: "root-a", AffectsIDs: []string{"item"}})
	m.Expose(Exposure{ID: "root-a", SessionKey: "s", Seq: 1})
	m.Expose(Exposure{ID: "root-b", AffectsIDs: []string{"item"}})
	b := &evaluationBudget{Context: context.Background(), affects: []map[string]struct{}{{"item": {}}, {}, {"item": {}}}, roots: map[string][]string{}}
	roots, err := m.exposureRoots(b, m.items["item"])
	if err != nil || len(roots) != 2 || roots[0] != "root-a" || roots[1] != "root-b" {
		t.Fatalf("distinct roots lost: %v %v", roots, err)
	}
	work := b.work
	if _, err := m.exposureRoots(b, m.items["item"]); err != nil || b.work > work+2 {
		t.Fatalf("cache did not bound repeated probes: %d to %d: %v", work, b.work, err)
	}
	exhausted := &evaluationBudget{Context: context.Background(), work: maxEvaluationWork, affects: b.affects, roots: map[string][]string{}}
	if _, err := m.exposureRoots(exhausted, m.items["item"]); !errors.Is(err, ErrEvaluationBudget) {
		t.Fatalf("exhaustion did not refuse: %v", err)
	}
}

type refusingSpendContext struct {
	context.Context
	remaining int
}

func (c *refusingSpendContext) SpendWork(n int) error {
	c.remaining -= n
	if c.remaining < 0 {
		return ErrEvaluationBudget
	}
	return nil
}

func TestExposureRootsEmptyAndPartialRefusal(t *testing.T) {
	m := NewModel()
	m.Admit(item("empty"))
	m.Expose(Exposure{ID: hx("root"), AffectsIDs: []string{hx("other")}})
	b := &evaluationBudget{Context: context.Background(), affects: []map[string]struct{}{{hx("other"): {}}}, roots: map[string][]string{}}
	roots, err := m.exposureRoots(b, m.items[hx("empty")])
	if err != nil || len(roots) != 0 {
		t.Fatalf("empty: %v %v", roots, err)
	}
	work := b.work
	_, err = m.exposureRoots(b, m.items[hx("empty")])
	if err != nil || b.work > work+2 {
		t.Fatalf("empty not cached: %d %d %v", work, b.work, err)
	}
	m.Expose(Exposure{ID: hx("other-root"), AffectsIDs: []string{hx("empty")}})
	m.Expose(Exposure{ID: hx("last-root"), AffectsIDs: []string{hx("empty")}})
	b = &evaluationBudget{Context: &refusingSpendContext{Context: context.Background(), remaining: 2}, affects: []map[string]struct{}{{hx("other"): {}}, {hx("empty"): {}}, {hx("empty"): {}}}, roots: map[string][]string{"already": {"safe"}}}
	if _, err = m.exposureRoots(b, m.items[hx("empty")]); !errors.Is(err, ErrEvaluationBudget) {
		t.Fatalf("parent refusal: %v", err)
	}
	if _, ok := b.roots[hx("empty")]; ok {
		t.Fatal("partial roots cached")
	}
	if len(b.roots["already"]) != 1 || b.roots["already"][0] != "safe" {
		t.Fatal("existing cache changed on refusal")
	}
}

func TestExposureEvaluationDuplicateRootsParity(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		build := func(duplicates bool) *Model {
			m := snapshotModel(t)
			a := item("cycle-a", "cycle-b")
			b := item("cycle-b", "cycle-a")
			m.Admit(a)
			m.Admit(b)
			exposures := []Exposure{{ID: hx("root"), AffectsIDs: []string{a.ID}}, {ID: hx("root"), AffectsIDs: []string{b.ID}}}
			if reverse {
				exposures[0], exposures[1] = exposures[1], exposures[0]
			}
			for _, e := range exposures {
				m.Expose(e)
				if duplicates {
					m.Expose(e)
				}
			}
			return m
		}
		a, err := build(false).EvaluateDetachedContext(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		b, err := build(true).EvaluateDetachedContext(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a.Status, b.Status) || !reflect.DeepEqual(a.Tombs, b.Tombs) || !reflect.DeepEqual(a.HoldCauses, b.HoldCauses) || !reflect.DeepEqual(a.Causes, b.Causes) {
			t.Fatalf("duplicate exposures changed evaluation: %#v %#v", a.Status, b.Status)
		}
	}
}

func TestExposureRootsDenseUniqueBudgetRefusesWithoutCache(t *testing.T) {
	m := NewModel()
	m.Admit(Item{ID: "target"})
	idx := make([]map[string]struct{}, 1024)
	for i := range idx {
		m.Expose(Exposure{ID: fmt.Sprintf("root-%d", i), AffectsIDs: []string{"target"}})
		idx[i] = map[string]struct{}{"target": {}}
	}
	b := &evaluationBudget{Context: context.Background(), bytes: maxEvaluationBytes - 1000, affects: idx, roots: map[string][]string{}}
	if _, err := m.exposureRoots(b, m.items["target"]); !errors.Is(err, ErrEvaluationBudget) {
		t.Fatalf("dense roots did not refuse: %v", err)
	}
	if _, ok := b.roots["target"]; ok {
		t.Fatal("memory refusal cached partial roots")
	}
}

func TestExposureRootsCancellationDoesNotCachePartial(t *testing.T) {
	m := NewModel()
	m.Admit(Item{ID: "target"})
	m.Expose(Exposure{ID: "root", AffectsIDs: []string{"target"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := &evaluationBudget{Context: ctx, affects: []map[string]struct{}{{"target": {}}}, roots: map[string][]string{}}
	if _, err := m.exposureRoots(b, m.items["target"]); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if _, ok := b.roots["target"]; ok {
		t.Fatal("cancel cached partial roots")
	}
}
