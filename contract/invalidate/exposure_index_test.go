package invalidate

import (
	"context"
	"errors"
	"fmt"
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
