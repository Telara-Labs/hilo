package ranking

import (
	"math"
	"testing"
)

func TestUncalibratedSemanticCannotAdmitButCanRank(t *testing.T) {
	lanes := Lanes{Passages: []LexicalHit{{"b", true}, {"a", true}, {"fts-only", false}}, Semantic: []SemanticHit{{"unrelated", .9}, {"a", .8}}}
	got, err := Fuse(lanes, nil)
	if err != nil || len(got) != 2 || got[0].ID != "a" || got[0].RRF != 1 || got[1].ID != "b" {
		t.Fatalf("got %+v, %v", got, err)
	}
}
func TestCalibratedThresholdAndStableTies(t *testing.T) {
	floor := .8
	got, err := Fuse(Lanes{Anchors: []string{"anchor"}, Semantic: []SemanticHit{{"high", .9}, {"low", .79}}}, &floor)
	if err != nil || len(got) != 2 || got[0].ID != "anchor" || got[1].ID != "high" || got[0].RRF != 1 || got[1].RRF != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
}
func TestRejectMalformedAndOverBudget(t *testing.T) {
	for _, lanes := range []Lanes{
		{Anchors: []string{"a", "a"}}, {Passages: []LexicalHit{{"", true}}}, {Semantic: []SemanticHit{{"a", math.NaN()}}}, {Semantic: []SemanticHit{{"a", 1.1}}}, {Events: make([]LexicalHit, 101)},
	} {
		if _, err := Fuse(lanes, nil); err == nil {
			t.Fatalf("accepted %+v", lanes)
		}
	}
	bad := math.Inf(1)
	if _, err := Fuse(Lanes{}, &bad); err == nil {
		t.Fatal("accepted invalid floor")
	}
	got, err := Fuse(Lanes{Semantic: []SemanticHit{{"a", .9}}}, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
}
