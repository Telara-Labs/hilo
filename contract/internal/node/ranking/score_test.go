package ranking

import (
	"math"
	"testing"
)

func TestScoreUsesPriorsOnlyAfterRelevance(t *testing.T) {
	lanes := Lanes{Passages: []LexicalHit{{"a", true}, {"b", true}}, Semantic: []SemanticHit{{"irrelevant", .99}}}
	signals := map[string]Signals{"a": {TermCoverage: .5, Kind: "activity", Evidence: "none", Recency: "older"}, "b": {TermCoverage: .5, Kind: "conclusion", Evidence: "revision", Recency: "day"}}
	got, err := Score(lanes, nil, signals)
	if err != nil || len(got) != 2 || got[0].ID != "b" {
		t.Fatalf("got %+v, %v", got, err)
	}
	signals["irrelevant"] = Signals{TermCoverage: 1, Kind: "conclusion", Evidence: "revision", Recency: "day"}
	if _, err := Score(lanes, nil, signals); err == nil {
		t.Fatal("accepted signals for ineligible candidate")
	}
}
func TestScoreCutoffAndMalformedSignals(t *testing.T) {
	lanes := Lanes{Passages: []LexicalHit{{"top", true}, {"tail", true}}, Events: []LexicalHit{{"top", true}}, Anchors: []string{"top"}, Semantic: []SemanticHit{{"top", .9}}}
	signals := map[string]Signals{"top": {Kind: "other", Evidence: "none", Recency: "older"}, "tail": {Kind: "other", Evidence: "none", Recency: "older"}}
	got, err := Score(lanes, nil, signals)
	if err != nil || len(got) != 1 || got[0].ID != "top" {
		t.Fatalf("got %+v, %v", got, err)
	}
	s := signals["tail"]
	s.TermCoverage = .2
	signals["tail"] = s
	got, err = Score(lanes, nil, signals)
	if err != nil || len(got) != 2 {
		t.Fatalf("coverage cutoff: %+v, %v", got, err)
	}
	s.TermCoverage = math.NaN()
	signals["tail"] = s
	if _, err := Score(lanes, nil, signals); err == nil {
		t.Fatal("accepted NaN")
	}
	delete(signals, "tail")
	if _, err := Score(lanes, nil, signals); err == nil {
		t.Fatal("accepted missing signals")
	}
}
