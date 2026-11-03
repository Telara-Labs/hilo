package ranking

import "testing"

func TestDiversityPenaltyAndCaps(t *testing.T) {
	scores := []ScoredResult{{ID: "a", Score: 1}, {ID: "b", Score: .99}, {ID: "c", Score: .94}, {ID: "d", Score: .93}, {ID: "e", Score: .92}}
	signals := map[string]DiversitySignals{
		"a": {Session: "s1", Owner: "o", Task: "t", Kind: "digest", Terms: []string{"one", "two"}},
		"b": {Session: "s1", Owner: "o", Task: "t", Kind: "digest", Terms: []string{"one", "two"}},
		"c": {Session: "s2", Owner: "o", Task: "t", Kind: "activity", Terms: []string{"three"}},
		"d": {Session: "s3", Owner: "o", Task: "t", Kind: "activity", Terms: []string{"four"}},
		"e": {Session: "s4", Owner: "other", Task: "t", Kind: "activity", Terms: []string{"five"}},
	}
	got, err := Diversify(scores, signals, 5)
	if err != nil || len(got) != 4 || got[0].ID != "a" || got[1].ID != "c" || got[2].ID != "d" || got[3].ID != "e" {
		t.Fatalf("got %+v, %v", got, err)
	}
	for _, hit := range got {
		if hit.ID == "b" {
			t.Fatal("owner/task cap allowed fourth hit")
		}
	}
}
func TestDiversitySessionCapAndValidation(t *testing.T) {
	scores := []ScoredResult{{ID: "a", Score: .5}, {ID: "b", Score: .5}, {ID: "c", Score: .5}}
	signals := map[string]DiversitySignals{"a": {Session: "s", Owner: "o1", Task: "t", Kind: "x"}, "b": {Session: "s", Owner: "o2", Task: "t", Kind: "x"}, "c": {Session: "s", Owner: "o3", Task: "t", Kind: "x"}}
	got, err := Diversify(scores, signals, 3)
	if err != nil || len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
		t.Fatalf("got %+v, %v", got, err)
	}
	bad := signals["a"]
	bad.Terms = []string{"x", "x"}
	signals["a"] = bad
	if _, err := Diversify(scores, signals, 3); err == nil {
		t.Fatal("accepted duplicate terms")
	}
}
