package ranking

import (
	"fmt"
	"math"
)

// DiversitySignals describe an already eligible, authorized candidate. Terms
// are normalized by the caller and are used as sets for Jaccard similarity.
type DiversitySignals struct {
	Session, Owner, Task, Kind string
	Terms                      []string
}
type DiversifiedResult struct {
	ScoredResult
	AdjustedScore float64
}

// Diversify greedily selects at most limit scored hits. It subtracts .16 times
// the maximum Jaccard overlap with previously selected hits and .035 if any
// selected hit has the same kind, then applies session and owner/task caps.
// This pure calculation does not authorize candidates or recheck delivery.
func Diversify(scored []ScoredResult, signals map[string]DiversitySignals, limit int) ([]DiversifiedResult, error) {
	if len(scored) > 350 || limit < 0 || limit > 350 || len(signals) != len(scored) {
		return nil, fmt.Errorf("invalid diversity input")
	}
	type item struct {
		result ScoredResult
		sig    DiversitySignals
		terms  map[string]bool
	}
	items := make([]item, 0, len(scored))
	seen := map[string]bool{}
	for _, hit := range scored {
		s, ok := signals[hit.ID]
		if hit.ID == "" || seen[hit.ID] || !ok || math.IsNaN(hit.Score) || math.IsInf(hit.Score, 0) || hit.Score < 0 || hit.Score > 1.08 || s.Session == "" || s.Owner == "" || s.Task == "" || s.Kind == "" || len(s.Terms) > 128 {
			return nil, fmt.Errorf("invalid diversity candidate")
		}
		seen[hit.ID] = true
		terms := map[string]bool{}
		for _, term := range s.Terms {
			if term == "" || len(term) > 256 || terms[term] {
				return nil, fmt.Errorf("invalid diversity term")
			}
			terms[term] = true
		}
		items = append(items, item{hit, s, terms})
	}
	overlaps := make([]float64, len(items))
	sameKinds := make([]bool, len(items))
	out := []DiversifiedResult{}
	sessions := map[string]int{}
	ownerTasks := map[[2]string]int{}
	for len(out) < limit {
		best, bestScore := -1, math.Inf(-1)
		for i, candidate := range items {
			if candidate.result.ID == "" || sessions[candidate.sig.Session] >= 2 || ownerTasks[[2]string{candidate.sig.Owner, candidate.sig.Task}] >= 3 {
				continue
			}
			value := candidate.result.Score - .16*overlaps[i]
			if sameKinds[i] {
				value -= .035
			}
			if best < 0 || value > bestScore || (value == bestScore && candidate.result.ID < items[best].result.ID) {
				best, bestScore = i, value
			}
		}
		if best < 0 {
			break
		}
		item := items[best]
		items[best].result.ID = ""
		for i, candidate := range items {
			if candidate.result.ID == "" {
				continue
			}
			intersection := 0
			for term := range candidate.terms {
				if item.terms[term] {
					intersection++
				}
			}
			union := len(candidate.terms) + len(item.terms) - intersection
			if union > 0 {
				v := float64(intersection) / float64(union)
				if v > overlaps[i] {
					overlaps[i] = v
				}
			}
			if candidate.sig.Kind == item.sig.Kind {
				sameKinds[i] = true
			}
		}
		out = append(out, DiversifiedResult{item.result, bestScore})
		sessions[item.sig.Session]++
		ownerTasks[[2]string{item.sig.Owner, item.sig.Task}]++
	}
	return out, nil
}
