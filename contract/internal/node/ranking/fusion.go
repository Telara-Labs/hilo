// Package ranking provides pure relevance and rank-fusion arithmetic. Callers
// must authorize and recheck every candidate before exposing any output.
package ranking

import (
	"fmt"
	"math"
	"sort"
)

// LexicalHit must identify an exact non-stopword match, not merely an FTS hit.
// Rank is its one-based position in the bounded source lane.
type LexicalHit struct {
	ID        string
	ExactTerm bool
}
type SemanticHit struct {
	ID     string
	Cosine float64
}
type Lanes struct {
	Passages, Events []LexicalHit
	Anchors          []string
	Semantic         []SemanticHit
}
type Result struct {
	ID  string
	RRF float64
}

// Fuse applies the 01-memory RRF formula over already authorized lanes. A nil
// threshold makes semantic scores ranking-only; a calibrated threshold may
// admit a semantic-only candidate. It does not perform authorization, passage
// lifting, final scoring, term coverage, diversification, or delivery rechecks.
// Callers must obtain and apply all required policy checks independently.
func Fuse(lanes Lanes, threshold *float64) ([]Result, error) {
	if len(lanes.Passages) > 100 || len(lanes.Events) > 100 || len(lanes.Anchors) > 50 || len(lanes.Semantic) > 100 {
		return nil, fmt.Errorf("ranking lane exceeds bound")
	}
	if threshold != nil && (math.IsNaN(*threshold) || math.IsInf(*threshold, 0) || *threshold < -1 || *threshold > 1) {
		return nil, fmt.Errorf("invalid calibrated threshold")
	}
	type entry struct {
		score    float64
		relevant bool
	}
	entries := make(map[string]*entry)
	add := func(id string, rank int, relevant bool) error {
		if id == "" || len(id) > 256 {
			return fmt.Errorf("invalid candidate id")
		}
		e := entries[id]
		if e == nil {
			e = &entry{}
			entries[id] = e
		}
		e.score += 1 / float64(60+rank)
		e.relevant = e.relevant || relevant
		return nil
	}
	lex := func(hits []LexicalHit) error {
		seen := map[string]bool{}
		for i, h := range hits {
			if seen[h.ID] {
				return fmt.Errorf("duplicate candidate in lane")
			}
			seen[h.ID] = true
			if err := add(h.ID, i+1, h.ExactTerm); err != nil {
				return err
			}
		}
		return nil
	}
	if err := lex(lanes.Passages); err != nil {
		return nil, err
	}
	if err := lex(lanes.Events); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i, id := range lanes.Anchors {
		if seen[id] {
			return nil, fmt.Errorf("duplicate anchor")
		}
		seen[id] = true
		if err := add(id, i+1, true); err != nil {
			return nil, err
		}
	}
	seen = map[string]bool{}
	for i, h := range lanes.Semantic {
		if seen[h.ID] || math.IsNaN(h.Cosine) || math.IsInf(h.Cosine, 0) || h.Cosine < -1 || h.Cosine > 1 {
			return nil, fmt.Errorf("invalid semantic hit")
		}
		seen[h.ID] = true
		if err := add(h.ID, i+1, threshold != nil && h.Cosine >= *threshold); err != nil {
			return nil, err
		}
	}
	var best float64
	for _, e := range entries {
		if e.relevant && e.score > best {
			best = e.score
		}
	}
	if best == 0 {
		return []Result{}, nil
	}
	results := make([]Result, 0, len(entries))
	for id, e := range entries {
		if e.relevant {
			results = append(results, Result{ID: id, RRF: e.score / best})
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].RRF != results[j].RRF {
			return results[i].RRF > results[j].RRF
		}
		return results[i].ID < results[j].ID
	})
	return results, nil
}
