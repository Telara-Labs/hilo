package ranking

import (
	"fmt"
	"math"
	"sort"
)

// Signals are computed from currently authorized, already relevant candidates.
// Kind and evidence labels must reflect verified source data, not model output.
type Signals struct {
	TermCoverage float64 // fraction of distinct non-stopword query terms matched
	Kind         string  // conclusion, head, digest-outcome, activity, or other
	Evidence     string  // revision, observation, or none
	Recency      string  // day, week, month, or older
}
type ScoredResult struct {
	ID         string
	RRF, Score float64
}

// Score calculates the preliminary 01-memory score and relevance cutoff. It
// intentionally accepts lanes, not arbitrary candidates: priors cannot create
// relevance. Signals must exist for exactly the candidates admitted by Fuse.
// Authorization, verified labels, diversity, pagination and delivery checks
// are caller responsibilities; this is not a disclosure boundary.
func Score(lanes Lanes, threshold *float64, signals map[string]Signals) ([]ScoredResult, error) {
	fused, err := Fuse(lanes, threshold)
	if err != nil {
		return nil, err
	}
	if len(signals) != len(fused) {
		return nil, fmt.Errorf("signals do not match eligible candidates")
	}
	out := make([]ScoredResult, 0, len(fused))
	for _, hit := range fused {
		s, ok := signals[hit.ID]
		if !ok || math.IsNaN(s.TermCoverage) || math.IsInf(s.TermCoverage, 0) || s.TermCoverage < 0 || s.TermCoverage > 1 {
			return nil, fmt.Errorf("invalid candidate signals")
		}
		var kind, evidence, recency float64
		switch s.Kind {
		case "conclusion":
			kind = .08
		case "head":
			kind = .07
		case "digest-outcome":
			kind = .05
		case "activity":
			kind = .02
		case "other":
		default:
			return nil, fmt.Errorf("invalid kind")
		}
		switch s.Evidence {
		case "revision":
			evidence = .05
		case "observation":
			evidence = .02
		case "none":
		default:
			return nil, fmt.Errorf("invalid evidence")
		}
		switch s.Recency {
		case "day":
			recency = .05
		case "week":
			recency = .035
		case "month":
			recency = .02
		case "older":
		default:
			return nil, fmt.Errorf("invalid recency")
		}
		if hit.RRF < .70 && s.TermCoverage < .20 {
			continue
		}
		out = append(out, ScoredResult{ID: hit.ID, RRF: hit.RRF, Score: .78*hit.RRF + .10*s.TermCoverage + kind + evidence + recency})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
