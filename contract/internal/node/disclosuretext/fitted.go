package disclosuretext

import "sort"

// Coordinates describe only source-derived bytes in the final formatted reply.
// Generated frame, quote prefixes and fitting markers have no source attribution.
type renderSource struct {
	item, field int
	label       bool
}
type renderSpan struct {
	start, end int
	source     renderSource
}

// fittedReplyMatches checks exactly the bytes that would be persisted/released.
// A match must intersect retained source bytes; generated-only and empty matches
// refuse rather than guessing which source should be removed. Each caller pass
// removes all returned fields, then rebuilds and rechecks from the complete input.
func fittedReplyMatches(text string, spans []renderSpan, policy AssemblyPolicy, work *WorkBudget) ([]renderSource, error) {
	if work == nil || len(text) > MaxViewOperation-work.bytes || len(spans) > (MaxViewOperation-work.bytes-len(text))/64 {
		return nil, fail("render_limit")
	}
	work.bytes += len(text) + 64*len(spans)
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i, span := range spans {
		if span.start < 0 || span.start >= span.end || span.end > len(text) || (i > 0 && spans[i-1].end > span.start) {
			return nil, fail("assembled_policy_unavailable")
		}
	}
	var matches [][2]int
	for _, p := range policy.patterns {
		if len(text) > MaxViewOperation-work.bytes {
			return nil, fail("render_limit")
		}
		work.bytes += len(text)
		xs := p.FindAllStringIndex(text, 8193-work.assemblyMatches)
		if len(xs) > 8192-work.assemblyMatches {
			return nil, fail("render_limit")
		}
		work.assemblyMatches += len(xs)
		for _, x := range xs {
			if x[0] == x[1] {
				return nil, fail("assembled_policy_unavailable")
			}
			matches = append(matches, [2]int{x[0], x[1]})
		}
	}
	if len(matches) == 0 {
		if policy.Text(text) != text {
			return nil, fail("assembled_policy_unavailable")
		}
		return nil, nil
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i][0] < matches[j][0] })
	// Do not merge matches before attribution: each match needs its own witness,
	// including a generated-only match adjacent to a source-bearing match.
	seen := map[renderSource]bool{}
	var removed []renderSource
	si := 0
	for _, m := range matches {
		for si < len(spans) && spans[si].end <= m[0] {
			si++
		}
		attributed := false
		for j := si; j < len(spans) && spans[j].start < m[1]; j++ {
			if work.bytes >= MaxViewOperation {
				return nil, fail("render_limit")
			}
			work.bytes++
			attributed = true
			src := spans[j].source
			if !seen[src] {
				seen[src] = true
				removed = append(removed, src)
			}
		}
		if !attributed {
			return nil, fail("assembled_policy_unavailable")
		}
	}
	return removed, nil
}
