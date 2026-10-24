package disclosuretext

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// AssemblyPolicy keeps interval detection and redaction tied to the same policy.
// The store constructs it only from its current verified tenant policy. Its zero
// value selects the ordinary local overlay, just like localpolicy.Overlay.
type AssemblyPolicy struct {
	overlay  localpolicy.Overlay
	patterns []*regexp.Regexp
}

func NewAssemblyPolicy(body *record.PolicyBody) (AssemblyPolicy, error) {
	o, err := localpolicy.TenantOverlay(body)
	if err != nil {
		return AssemblyPolicy{}, err
	}
	p := AssemblyPolicy{overlay: o}
	if body != nil {
		for _, shape := range body.Redaction.Shapes {
			r, err := regexp.Compile(shape.RE2)
			if err != nil {
				return AssemblyPolicy{}, err
			}
			p.patterns = append(p.patterns, r)
		}
	}
	return p, nil
}

// FieldOverlay returns the same immutable overlay for per-field preparation.
func (p AssemblyPolicy) FieldOverlay() localpolicy.Overlay { return p.overlay }
func (p AssemblyPolicy) Text(s string) string              { return p.overlay.Text(s) }

// ProjectionSpan maps bytes in a joined projection back to an input field.
// Spans always describe the original join, including subsequently removed fields.
type ProjectionSpan struct{ Start, End, Field int }

type Assembly struct {
	Text       string
	Spans      []ProjectionSpan
	Suppressed []int
	Restricted bool
}

// CheckAssembly consumes complete normalized, individually overlaid fields in
// release order. Only fields intersecting actual tenant matches are removed.
// Every removal is followed by a complete recheck: it can create a new join.
// Input is never changed. No partial result is usable when work is exhausted.
func CheckAssembly(values []string, policy AssemblyPolicy, work *WorkBudget) (Assembly, error) {
	var out Assembly
	if work == nil || len(values) > 64*(4096+6) {
		return out, fail("render_limit")
	}
	removed := make([]bool, len(values))
	// Each nonterminal pass must remove at least one field. Byte charges and
	// the shared interval cap also bound repeated tiny/empty-match policies.
	for pass := 0; pass <= len(values); pass++ {
		if len(values) > MaxViewOperation-work.bytes {
			return Assembly{}, fail("render_limit")
		}
		work.bytes += len(values)
		size, count := 0, 0
		for i, v := range values {
			if removed[i] || v == "" {
				continue
			}
			if count > 0 {
				size++
			}
			if len(v) > MaxViewValue-size {
				return Assembly{}, fail("render_limit")
			}
			size += len(v)
			count++
		}
		if size > MaxViewOperation-work.bytes {
			return Assembly{}, fail("render_limit")
		}
		work.bytes += size
		var text strings.Builder
		text.Grow(size)
		var spans []ProjectionSpan
		for i, v := range values {
			if removed[i] || v == "" {
				continue
			}
			if text.Len() > 0 {
				text.WriteByte('\n')
			}
			start := text.Len()
			text.WriteString(v)
			spans = append(spans, ProjectionSpan{start, text.Len(), i})
		}
		if pass == 0 {
			out.Spans = spans
		}
		joined := text.String()
		var matches [][2]int
		for _, p := range policy.patterns {
			if size > MaxViewOperation-work.bytes {
				return Assembly{}, fail("render_limit")
			}
			work.bytes += size
			xs := p.FindAllStringIndex(joined, 8193-work.assemblyMatches)
			if len(xs) > 8192-work.assemblyMatches {
				return Assembly{}, fail("render_limit")
			}
			work.assemblyMatches += len(xs)
			for _, x := range xs {
				if x[0] == x[1] {
					return Assembly{}, fail("assembled_policy_unavailable")
				}
				matches = append(matches, [2]int{x[0], x[1]})
			}
		}
		if len(matches) == 0 {
			// The local redactor has no interval API. An unexpected local-only
			// transformation cannot be attributed to tenant matches; refuse it
			// rather than inventing a map or releasing an unchecked join.
			if policy.Text(joined) != joined {
				return Assembly{}, fail("assembled_policy_unavailable")
			}
			out.Text = joined
			return out, nil
		}
		sort.Slice(matches, func(i, j int) bool { return matches[i][0] < matches[j][0] })
		// Merge intervals so attribution is linear in fields plus matches.
		merged := matches[:0]
		for _, m := range matches {
			if len(merged) > 0 && m[0] <= merged[len(merged)-1][1] {
				merged[len(merged)-1][1] = max(merged[len(merged)-1][1], m[1])
			} else {
				merged = append(merged, m)
			}
		}
		progress, mi := false, 0
		for _, span := range spans {
			for mi < len(merged) && merged[mi][1] <= span.Start {
				mi++
			}
			if mi == len(merged) {
				break
			}
			m := merged[mi]
			intersects := m[0] < span.End && m[1] > span.Start
			if intersects {
				removed[span.Field] = true
				out.Suppressed = append(out.Suppressed, span.Field)
				progress = true
			}
		}
		if !progress {
			return Assembly{}, fail("assembled_policy_unavailable")
		}
		out.Restricted = true
	}
	return Assembly{}, fail("render_limit")
}
