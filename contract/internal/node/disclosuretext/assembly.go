package disclosuretext

import (
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
)

// ProjectionSpan maps bytes of the complete joined projection back to an input
// field. Empty fields contribute no bytes and have no span.
type ProjectionSpan struct{ Start, End, Field int }

type Assembly struct {
	Text       string
	Spans      []ProjectionSpan
	Restricted bool
}

// CheckAssembly consumes fully normalized, individually overlaid values, in
// display order, before persistence, escaping or fitting. A match formed by a
// join suppresses the entire assembly and all contributing source fields. This
// deliberately conservative unit prevents removing a matched field from making
// another forbidden join, and never changes a retained signed body.
func CheckAssembly(values []string, overlay localpolicy.Overlay, work *WorkBudget) (Assembly, error) {
	var out Assembly
	size, count := 0, 0
	for _, v := range values {
		if v == "" {
			continue
		}
		if count > 0 {
			size++
		}
		if len(v) > MaxViewValue-size {
			return out, fail("render_limit")
		}
		size += len(v)
		count++
	}
	if work == nil || size > MaxViewOperation-work.bytes {
		return out, fail("render_limit")
	}
	// Charge the complete join before allocating it or running policy patterns.
	work.bytes += size
	var text strings.Builder
	text.Grow(size)
	for i, v := range values {
		if v == "" {
			continue
		}
		if text.Len() > 0 {
			text.WriteByte('\n')
		}
		start := text.Len()
		text.WriteString(v)
		out.Spans = append(out.Spans, ProjectionSpan{start, text.Len(), i})
	}
	joined := text.String()
	if overlay.Text(joined) != joined {
		out.Restricted = true
		return out, nil
	}
	out.Text = joined
	return out, nil
}
