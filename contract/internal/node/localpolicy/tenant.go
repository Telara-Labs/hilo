package localpolicy

import (
	"github.com/Telara-Labs/hilo/contract/record"
	"regexp"
)

// Overlay is constructed only from a verified tenant policy by the store. RE2
// patterns and total work are bounded by the contract's closed policy schema.
type Overlay struct{ patterns []*regexp.Regexp }

func TenantOverlay(b *record.PolicyBody) (Overlay, error) {
	var out Overlay
	if b == nil {
		return out, nil
	}
	if len(b.Redaction.Shapes) > 256 {
		return out, policyError{}
	}
	total := 0
	for _, shape := range b.Redaction.Shapes {
		total += len(shape.RE2)
		if total > 65536 {
			return Overlay{}, policyError{}
		}
		p, err := regexp.Compile(shape.RE2)
		if err != nil {
			return Overlay{}, policyError{}
		}
		out.patterns = append(out.patterns, p)
	}
	return out, nil
}
func (o Overlay) Text(s string) string {
	s = Text(s)
	for _, p := range o.patterns {
		s = p.ReplaceAllLiteralString(s, "[REDACTED]")
	}
	return s
}
func (o Overlay) Argument(name, s string) string { return o.Text(Argument(name, s)) }
