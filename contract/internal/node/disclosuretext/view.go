package disclosuretext

import (
	"bytes"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

const RendererVersion = "quoted-local/1;xtext=0.43.0;unicode=15.0.0;empty=neutral/1;tenant-overlay=post-normalize/1;assembled-policy/2"
const ClassifierVersion = "possible-recall-field/1;" + RendererVersion
const MaxViewValue = 2 << 20
const MaxViewOperation = 64 << 20

// Capability is an ordinary factory check, not init/panic. Guarded key
// authority remains usable even if a newer compiler selects different tables.
func Capability() error {
	if norm.Version != "15.0.0" {
		return fail("normalization_unavailable")
	}
	if _, e := localpolicy.Ruleset(); e != nil {
		return fail("local_policy_unavailable")
	}
	return nil
}

// WorkBudget is per operation and must be shared across ALL typed values.
// It counts full transforms, not fitted prefixes. Zero starts a fresh budget.
type WorkBudget struct{ bytes, candidates, assemblyMatches int }

func normalize(value string, b *WorkBudget) (string, bool, error) {
	return normalizeOverlay(value, b, localpolicy.Overlay{})
}

func normalizeOverlay(value string, b *WorkBudget, overlay localpolicy.Overlay) (string, bool, error) {
	value, stripped, err := NormalizePolicyValue(value, b)
	if err != nil {
		return "", false, err
	}
	// Apply the complete verified overlay after every display transformation,
	// before classification, indexing, escaping or fitting can observe it.
	out := overlay.Text(value)
	if len(out) > MaxViewValue {
		return "", false, fail("render_limit")
	}
	return out, stripped, nil
}

// NormalizePolicyValue returns the complete NFKC/control-stripped value for
// admission checks. It is unredacted and must pass the current verified overlay
// before any retention or release. The same bounded transform drives rendering.
func NormalizePolicyValue(value string, b *WorkBudget) (string, bool, error) {
	normalized, err := normalizeNFKC(value, b)
	if err != nil {
		return "", false, err
	}
	clean, stripped := removeControls([]byte(normalized))
	defer clear(clean)
	if !stripped {
		return string(clean), false, nil
	}
	// Removing a control can join a base character and a combining mark (or
	// Hangul jamo). Compose again so later rendering cannot create a new match.
	normalized, err = normalizeNFKC(string(clean), b)
	return normalized, true, err
}

func normalizeNFKC(value string, b *WorkBudget) (string, error) {
	if b == nil || !utf8.ValidString(value) || len(value) > MaxViewValue {
		return "", fail("render_limit")
	}
	if norm.Version != "15.0.0" {
		return "", fail("normalization_unavailable")
	}
	src := []byte(value)
	defer clear(src)
	var dst bytes.Buffer
	var block [4096]byte
	defer clear(block[:])
	t := norm.NFKC
	for {
		nD, nS, e := t.Transform(block[:], src, true)
		if nD > MaxViewValue-dst.Len() {
			clear(dst.Bytes())
			return "", fail("render_limit")
		}
		dst.Write(block[:nD])
		clear(block[:nD])
		src = src[nS:]
		if e == nil {
			break
		}
		if e != transform.ErrShortDst || nD == 0 && nS == 0 {
			clear(dst.Bytes())
			return "", fail("normalization_unavailable")
		}
	}
	defer clear(dst.Bytes())
	if dst.Len() > MaxViewOperation-b.bytes {
		return "", fail("render_limit")
	}
	b.bytes += dst.Len()
	return string(dst.Bytes()), nil
}

func removeControls(in []byte) ([]byte, bool) {
	out := make([]byte, 0, len(in))
	stripped := false
	for i := 0; i < len(in); {
		if in[i] == 0x1b {
			stripped = true
			i++
			if i >= len(in) {
				break
			}
			kind := in[i]
			if kind < 0x20 || kind > 0x7e {
				continue
			}
			i++
			if kind >= 0x20 && kind <= 0x2f {
				for i < len(in) && in[i] >= 0x20 && in[i] <= 0x2f {
					i++
				}
				if i < len(in) && in[i] >= 0x30 && in[i] <= 0x7e {
					i++
				}
				continue
			}
			if kind == '[' {
				for i < len(in) {
					c := in[i]
					i++
					if c >= 0x40 && c <= 0x7e {
						break
					}
				}
			} else if kind == ']' || kind == 'P' || kind == 'X' || kind == '^' || kind == '_' {
				for i < len(in) {
					if in[i] == 7 {
						i++
						break
					}
					if in[i] == 0x1b && i+1 < len(in) && in[i+1] == '\\' {
						i += 2
						break
					}
					i++
				}
			}
			continue
		}
		r, n := utf8.DecodeRune(in[i:])
		i += n
		if r == 0x9b {
			stripped = true
			for i < len(in) {
				c := in[i]
				i++
				if c >= 0x40 && c <= 0x7e {
					break
				}
			}
			continue
		}
		if r == 0x9d || r == 0x90 || r == 0x9e || r == 0x9f {
			stripped = true
			for i < len(in) {
				q, k := utf8.DecodeRune(in[i:])
				i += k
				if q == 7 || q == 0x9c {
					break
				}
				if q == 0x1b && i < len(in) && in[i] == '\\' {
					i++
					break
				}
			}
			continue
		}
		if unicode.Is(unicode.Cf, r) || (r < 0x20 && r != '\n' && r != '\t') || (r >= 0x7f && r <= 0x9f) || r == 0x61c || (r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2060 && r <= 0x206f) || r == 0xfeff || (r >= 0xe0000 && r <= 0xe007f) || (r >= 0xe0100 && r <= 0xe01ef) {
			stripped = true
			continue
		}
		out = utf8.AppendRune(out, r)
	}
	return out, stripped
}

type FieldInput struct {
	Family, EventKind, Value string
	Ordinal                  int
	Overlay                  localpolicy.Overlay
}

// PreparedField is a view, not provenance. Store owns completeness and must
// refuse fresh classification without its exact fixed-builder side fact.
type PreparedField struct {
	value           string
	nonces          []string
	injected, valid bool
}

func (p PreparedField) NonceCandidates() []string { return append([]string(nil), p.nonces...) }

// ProjectionValue is the complete normalized/control-stripped/re-redacted
// view, never the original source. Its availability grants no completeness or
// freshness authority; store must first check its exact provenance and class.
func (p PreparedField) ProjectionValue() string { return p.value }

// InstructionShaped is a restrictive supplementary signal. False never
// establishes freshness, native authenticity, or automatic-channel safety.
func (p PreparedField) InstructionShaped() bool { return instructionShape(p.value) }

type Classification struct{ Class, Reason string }

const (
	NoDetectedMarker          = "no_detected_marker"
	InjectedSource            = "injected_source"
	PossibleMemoryFrame       = "possible_memory_frame"
	ClassificationUnavailable = "classification_unavailable"
)

var fieldFamilies = map[string]bool{"name": true, "goal": true, "anchor_file": true, "milestone": true, "next_steps": true, "step_title": true, "resume_context": true, "progress_notes": true, "handoff_hint": true, "request": true, "text": true, "change_made": true, "title": true, "cwd": true, "repo": true, "text_body": true, "call_tool": true, "call_server": true, "call_command": true, "call_argument": true, "result_excerpt": true, "result_error": true, "result_path": true, "result_token": true, "meta": true, "digest_text": true, "rollup_text": true, "final_summary": true}

func PrepareField(f FieldInput, b *WorkBudget) (PreparedField, error) {
	if f.EventKind == "injected_context" {
		return PreparedField{injected: true, valid: true}, nil
	}
	if f.Ordinal < 0 || f.Ordinal > 4095 || !fieldFamilies[f.Family] {
		return PreparedField{}, fail("unsupported_field")
	}
	s, _, e := normalizeOverlay(f.Value, b, f.Overlay)
	if e != nil {
		return PreparedField{}, e
	}
	// Every delimiter/nonce candidate consumes the same bounded work pool.
	for _, r := range strings.NewReplacer("&lt;", "<", "&#60;", "<", "&#x3c;", "<", `\u003c`, "<").Replace(strings.ToLower(s)) {
		if r == '<' || r == '⟨' || r == '〈' || r == '《' || r == '〈' {
			if b.candidates >= 8192 {
				return PreparedField{}, fail("classification_limit")
			}
			b.candidates++
		}
	}
	nonces := []string{}
	fieldCandidates := strings.Count(strings.NewReplacer("&lt;", "<", "&#60;", "<", "&#x3c;", "<", `\u003c`, "<").Replace(strings.ToLower(s)), "<")
	for _, r := range s {
		if r == '⟨' || r == '〈' || r == '《' || r == '〈' {
			fieldCandidates++
		}
	}
	if fieldCandidates > 256 {
		return PreparedField{}, fail("classification_limit")
	}
	for i := 0; i < len(s); {
		if !hexbyte(s[i]) {
			i++
			continue
		}
		start := i
		for i < len(s) && hexbyte(s[i]) {
			i++
		}
		if i-start == 20 {
			if fieldCandidates+len(nonces) >= 256 || b.candidates >= 8192 {
				return PreparedField{}, fail("classification_limit")
			}
			nonces = append(nonces, strings.ToLower(s[start:i]))
			b.candidates++
		}
	}
	return PreparedField{value: s, nonces: nonces, valid: true}, nil
}
func hexbyte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

var fullMarker = regexp.MustCompile(`(?i)[a-f0-9]{64}@[a-f0-9]{64}`)
var callMarker = regexp.MustCompile(`(?i)call_ref\s*m1\.[a-z2-7]{0,10}`)

func ClassifyField(p PreparedField, matchedNonceIndices []int) Classification {
	if len(matchedNonceIndices) > 256 {
		return Classification{ClassificationUnavailable, "nonce_hint_invalid"}
	}
	if !p.valid {
		return Classification{ClassificationUnavailable, "unprepared_field"}
	}
	if p.injected {
		return Classification{InjectedSource, "injected_context"}
	}
	for _, i := range matchedNonceIndices {
		if i < 0 || i >= len(p.nonces) {
			return Classification{ClassificationUnavailable, "nonce_hint_invalid"}
		}
	}
	if len(matchedNonceIndices) > 0 {
		return Classification{PossibleMemoryFrame, "retained_nonce"}
	}
	s := strings.ToLower(p.value)
	var compact strings.Builder
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' || r == '\r' {
			continue
		}
		compact.WriteRune(r)
	}
	x := compact.String()
	if strings.Contains(x, "memory-evidence") || fullMarker.MatchString(x) || callMarker.MatchString(x) {
		return Classification{PossibleMemoryFrame, "frame_syntax"}
	}
	// Normalize supported literal/HTML delimiter spellings for classification
	// only. Escaping of actual output does not use this detector as authority.
	x = strings.NewReplacer("&lt;", "<", "&#60;", "<", "&#x3c;", "<", `\u003c`, "<", "&gt;", ">", "&#62;", ">", "&#x3e;", ">", `\u003e`, ">").Replace(x)
	for start := 0; start < len(x); {
		r, n := utf8.DecodeRuneInString(x[start:])
		start += n
		if r != '<' && r != '⟨' && r != '〈' && r != '《' && r != '〈' {
			continue
		}
		end := start
		for end < len(x) {
			q, k := utf8.DecodeRuneInString(x[end:])
			if q == '>' || q == '⟩' || q == '〉' || q == '》' || q == '〉' {
				break
			}
			end += k
		}
		span := x[start:end]
		namePrefix := strings.TrimLeft(span, "/!? ")
		for _, fragment := range []string{"mem", "evid", "nonc", "ite", "mark", "call_"} {
			if strings.HasPrefix(namePrefix, fragment) {
				return Classification{PossibleMemoryFrame, "possible_markup"}
			}
		}
		for _, reserved := range []string{"memory", "evidence", "nonce", "item", "marker", "call_ref"} {
			if strings.Contains(span, reserved) {
				return Classification{PossibleMemoryFrame, "possible_markup"}
			}
		}
		// Non-ASCII letters/symbols in a markup-looking name overexclude
		// only this field, never ordinary Unicode prose outside brackets.
		name := strings.TrimLeft(span, "/!?")
		for _, q := range name {
			if q == '=' || q == '"' || q == '\'' || q == '/' {
				break
			}
			if q > 127 && (unicode.IsLetter(q) || unicode.IsSymbol(q)) {
				return Classification{PossibleMemoryFrame, "possible_markup"}
			}
		}
		start = end
	}
	return Classification{NoDetectedMarker, "none"}
}
