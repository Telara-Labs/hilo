// Package jcs is the strict canonical JSON gate of the record contract.
//
// Canonicalize accepts exactly one I-JSON value (RFC 7493) and returns its
// RFC 8785 (JSON Canonicalization Scheme) encoding. Before encoding it
// rejects everything a lenient decoder would silently repair:
//
//   - input that is not valid UTF-8 (Go's decoder replaces it with U+FFFD),
//   - a \uD800-\uDFFF escape that is not part of a valid surrogate pair,
//   - Unicode noncharacters, which I-JSON forbids,
//   - duplicate object member names, compared after unescaping,
//   - any byte other than JSON whitespace after the value,
//   - numbers that do not fit an IEEE-754 double (overflow or underflow).
//
// CanonicalizeRecord applies the record profile on top: no null anywhere,
// and every number an integer literal with magnitude at most 2^53-1.
//
// Encoding uses the published strict TAP contract canonicalizer after the narrower record gate.
package jcs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	tapcanon "github.com/Telara-Labs/TAP-Runtime/contract/canon"
)

// MaxDepth bounds nesting of arrays and objects. Records nest a handful of
// levels; the bound keeps a hostile input from exhausting the stack.
const MaxDepth = 64

// MaxSafeInteger is 2^53-1, the largest integer every JSON implementation
// represents exactly.
const MaxSafeInteger = 1<<53 - 1

// Error codes returned in *Error.Code.
const (
	CodeSyntax         = "syntax"
	CodeInvalidUTF8    = "invalid_utf8"
	CodeLoneSurrogate  = "lone_surrogate"
	CodeNoncharacter   = "noncharacter"
	CodeDuplicateKey   = "duplicate_key"
	CodeTrailingData   = "trailing_data"
	CodeNumberRange    = "number_range"
	CodeDepth          = "depth"
	CodeNullNotAllowed = "null_not_allowed"
	CodeNotInteger     = "not_integer"
)

// Error is a rejection with a stable code and the byte offset where it was
// detected.
type Error struct {
	Code   string
	Offset int
	Msg    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("jcs: %s at offset %d: %s", e.Code, e.Offset, e.Msg)
}

// Canonicalize returns the RFC 8785 encoding of raw, which must be a single
// valid I-JSON value.
func Canonicalize(raw []byte) ([]byte, error) {
	return canonicalize(raw, false)
}

// CanonicalizeRecord is Canonicalize with the record profile: null is
// rejected and every number must be an integer literal (no fraction, no
// exponent, no "-0") within ±(2^53-1).
func CanonicalizeRecord(raw []byte) ([]byte, error) {
	return canonicalize(raw, true)
}

// Marshal encodes v with encoding/json and canonicalizes the result.
func Marshal(v any) ([]byte, error) {
	if err := checkValueStrings(reflect.ValueOf(v), map[uintptr]bool{}, 0); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonicalize(raw)
}

// MarshalRecord encodes v with encoding/json and canonicalizes the result
// under the record profile.
func MarshalRecord(v any) ([]byte, error) {
	if err := checkValueStrings(reflect.ValueOf(v), map[uintptr]bool{}, 0); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return CanonicalizeRecord(raw)
}

// checkValueStrings prevents encoding/json from silently repairing invalid UTF-8.
func checkValueStrings(v reflect.Value, seen map[uintptr]bool, depth int) error {
	if !v.IsValid() {
		return nil
	}
	if depth > MaxDepth {
		return &Error{Code: CodeDepth, Msg: "typed value too deep"}
	}
	switch v.Kind() {
	case reflect.String:
		return checkString(v.String())
	case reflect.Interface:
		if !v.IsNil() {
			return checkValueStrings(v.Elem(), seen, depth+1)
		}
	case reflect.Pointer:
		if !v.IsNil() {
			p := v.Pointer()
			if seen[p] {
				return nil
			}
			seen[p] = true
			defer delete(seen, p)
			return checkValueStrings(v.Elem(), seen, depth+1)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath == "" {
				if err := checkValueStrings(v.Field(i), seen, depth+1); err != nil {
					return err
				}
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := checkValueStrings(v.Index(i), seen, depth+1); err != nil {
				return err
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if err := checkValueStrings(iter.Key(), seen, depth+1); err != nil {
				return err
			}
			if err := checkValueStrings(iter.Value(), seen, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// IsCanonicalRecord reports whether raw passes the record gate and is
// already byte-identical to its canonical form.
func IsCanonicalRecord(raw []byte) bool {
	c, err := CanonicalizeRecord(raw)
	return err == nil && bytes.Equal(c, raw)
}

// StringArray returns the canonical encoding of a JSON array of strings.
// Every string must be valid UTF-8 without noncharacters.
func StringArray(parts ...string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, p := range parts {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := checkString(p); err != nil {
			return nil, err
		}
		writeString(&buf, p)
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}

func checkString(s string) error {
	for i, r := range s {
		if r == utf8.RuneError {
			if _, size := utf8.DecodeRuneInString(s[i:]); size <= 1 {
				return &Error{CodeInvalidUTF8, i, "invalid UTF-8 in string"}
			}
		}
		if isNoncharacter(r) {
			return &Error{CodeNoncharacter, i, fmt.Sprintf("noncharacter U+%04X", r)}
		}
	}
	return nil
}

// value kinds of the parsed tree
type kind int

const (
	kNull kind = iota
	kBool
	kNumber
	kString
	kArray
	kObject
)

type member struct {
	key string
	val *node
}

type node struct {
	k    kind
	b    bool
	num  float64
	str  string
	arr  []*node
	obj  []member
	off  int
	text string // number literal as written
}

type parser struct {
	in     []byte
	pos    int
	record bool
}

func canonicalize(raw []byte, record bool) ([]byte, error) {
	if !utf8.Valid(raw) {
		// Locate the first invalid byte for the error offset.
		off := 0
		for off < len(raw) {
			r, size := utf8.DecodeRune(raw[off:])
			if r == utf8.RuneError && size <= 1 {
				break
			}
			off += size
		}
		return nil, &Error{CodeInvalidUTF8, off, "input is not valid UTF-8"}
	}
	p := &parser{in: raw, record: record}
	p.skipWS()
	_, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.in) {
		return nil, &Error{CodeTrailingData, p.pos, "data after the JSON value"}
	}
	return tapcanon.CanonicalJSON(raw)
}

func (p *parser) errf(code string, format string, a ...any) error {
	return &Error{Code: code, Offset: p.pos, Msg: fmt.Sprintf(format, a...)}
}

func (p *parser) skipWS() {
	for p.pos < len(p.in) {
		switch p.in[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (*node, error) {
	if p.pos >= len(p.in) {
		return nil, p.errf(CodeSyntax, "unexpected end of input")
	}
	switch c := p.in[p.pos]; {
	case c == '{':
		return p.object(depth + 1)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		off := p.pos
		s, err := p.string()
		if err != nil {
			return nil, err
		}
		return &node{k: kString, str: s, off: off}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case c == 't':
		return p.literal("true", &node{k: kBool, b: true})
	case c == 'f':
		return p.literal("false", &node{k: kBool, b: false})
	case c == 'n':
		if p.record {
			return nil, p.errf(CodeNullNotAllowed, "null is not allowed in a record")
		}
		return p.literal("null", &node{k: kNull})
	default:
		return nil, p.errf(CodeSyntax, "unexpected character %q", c)
	}
}

func (p *parser) literal(word string, n *node) (*node, error) {
	if !bytes.HasPrefix(p.in[p.pos:], []byte(word)) {
		return nil, p.errf(CodeSyntax, "invalid literal")
	}
	n.off = p.pos
	p.pos += len(word)
	return n, nil
}

func (p *parser) object(depth int) (*node, error) {
	if depth > MaxDepth {
		return nil, p.errf(CodeDepth, "nesting deeper than %d", MaxDepth)
	}
	n := &node{k: kObject, off: p.pos}
	p.pos++ // {
	p.skipWS()
	if p.pos < len(p.in) && p.in[p.pos] == '}' {
		p.pos++
		return n, nil
	}
	seen := map[string]bool{}
	for {
		p.skipWS()
		if p.pos >= len(p.in) || p.in[p.pos] != '"' {
			return nil, p.errf(CodeSyntax, "expected object member name")
		}
		keyOff := p.pos
		key, err := p.string()
		if err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, &Error{CodeDuplicateKey, keyOff, fmt.Sprintf("duplicate member name %q", key)}
		}
		seen[key] = true
		p.skipWS()
		if p.pos >= len(p.in) || p.in[p.pos] != ':' {
			return nil, p.errf(CodeSyntax, "expected ':'")
		}
		p.pos++
		p.skipWS()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		n.obj = append(n.obj, member{key, v})
		p.skipWS()
		if p.pos >= len(p.in) {
			return nil, p.errf(CodeSyntax, "unterminated object")
		}
		switch p.in[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return n, nil
		default:
			return nil, p.errf(CodeSyntax, "expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (*node, error) {
	if depth > MaxDepth {
		return nil, p.errf(CodeDepth, "nesting deeper than %d", MaxDepth)
	}
	n := &node{k: kArray, off: p.pos}
	p.pos++ // [
	p.skipWS()
	if p.pos < len(p.in) && p.in[p.pos] == ']' {
		p.pos++
		return n, nil
	}
	for {
		p.skipWS()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		n.arr = append(n.arr, v)
		p.skipWS()
		if p.pos >= len(p.in) {
			return nil, p.errf(CodeSyntax, "unterminated array")
		}
		switch p.in[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return n, nil
		default:
			return nil, p.errf(CodeSyntax, "expected ',' or ']'")
		}
	}
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	return r, true
}

func isNoncharacter(r rune) bool {
	return (r >= 0xFDD0 && r <= 0xFDEF) || (r&0xFFFE == 0xFFFE && r <= 0x10FFFF)
}

// string parses a JSON string starting at the opening quote.
func (p *parser) string() (string, error) {
	p.pos++ // opening quote
	var sb strings.Builder
	for {
		if p.pos >= len(p.in) {
			return "", p.errf(CodeSyntax, "unterminated string")
		}
		c := p.in[p.pos]
		switch {
		case c == '"':
			p.pos++
			return sb.String(), nil
		case c == '\\':
			if p.pos+1 >= len(p.in) {
				return "", p.errf(CodeSyntax, "unterminated escape")
			}
			esc := p.in[p.pos+1]
			switch esc {
			case '"', '\\', '/':
				sb.WriteByte(esc)
				p.pos += 2
			case 'b':
				sb.WriteByte('\b')
				p.pos += 2
			case 'f':
				sb.WriteByte('\f')
				p.pos += 2
			case 'n':
				sb.WriteByte('\n')
				p.pos += 2
			case 'r':
				sb.WriteByte('\r')
				p.pos += 2
			case 't':
				sb.WriteByte('\t')
				p.pos += 2
			case 'u':
				r, ok := hex4(p.in[p.pos+2:])
				if !ok {
					return "", p.errf(CodeSyntax, "invalid \\u escape")
				}
				switch {
				case r >= 0xD800 && r <= 0xDBFF:
					// must be followed by an escaped low surrogate
					q := p.pos + 6
					if q+1 < len(p.in) && p.in[q] == '\\' && p.in[q+1] == 'u' {
						lo, ok := hex4(p.in[q+2:])
						if ok && lo >= 0xDC00 && lo <= 0xDFFF {
							full := utf16.DecodeRune(r, lo)
							if isNoncharacter(full) {
								return "", p.errf(CodeNoncharacter, "noncharacter U+%04X", full)
							}
							sb.WriteRune(full)
							p.pos = q + 6
							continue
						}
					}
					return "", p.errf(CodeLoneSurrogate, "high surrogate \\u%04X without a low surrogate", r)
				case r >= 0xDC00 && r <= 0xDFFF:
					return "", p.errf(CodeLoneSurrogate, "low surrogate \\u%04X without a high surrogate", r)
				}
				if isNoncharacter(r) {
					return "", p.errf(CodeNoncharacter, "noncharacter U+%04X", r)
				}
				sb.WriteRune(r)
				p.pos += 6
			default:
				return "", p.errf(CodeSyntax, "invalid escape \\%c", esc)
			}
		case c < 0x20:
			return "", p.errf(CodeSyntax, "unescaped control character 0x%02x", c)
		case c < utf8.RuneSelf:
			sb.WriteByte(c)
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.in[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", p.errf(CodeInvalidUTF8, "invalid UTF-8")
			}
			if isNoncharacter(r) {
				return "", p.errf(CodeNoncharacter, "noncharacter U+%04X", r)
			}
			sb.WriteRune(r)
			p.pos += size
		}
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (p *parser) number() (*node, error) {
	start := p.pos
	i := p.pos
	if i < len(p.in) && p.in[i] == '-' {
		i++
	}
	if i >= len(p.in) || !isDigit(p.in[i]) {
		return nil, p.errf(CodeSyntax, "invalid number")
	}
	if p.in[i] == '0' {
		i++
	} else {
		for i < len(p.in) && isDigit(p.in[i]) {
			i++
		}
	}
	integer := true
	if i < len(p.in) && p.in[i] == '.' {
		integer = false
		i++
		if i >= len(p.in) || !isDigit(p.in[i]) {
			p.pos = i
			return nil, p.errf(CodeSyntax, "invalid fraction")
		}
		for i < len(p.in) && isDigit(p.in[i]) {
			i++
		}
	}
	if i < len(p.in) && (p.in[i] == 'e' || p.in[i] == 'E') {
		integer = false
		i++
		if i < len(p.in) && (p.in[i] == '+' || p.in[i] == '-') {
			i++
		}
		if i >= len(p.in) || !isDigit(p.in[i]) {
			p.pos = i
			return nil, p.errf(CodeSyntax, "invalid exponent")
		}
		for i < len(p.in) && isDigit(p.in[i]) {
			i++
		}
	}
	text := string(p.in[start:i])
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, &Error{CodeNumberRange, start, fmt.Sprintf("number %s is not representable as an IEEE-754 double", text)}
	}
	if f == 0 && strings.ContainsAny(mantissa(text), "123456789") {
		// strconv rounds an underflowing literal to zero without an error.
		return nil, &Error{CodeNumberRange, start, fmt.Sprintf("number %s underflows an IEEE-754 double", text)}
	}
	if p.record {
		if !integer || text == "-0" {
			return nil, &Error{CodeNotInteger, start, fmt.Sprintf("number %s is not an integer literal", text)}
		}
		if math.Abs(f) > MaxSafeInteger {
			return nil, &Error{CodeNumberRange, start, fmt.Sprintf("integer %s exceeds 2^53-1", text)}
		}
	}
	p.pos = i
	return &node{k: kNumber, num: f, off: start, text: text}, nil
}

// mantissa returns the part of a number literal before any exponent.
func mantissa(text string) string {
	if i := strings.IndexAny(text, "eE"); i >= 0 {
		return text[:i]
	}
	return text
}

// writeString escapes as ECMAScript JSON.stringify does (RFC 8785 §3.2.2.2).
func writeString(buf *bytes.Buffer, s string) {
	const hexdig = "0123456789abcdef"
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexdig[r>>4])
				buf.WriteByte(hexdig[r&0xF])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// FormatNumber renders a finite double as ECMAScript Number::toString does
// (RFC 8785 §3.2.2.3). -0 renders as "0".
func FormatNumber(f float64) string {
	if f == 0 {
		return "0"
	}
	neg := f < 0
	if neg {
		f = -f
	}
	// Shortest round-trip decimal digits and exponent.
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.dddde±XX
	mant, expStr, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expStr)
	k := len(digits)
	n := exp + 1 // decimal point position relative to the digit string
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		x := n - 1
		sign := "+"
		if x < 0 {
			sign = "-"
			x = -x
		}
		if k == 1 {
			out = digits + "e" + sign + strconv.Itoa(x)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(x)
		}
	}
	if neg {
		return "-" + out
	}
	return out
}
