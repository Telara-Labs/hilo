package store

import (
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/view"
)

// Measure the fixed Event DTO's encoding before any helper allocates its JSON.
// This follows encoding/json's HTML-escaped string spelling; canonical JCS
// removes those escapes and never increases this conservative byte bound. No
// event bytes, comparison hash or salt are copied into retained planning state.
func (c *reductionContext) eventEncodingSize(e record.Event) (int, error) {
	var size func(reflect.Value, int) (int, error)
	stringSize := func(s string) int {
		n := 2
		for len(s) > 0 {
			r, w := utf8.DecodeRuneInString(s)
			switch {
			case r == utf8.RuneError && w == 1:
				n += 6
			case r == '"' || r == '\\':
				n += 2
			case r == '\n' || r == '\r' || r == '\t' || r == '\b' || r == '\f':
				n += 2
			case r < 32 || r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029':
				n += 6
			default:
				n += w
			}
			s = s[w:]
		}
		return n
	}
	empty := func(v reflect.Value) bool {
		switch v.Kind() {
		case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
			return v.Len() == 0
		default:
			return v.IsZero()
		}
	}
	size = func(v reflect.Value, depth int) (int, error) {
		if depth > 16 {
			return 0, failure("invalid_causal_state")
		}
		if err := c.charge(1); err != nil {
			return 0, err
		}
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return 4, nil
			}
			return size(v.Elem(), depth+1)
		}
		n := 0
		switch v.Kind() {
		case reflect.String:
			n = stringSize(v.String())
		case reflect.Bool:
			if v.Bool() {
				n = 4
			} else {
				n = 5
			}
		case reflect.Int, reflect.Int64, reflect.Int32:
			n = len(strconv.FormatInt(v.Int(), 10))
		case reflect.Slice, reflect.Array:
			if v.Kind() == reflect.Slice && v.IsNil() {
				return 4, nil
			}
			n = 2
			for i := 0; i < v.Len(); i++ {
				m, err := size(v.Index(i), depth+1)
				if err != nil {
					return 0, err
				}
				n += m
				if i > 0 {
					n++
				}
				if n > 64<<20 {
					return 0, &projectionLimit{}
				}
			}
		case reflect.Map:
			if v.IsNil() {
				return 4, nil
			}
			n = 2
			iter := v.MapRange()
			i := 0
			for iter.Next() {
				m, err := size(iter.Value(), depth+1)
				if err != nil {
					return 0, err
				}
				n += stringSize(iter.Key().String()) + 1 + m
				if i > 0 {
					n++
				}
				i++
				if n > 64<<20 {
					return 0, &projectionLimit{}
				}
			}
		case reflect.Struct:
			n = 2
			i := 0
			t := v.Type()
			for j := 0; j < v.NumField(); j++ {
				field := t.Field(j)
				tag := field.Tag.Get("json")
				parts := strings.Split(tag, ",")
				name := parts[0]
				if name == "-" {
					continue
				}
				if name == "" {
					name = field.Name
				}
				if len(parts) > 1 && parts[1] == "omitempty" && empty(v.Field(j)) {
					continue
				}
				m, err := size(v.Field(j), depth+1)
				if err != nil {
					return 0, err
				}
				n += stringSize(name) + 1 + m
				if i > 0 {
					n++
				}
				i++
				if n > 64<<20 {
					return 0, &projectionLimit{}
				}
			}
		default:
			return 0, failure("invalid_causal_state")
		}
		if n > 64<<20 {
			return 0, &projectionLimit{}
		}
		return n, nil
	}
	return size(reflect.ValueOf(e), 0)
}

// EventRevision encodes the event, filtered map and canonical output, then
// encodes that canonical JSON again as a quoted field in its hash envelope.
// The envelope can double escapes and adds fixed domain/ID syntax. One extra
// event-size allowance also conservatively covers the measurement scan.
func (c *reductionContext) reserveRevisionEncoding(e record.Event, n int) error {
	if err := c.encode(n, 6); err != nil {
		return err
	}
	return c.encode(2*len(e.ID)+64, 1)
}

// EventPayload encodes the complete event, filtered field map and canonical
// output. The outer slot also reserves a possible final-head payload call.
func (c *reductionContext) reservePayloadEncoding(n, calls int) error {
	if calls < 0 || calls > 2 {
		return &projectionLimit{}
	}
	return c.encode(n, 3*calls)
}

// witnessKey hashes one canonical array with two fixed domain strings and
// seven identifiers. Valid identifiers are ASCII without escaping, so this
// measures the complete StringArray envelope without allocating its bytes.
func (c *reductionContext) reserveWitnessEncoding(w view.EqualityWitness) error {
	if !record.IsKeyID(w.Owner) || !record.IsSessionKey(w.SessionKey) || !record.IsEventID(w.EventID) || !record.IsHex64(w.A) || !record.IsHex64(w.B) || !record.IsHex64(w.RecordA) || !record.IsHex64(w.RecordB) {
		return failure("invalid_causal_state")
	}
	const framing = 2 + 2*9 + 8 + len("mnc1") + len("event-equality")
	n := framing + len(w.Owner) + len(w.SessionKey) + len(w.EventID) + len(w.A) + len(w.B) + len(w.RecordA) + len(w.RecordB)
	return c.encode(n, 1)
}
