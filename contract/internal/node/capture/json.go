package capture

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

func strictJSON(b []byte) error {
	if !utf8.Valid(b) || !validSurrogates(b) {
		return hold("invalid_json")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return hold("json_depth")
		}
		t, err := d.Token()
		if err != nil {
			return hold("invalid_json")
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return hold("invalid_json")
					}
					s, ok := key.(string)
					if !ok || seen[s] {
						return hold("invalid_json")
					}
					seen[s] = true
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return hold("invalid_json")
				}
			case '[':
				for d.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return hold("invalid_json")
				}
			default:
				return hold("invalid_json")
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return hold("invalid_json")
	}
	return nil
}

// encoding/json substitutes U+FFFD for unpaired UTF-16 escapes. Reject those
// rather than silently changing native text or collapsing native identities.
func validSurrogates(b []byte) bool {
	in := false
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			in = !in
			continue
		}
		if !in || b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		x, ok := hex4(b, i+1)
		if !ok {
			return false
		}
		i += 4
		if x >= 0xdc00 && x <= 0xdfff {
			return false
		}
		if x >= 0xd800 && x <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return false
			}
			y, ok := hex4(b, i+3)
			if !ok || y < 0xdc00 || y > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
func hex4(b []byte, start int) (int, bool) {
	if start+4 > len(b) {
		return 0, false
	}
	n := 0
	for _, c := range b[start : start+4] {
		n *= 16
		switch {
		case c >= '0' && c <= '9':
			n += int(c - '0')
		case c >= 'a' && c <= 'f':
			n += int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n += int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return n, true
}
