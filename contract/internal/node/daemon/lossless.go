package daemon

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/Telara-Labs/hilo/contract/jcs"
)

// validateEnvelope checks duplicate names, bounded depth and strict Unicode
// without ever decoding a transport number as float64 or rewriting correlation.
func validateEnvelope(raw []byte) bool {
	if !json.Valid(raw) {
		return false
	}
	// Check original string spellings before encoding/json can repair surrogates.
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		start := i
		for i++; i < len(raw); i++ {
			if raw[i] == '\\' {
				i++
				continue
			}
			if raw[i] == '"' {
				break
			}
		}
		if _, e := jcs.Canonicalize(raw[start : i+1]); e != nil {
			return false
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		token, e := decoder.Token()
		if e != nil {
			return false
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return true
		}
		if depth >= jcs.MaxDepth {
			return false
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, e := decoder.Token()
				if e != nil {
					return false
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, e := decoder.Token()
			return e == nil && end == json.Delim('}')
		case '[':
			for decoder.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, e := decoder.Token()
			return e == nil && end == json.Delim(']')
		}
		return false
	}
	if !value(0) {
		return false
	}
	_, e := decoder.Token()
	return e == io.EOF
}

// ValidRPCID accepts opaque JSON strings and exact JSON numbers only.
func ValidRPCID(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || !json.Valid(raw) {
		return false
	}
	if raw[0] == '"' {
		_, e := jcs.Canonicalize(raw)
		return e == nil
	}
	if raw[0] != '-' && (raw[0] < '0' || raw[0] > '9') {
		return false
	}
	var n json.Number
	return json.Unmarshal(raw, &n) == nil
}
