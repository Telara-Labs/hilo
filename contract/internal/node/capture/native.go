package capture

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

type object map[string]json.RawMessage

func obj(b []byte) (object, error) {
	var out object
	if len(bytes.TrimSpace(b)) == 0 || bytes.TrimSpace(b)[0] != '{' || json.Unmarshal(b, &out) != nil || out == nil {
		return nil, hold("native_shape")
	}
	return out, nil
}
func str(m object, key string, required bool) (string, error) {
	b, ok := m[key]
	if !ok {
		if required {
			return "", hold("native_shape")
		}
		return "", nil
	}
	var out string
	if json.Unmarshal(b, &out) != nil || bytes.Equal(b, []byte("null")) {
		return "", hold("native_shape")
	}
	return out, nil
}
func token(m object, key string, required bool) (string, error) {
	s, err := str(m, key, required)
	if err != nil {
		return "", err
	}
	if (required || s != "") && !identifier(s) {
		return "", hold("unsafe_native_id")
	}
	return s, nil
}
func boolean(m object, key string) (bool, error) {
	b, ok := m[key]
	if !ok {
		return false, nil
	}
	if bytes.Equal(b, []byte("true")) {
		return true, nil
	}
	if bytes.Equal(b, []byte("false")) {
		return false, nil
	}
	return false, hold("native_shape")
}
func blocks(b []byte) ([]object, error) {
	trim := bytes.TrimSpace(b)
	if len(trim) == 0 || trim[0] != '[' {
		return nil, hold("native_shape")
	}
	var raw []json.RawMessage
	if json.Unmarshal(b, &raw) != nil || len(raw) > maxObservations {
		return nil, hold("native_shape")
	}
	out := make([]object, 0, len(raw))
	for _, part := range raw {
		m, err := obj(part)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func metadata(m object, names []string, line int) ([]preparedObservation, error) {
	o := preparedObservation{kind: "metadata", position: position{line, -1, -1}}
	for _, name := range names {
		if _, ok := m[name]; ok {
			s, err := str(m, name, false)
			if err != nil {
				return nil, err
			}
			o.fields = append(o.fields, field{name: name, text: s})
		}
	}
	if len(o.fields) == 0 {
		return nil, nil
	}
	return []preparedObservation{o}, nil
}

func arguments(b []byte) ([]field, error) {
	// Codex arguments may be a JSON-encoded string. Decode the entire string,
	// validate its JSON independently, and never use the 32-KiB Flatten helper.
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if json.Unmarshal(b, &s) != nil {
			return nil, hold("native_shape")
		}
		b = []byte(s)
	}
	if err := strictJSON(b); err != nil {
		return nil, err
	}
	m, err := obj(b)
	if err != nil {
		return nil, err
	}
	if len(m) > maxArgs-2 {
		return nil, hold("field_limit")
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]field, 0, len(m))
	for _, k := range keys {
		// Keep structured types and complete nested objects. Argument performs
		// named semantic redaction on this full value before any byte bound.
		value := string(m[k])
		if len(m[k]) > 0 && m[k][0] == '"' {
			if json.Unmarshal(m[k], &value) != nil {
				return nil, hold("native_shape")
			}
		}
		out = append(out, field{name: k, text: value, argument: true})
	}
	return out, nil
}

// textualContent emits one observation per native text block. It deliberately
// does not join blocks, infer completion, or assert a result's execution truth.
func textualContent(raw []byte, base preparedObservation, allowed string) ([]preparedObservation, error) {
	b := bytes.TrimSpace(raw)
	if len(b) == 0 {
		return nil, hold("native_shape")
	}
	if b[0] == '"' {
		var s string
		if json.Unmarshal(b, &s) != nil {
			return nil, hold("native_shape")
		}
		base.fields = append(base.fields, field{name: "text", text: s})
		return []preparedObservation{base}, nil
	}
	parts, err := blocks(b)
	if err != nil {
		return nil, err
	}
	out := make([]preparedObservation, 0, len(parts))
	for i, m := range parts {
		t, err := str(m, "type", true)
		if err != nil {
			return nil, err
		}
		if t != allowed {
			return nil, hold("unsupported_content")
		}
		s, err := str(m, "text", true)
		if err != nil {
			return nil, err
		}
		o := base
		o.fields = append([]field(nil), base.fields...)
		o.position.inner = i
		o.fields = append(o.fields, field{name: "text", text: s})
		out = append(out, o)
	}
	if len(parts) == 0 {
		base.fields = append(base.fields, field{name: "text", text: ""})
		out = append(out, base)
	}
	return out, nil
}

func decodeClaude(b []byte, line int, nativeSession string) ([]preparedObservation, error) {
	m, err := obj(b)
	if err != nil {
		return nil, err
	}
	t, err := str(m, "type", true)
	if err != nil {
		return nil, err
	}
	if t != "user" && t != "assistant" {
		return nil, hold("unsupported_native_record")
	}
	if session, err := token(m, "sessionId", false); err != nil {
		return nil, err
	} else if session != "" && session != nativeSession {
		return nil, hold("session_mismatch")
	}
	meta, err := boolean(m, "isMeta")
	if err != nil {
		return nil, err
	}
	message, err := obj(m["message"])
	if err != nil {
		return nil, err
	}
	if role, err := str(message, "role", false); err != nil {
		return nil, err
	} else if role != "" && role != t {
		return nil, hold("native_shape")
	}
	id, err := token(message, "id", false)
	if err != nil {
		return nil, err
	}
	out, err := metadata(m, []string{"cwd", "gitBranch", "version", "timestamp"}, line)
	if err != nil {
		return nil, err
	}
	if model, ok := message["model"]; ok {
		mm := object{"model": model}
		extra, err := metadata(mm, []string{"model"}, line)
		if err != nil {
			return nil, err
		}
		if len(out) > 0 {
			out[0].fields = append(out[0].fields, extra[0].fields...)
		} else {
			out = append(out, extra...)
		}
	}
	content := bytes.TrimSpace(message["content"])
	if t == "user" && len(content) > 0 && content[0] == '"' {
		kind := "user_text"
		if meta {
			kind = "native_meta_text"
		}
		texts, err := textualContent(content, preparedObservation{kind: kind, nativeID: id, position: position{line, 0, 0}}, "text")
		return append(out, texts...), err
	}
	parts, err := blocks(content)
	if err != nil {
		return nil, err
	}
	for i, part := range parts {
		bt, err := str(part, "type", true)
		if err != nil {
			return nil, err
		}
		o := preparedObservation{nativeID: id, position: position{line, i, 0}}
		switch bt {
		case "text":
			o.kind = t + "_text"
			if meta {
				o.kind = "native_meta_text"
			}
			s, err := str(part, "text", true)
			if err != nil {
				return nil, err
			}
			o.fields = []field{{name: "text", text: s}}
			out = append(out, o)
		case "tool_use":
			if t != "assistant" {
				return nil, hold("native_shape")
			}
			o.kind = "tool_call"
			o.callID, err = token(part, "id", true)
			if err != nil {
				return nil, err
			}
			name, err := token(part, "name", true)
			if err != nil {
				return nil, err
			}
			o.fields, err = arguments(part["input"])
			if err != nil {
				return nil, err
			}
			o.fields = append(o.fields, field{name: "tool", text: name})
			out = append(out, o)
		case "tool_result":
			if t != "user" {
				return nil, hold("native_shape")
			}
			o.kind = "tool_result"
			o.callID, err = token(part, "tool_use_id", true)
			if err != nil {
				return nil, err
			}
			o.observedError, err = boolean(part, "is_error")
			if err != nil {
				return nil, err
			}
			texts, err := textualContent(part["content"], o, "text")
			if err != nil {
				return nil, err
			}
			out = append(out, texts...)
		default:
			return nil, hold("unsupported_content")
		}
	}
	return out, nil
}

func decodeCodex(b []byte, line int, nativeSession string) ([]preparedObservation, error) {
	m, err := obj(b)
	if err != nil {
		return nil, err
	}
	outer, err := str(m, "type", true)
	if err != nil {
		return nil, err
	}
	p, err := obj(m["payload"])
	if err != nil {
		return nil, err
	}
	base := preparedObservation{position: position{line, 0, 0}}
	if outer == "session_meta" || outer == "turn_context" {
		if outer == "session_meta" {
			id, err := token(p, "id", true)
			if err != nil {
				return nil, err
			}
			if id != nativeSession {
				return nil, hold("session_mismatch")
			}
		}
		out, err := metadata(p, []string{"cwd", "cli_version", "model"}, line)
		if err != nil {
			return nil, err
		}
		if git, ok := p["git"]; ok {
			g, err := obj(git)
			if err != nil {
				return nil, err
			}
			more, err := metadata(g, []string{"branch"}, line)
			if err != nil {
				return nil, err
			}
			if len(more) > 0 {
				if len(out) > 0 {
					out[0].fields = append(out[0].fields, more[0].fields...)
				} else {
					out = more
				}
			}
		}
		return out, nil
	}
	if outer != "response_item" && outer != "event_msg" {
		return nil, hold("unsupported_native_record")
	}
	t, err := str(p, "type", true)
	if err != nil {
		return nil, err
	}
	base.nativeID, err = token(p, "id", false)
	if err != nil {
		return nil, err
	}
	switch t {
	case "message":
		if outer != "response_item" {
			return nil, hold("native_shape")
		}
		role, err := str(p, "role", true)
		if err != nil {
			return nil, err
		}
		allowed := "input_text"
		if role == "assistant" {
			allowed = "output_text"
		} else if role != "user" {
			return nil, hold("unsupported_role")
		}
		parts, err := blocks(p["content"])
		if err != nil {
			return nil, err
		}
		var out []preparedObservation
		for i, part := range parts {
			kind, err := str(part, "type", true)
			if err != nil {
				return nil, err
			}
			if kind != allowed {
				return nil, hold("unsupported_content")
			}
			text, err := str(part, "text", true)
			if err != nil {
				return nil, err
			}
			o := base
			o.kind = role + "_text"
			o.position.block = i
			o.fields = []field{{name: "text", text: text}}
			out = append(out, o)
		}
		return out, nil
	case "function_call":
		base.kind = "tool_call"
		base.callID, err = token(p, "call_id", true)
		if err != nil {
			return nil, err
		}
		name, err := token(p, "name", true)
		if err != nil {
			return nil, err
		}
		// Code-mode exec has nested effects/opaque expressions; no inferred
		// JS tool extraction or nested result attribution in initial scope.
		if name == "exec" || strings.HasSuffix(name, ".exec") || strings.HasSuffix(name, "__exec") {
			return nil, hold("unsupported_nested_exec")
		}
		base.fields, err = arguments(p["arguments"])
		if err != nil {
			return nil, err
		}
		base.fields = append(base.fields, field{name: "tool", text: name})
		if ns, err := token(p, "namespace", false); err != nil {
			return nil, err
		} else if ns != "" {
			base.fields = append(base.fields, field{name: "namespace", text: ns})
		}
		return []preparedObservation{base}, nil
	case "local_shell_call":
		base.kind = "tool_call"
		base.callID, err = token(p, "call_id", false)
		if err != nil {
			return nil, err
		}
		if base.callID == "" {
			base.callID = base.nativeID
		}
		if base.callID == "" {
			return nil, hold("native_shape")
		}
		a, err := obj(p["action"])
		if err != nil {
			return nil, err
		}
		var argv []string
		if json.Unmarshal(a["command"], &argv) != nil || len(argv) == 0 || len(argv) > maxArgs {
			return nil, hold("native_shape")
		}
		// Preserve argv boundaries as full structured JSON, not a joined shell
		// command. Semantic argument redaction runs before display bounds.
		base.fields = []field{{name: "command", text: string(a["command"]), argument: true}, {name: "tool", text: "local_shell"}}
		return []preparedObservation{base}, nil
	case "function_call_output":
		base.kind = "tool_result"
		base.callID, err = token(p, "call_id", true)
		if err != nil {
			return nil, err
		}
		return textualContent(p["output"], base, "text")
	case "mcp_tool_call_end":
		base.kind = "tool_result"
		base.callID, err = token(p, "call_id", true)
		if err != nil {
			return nil, err
		}
		result, err := obj(p["result"])
		if err != nil {
			return nil, err
		}
		if e, ok := result["Err"]; ok {
			if len(result) != 1 {
				return nil, hold("native_shape")
			}
			base.observedError = true
			return textualContent(e, base, "text")
		}
		ok, err := obj(result["Ok"])
		if err != nil || len(result) != 1 {
			return nil, hold("native_shape")
		}
		base.observedError, err = boolean(ok, "isError")
		if err != nil {
			return nil, err
		}
		return textualContent(ok["content"], base, "text")
	default:
		return nil, hold("unsupported_native_record")
	}
}
