package capture

import (
	"bytes"
	"encoding/json"
)

func supportedClient(client string) bool {
	switch client {
	case "claude-code", "codex", "cursor-agent", "pi":
		return true
	}
	return false
}

// Cursor 2026.10.22's agent-transcript writer exports role/message.content,
// merging reasoning into text and omitting native call IDs and tool results.
// Preserve only what is present. In particular a tool_use is never proof of
// execution, and no invented call ID may become a native event anchor.
func decodeCursor(b []byte, line int) ([]preparedObservation, error) {
	m, err := obj(b)
	if err != nil {
		return nil, err
	}
	if _, ok := m["type"]; ok {
		typ, err := str(m, "type", true)
		if err != nil {
			return nil, err
		}
		switch typ {
		case "metadata":
			meta, err := obj(m["metadata"])
			if err != nil {
				return nil, err
			}
			return metadata(meta, []string{"overview"}, line)
		case "turn_ended":
			status, err := str(m, "status", true)
			if err != nil {
				return nil, err
			}
			if status != "success" && status != "error" && status != "aborted" {
				return nil, hold("native_shape")
			}
			return metadata(m, []string{"status", "error"}, line)
		default:
			return nil, hold("unsupported_native_record")
		}
	}
	role, err := str(m, "role", true)
	if err != nil {
		return nil, err
	}
	if role != "user" && role != "assistant" && role != "tool" {
		return nil, hold("unsupported_role")
	}
	message, err := obj(m["message"])
	if err != nil {
		return nil, err
	}
	parts, err := blocks(message["content"])
	if err != nil {
		return nil, err
	}
	var out []preparedObservation
	for i, part := range parts {
		typ, err := str(part, "type", true)
		if err != nil {
			return nil, err
		}
		o := preparedObservation{position: position{line, i, 0}}
		switch typ {
		case "text":
			o.kind = role + "_text"
			// Cursor's tool-role export carries no reliable call association.
			// Capture its prose as untrusted context, never a verified tool result.
			if role == "tool" {
				o.kind = "native_meta_text"
			}
			text, err := str(part, "text", true)
			if err != nil {
				return nil, err
			}
			o.fields = []field{{name: "text", text: text}}
		case "tool_use":
			if role != "assistant" {
				return nil, hold("native_shape")
			}
			name, err := token(part, "name", true)
			if err != nil {
				return nil, err
			}
			o.kind = "tool_call"
			o.fields, err = arguments(part["input"])
			if err != nil {
				return nil, err
			}
			o.fields = append(o.fields, field{name: "tool", text: name})
		default:
			return nil, hold("unsupported_content")
		}
		out = append(out, o)
	}
	return out, nil
}

// Pi 1.1.0 stores raw tree entries, not a linear active context. Capture each
// physical message with its parent metadata without inferring branch selection,
// execution success, or compaction provenance completeness.
func decodePi(b []byte, line int, session string) ([]preparedObservation, error) {
	m, err := obj(b)
	if err != nil {
		return nil, err
	}
	typ, err := str(m, "type", true)
	if err != nil {
		return nil, err
	}
	if line == 1 && typ != "session" {
		return nil, hold("native_shape")
	}
	if typ == "session" {
		id, err := token(m, "id", true)
		if err != nil {
			return nil, err
		}
		if id != session {
			return nil, hold("session_mismatch")
		}
		var version int
		if json.Unmarshal(m["version"], &version) != nil || version != 3 {
			return nil, hold("unsupported_native_record")
		}
		if line != 1 {
			return nil, hold("native_shape")
		}
		return metadata(m, []string{"cwd", "timestamp", "parentSession"}, line)
	}
	id, err := token(m, "id", true)
	if err != nil {
		return nil, err
	}
	parent := ""
	if !bytes.Equal(bytes.TrimSpace(m["parentId"]), []byte("null")) {
		parent, err = token(m, "parentId", true)
		if err != nil {
			return nil, err
		}
	}
	meta := preparedObservation{kind: "metadata", nativeID: id, position: position{line, -1, -1}, fields: []field{{name: "entry_type", text: typ}, {name: "parent_id", text: parent}}}
	out := []preparedObservation{meta}
	base := preparedObservation{nativeID: id, position: position{line, 0, 0}}
	switch typ {
	case "message":
		msg, err := obj(m["message"])
		if err != nil {
			return nil, err
		}
		role, err := str(msg, "role", true)
		if err != nil {
			return nil, err
		}
		extra, err := metadata(msg, []string{"model", "provider", "responseModel", "errorMessage", "stopReason"}, line)
		if err != nil {
			return nil, err
		}
		if len(extra) > 0 {
			out[0].fields = append(out[0].fields, extra[0].fields...)
		}
		switch role {
		case "system":
			base.kind = "native_meta_text"
			// Preserve the complete prompt checkpoint, including sections/tools, under
			// the same full-field redaction that protects all transcript content.
			base.fields = []field{{name: "text", text: string(m["message"])}}
			return append(out, base), nil
		case "user", "assistant":
			base.kind = role + "_text"
		case "custom":
			base.kind = "native_meta_text"
		case "toolResult":
			base.kind = "tool_result"
			base.callID, err = token(msg, "toolCallId", true)
			if err != nil {
				return nil, err
			}
			base.observedError, err = boolean(msg, "isError")
			if err != nil {
				return nil, err
			}
			texts, err := textualContent(msg["content"], base, "text")
			return append(out, texts...), err
		default:
			// Augmented Pi hosts may persist custom roles. Preserve them only
			// as unknown injected context, never user/assistant/tool evidence.
			out[0].fields = append(out[0].fields, field{name: "native_role", text: role})
			base.kind = "native_meta_text"
			base.fields = []field{{name: "text", text: string(m["message"])}}
			return append(out, base), nil
		}
		content := bytes.TrimSpace(msg["content"])
		if len(content) > 0 && content[0] == '"' {
			if role == "assistant" {
				return nil, hold("native_shape")
			}
			texts, err := textualContent(content, base, "text")
			return append(out, texts...), err
		}
		parts, err := blocks(content)
		if err != nil {
			return nil, err
		}
		for i, part := range parts {
			o := base
			o.position.block = i
			pt, err := str(part, "type", true)
			if err != nil {
				return nil, err
			}
			switch pt {
			case "text", "thinking":
				key := "text"
				if pt == "thinking" {
					if role != "assistant" {
						return nil, hold("native_shape")
					}
					key = "thinking"
					o.kind = "native_meta_text"
				}
				text := ""
				if pt == "thinking" {
					redacted, err := boolean(part, "redacted")
					if err != nil {
						return nil, err
					}
					if redacted {
						text = "[native reasoning redacted]"
					} else {
						text, err = str(part, key, true)
						if err != nil {
							return nil, err
						}
					}
				} else {
					text, err = str(part, key, true)
					if err != nil {
						return nil, err
					}
				}
				o.fields = []field{{name: "text", text: text}}
			case "toolCall":
				if role != "assistant" {
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
				o.fields, err = arguments(part["arguments"])
				if err != nil {
					return nil, err
				}
				o.fields = append(o.fields, field{name: "tool", text: name})
				if namespace, err := token(part, "namespace", false); err != nil {
					return nil, err
				} else if namespace != "" {
					o.fields = append(o.fields, field{name: "namespace", text: namespace})
				}
			default:
				return nil, hold("unsupported_content")
			}
			out = append(out, o)
		}
		return out, nil
	case "compaction", "branch_summary":
		text, err := str(m, "summary", true)
		if err != nil {
			return nil, err
		}
		base.kind = "native_meta_text"
		base.fields = []field{{name: "text", text: text}}
		out = append(out, base)
		if checkpoint, ok := m["systemMessage"]; ok {
			if _, err := obj(checkpoint); err != nil {
				return nil, err
			}
			o := base
			o.position.block = 1
			o.fields = []field{{name: "text", text: string(checkpoint)}}
			out = append(out, o)
		}
		return out, nil
	case "context_edit":
		target, err := token(m, "targetId", true)
		if err != nil {
			return nil, err
		}
		out[0].fields = append(out[0].fields, field{name: "target_id", text: target})
		replacement, ok := m["replacement"]
		if !ok {
			return nil, hold("native_shape")
		}
		if bytes.Equal(bytes.TrimSpace(replacement), []byte("null")) {
			return out, nil
		}
		base.kind = "native_meta_text"
		texts, err := textualContent(replacement, base, "text")
		return append(out, texts...), err
	case "custom_message":
		base.kind = "native_meta_text"
		texts, err := textualContent(m["content"], base, "text")
		return append(out, texts...), err
	case "session_info":
		extra, err := metadata(m, []string{"name"}, line)
		if err != nil {
			return nil, err
		}
		if len(extra) > 0 {
			out[0].fields = append(out[0].fields, extra[0].fields...)
		}
		return out, nil
	case "model_change", "thinking_level_change", "usage", "custom", "label":
		extra, err := metadata(m, []string{"provider", "modelId", "thinkingLevel", "kind", "label"}, line)
		if err != nil {
			return nil, err
		}
		if len(extra) > 0 {
			out[0].fields = append(out[0].fields, extra[0].fields...)
		}
		// These entries do not assert new source messages or a successful action.
		return out, nil
	default:
		return nil, hold("unsupported_native_record")
	}
}

// piTree validates the complete raw graph with bounded linear work. A missing
// parent is a reported gap, not a guessed root. A selected native leaf is not
// present in this export, so every branch remains explicitly unknown.
type piTree struct{ parents map[string]string }

func (t *piTree) add(b []byte, line int) error {
	m, err := obj(b)
	if err != nil {
		return err
	}
	typ, err := str(m, "type", true)
	if err != nil {
		return err
	}
	if line == 1 {
		if typ != "session" {
			return hold("native_shape")
		}
		t.parents = map[string]string{}
		return nil
	}
	if typ == "session" || t.parents == nil {
		return hold("native_shape")
	}
	id, err := token(m, "id", true)
	if err != nil {
		return err
	}
	if _, dup := t.parents[id]; dup {
		return hold("duplicate_native_entry")
	}
	if len(t.parents) >= maxObservations {
		return hold("observation_limit")
	}
	parent := ""
	if !bytes.Equal(bytes.TrimSpace(m["parentId"]), []byte("null")) {
		parent, err = token(m, "parentId", true)
		if err != nil {
			return err
		}
	}
	t.parents[id] = parent
	return nil
}
func (t *piTree) finish(batch *preparedBatch) error {
	if t.parents == nil {
		return hold("native_shape")
	}
	state := map[string]uint8{}
	missing := map[string]bool{}
	for id := range t.parents {
		if state[id] == 2 {
			continue
		}
		path := []string{}
		at := id
		gap := false
		for at != "" {
			parent, ok := t.parents[at]
			if !ok {
				gap = true
				break
			}
			if state[at] == 1 {
				return hold("cyclic_native_entries")
			}
			if state[at] == 2 {
				gap = missing[at]
				break
			}
			state[at] = 1
			path = append(path, at)
			at = parent
		}
		for _, entry := range path {
			state[entry] = 2
			missing[entry] = gap
		}
	}
	for i := range batch.observations {
		o := &batch.observations[i]
		if o.kind != "metadata" || o.nativeID == "" {
			continue
		}
		parentState := "complete"
		if missing[o.nativeID] {
			parentState = "incomplete"
		}
		o.fields = append(o.fields, field{name: "branch_state", text: "unknown"}, field{name: "parent_chain", text: parentState})
	}
	return nil
}
