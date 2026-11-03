package capture

import (
	"sort"

	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
)

const runtimeReaderVersion = "native-jsonl-runtime.4"

func observationKind(s string) (string, error) {
	switch s {
	case "user_text":
		return "user_prompt", nil
	case "native_meta_text":
		return "injected_context", nil
	case "metadata":
		return "session_meta", nil
	case "assistant_text", "tool_call", "tool_result":
		return s, nil
	}
	return "", hold("unsupported_observation")
}

// The preparation inner ordinal names a text-content part, not an exec call.
// Nested execution is unsupported, so the wire Anchor.Inner is always zero.
func sourceAnchor(o preparedObservation, path string) (record.Anchor, string, error) {
	return sourceAnchorForClient(o, path, "")
}
func sourceAnchorForClient(o preparedObservation, path, client string) (record.Anchor, string, error) {
	var empty record.Anchor
	if o.position.line < 1 || o.position.block < -1 || o.position.block > 4095 {
		return empty, "", hold("source_position")
	}
	block := int64(o.position.block + 1)
	part := int64(o.position.inner)
	if o.kind == "metadata" && o.position.block == -1 && o.position.inner == -1 {
		part = 0
	} else if o.position.block < 0 || part < 0 {
		return empty, "", hold("source_position")
	}
	if part > 4095 {
		return empty, "", hold("source_position")
	}
	native := o.nativeID
	// A call ID correlates results with their invocation. It does not identify
	// a result item: Codex can emit both response output and an MCP end record
	// for the same call. Preserve each result's native item or source position.
	if o.kind == "tool_call" && o.callID != "" {
		native = o.callID
	}
	if native != "" {
		if !identifier(native) && !(client == "pi" && o.kind == "tool_call" && native == o.callID && piCallIdentifier(native)) {
			return empty, "", hold("unsafe_native_id")
		}
		return record.Anchor{NativeItemID: native, Inner: 0, Part: block*4096 + part}, native, nil
	}
	if path == "" {
		return empty, "", hold("source_position")
	}
	return record.Anchor{Path: path, Line: int64(o.position.line), Block: block, Inner: 0, Part: part}, "", nil
}

func normalize(batch preparedBatch, rs record.Ruleset) ([]record.Event, error) {
	if len(batch.observations) == 0 {
		return nil, hold("no_observations")
	}
	out := make([]record.Event, 0, len(batch.observations))
	seen := map[string]bool{}
	nativeLines := map[[2]string]int{}
	calls := map[string]string{}
	for seq, o := range batch.observations {
		kind, err := observationKind(o.kind)
		if err != nil {
			return nil, err
		}
		anchor, native, err := sourceAnchorForClient(o, batch.homeRelativeUnit, batch.client)
		if err != nil {
			return nil, err
		}
		if native != "" {
			key := [2]string{kind, native}
			if line, ok := nativeLines[key]; ok && line != o.position.line {
				return nil, hold("ambiguous_native_occurrence")
			}
			nativeLines[key] = o.position.line
		}
		id, err := record.EventID(batch.occurrence.session, kind, anchor)
		if err != nil {
			return nil, hold("source_position")
		}
		if seen[id] {
			return nil, hold("duplicate_event")
		}
		seen[id] = true
		e := record.Event{ID: id, Seq: int64(seq), Kind: kind, Prov: string(record.ProvTranscript), Ruleset: rs.Epoch, Src: &record.SourcePos{Path: batch.homeRelativeUnit, Line: int64(o.position.line), Record: native}}
		switch kind {
		case "user_prompt", "injected_context", "assistant_text":
			if len(o.fields) != 1 || o.fields[0].name != "text" {
				return nil, hold("observation_shape")
			}
			f := o.fields[0]
			e.Text = &record.Text{Body: f.text, Bytes: f.fullRedactedBytes, Truncated: f.truncated}
		case "session_meta":
			e.Meta = map[string]string{}
			for _, f := range o.fields {
				if f.argument {
					return nil, hold("observation_shape")
				}
				e.Meta[f.name] = f.text
			}
		case "tool_call":
			if o.callID == "" && batch.client != "cursor-agent" {
				return nil, hold("observation_shape")
			}
			if _, ok := calls[o.callID]; ok && o.callID != "" {
				return nil, hold("ambiguous_tool_call")
			}
			if o.callID != "" {
				calls[o.callID] = id
			}
			e.Call = &record.ToolCall{Args: map[string]string{}}
			types := [][2]string{}
			for _, f := range o.fields {
				if f.argument {
					switch f.nativeKind {
					case "string", "number", "bool", "null", "object", "array":
					default:
						return nil, hold("argument_type")
					}
					e.Call.Args[f.name] = f.text
					types = append(types, [2]string{f.name, f.nativeKind})
					continue
				}
				switch f.name {
				case "tool":
					e.Call.Tool = f.text
				case "namespace":
					if e.Meta == nil {
						e.Meta = map[string]string{}
					}
					e.Meta["native_namespace"] = f.text
				default:
					return nil, hold("observation_shape")
				}
			}
			sort.Slice(types, func(i, j int) bool { return types[i][0] < types[j][0] })
			raw, err := jcs.MarshalRecord(types)
			if err != nil {
				return nil, hold("argument_type")
			}
			full := localPolicy{}.text(string(raw))
			if full != string(raw) || len(full) > maxText {
				return nil, hold("argument_type_metadata")
			}
			if e.Meta == nil {
				e.Meta = map[string]string{}
			}
			e.Meta["capture_arg_types_v1"] = full
		case "tool_result":
			if len(o.fields) != 1 || o.fields[0].name != "text" {
				return nil, hold("observation_shape")
			}
			f := o.fields[0]
			e.Result = &record.ToolResult{Outcome: "unknown", Excerpt: f.text, Bytes: f.fullRedactedBytes}
			if o.observedError || f.truncated {
				e.Meta = map[string]string{}
			}
			if o.observedError {
				e.Meta["native_error_reported"] = "true"
			}
			if f.truncated {
				e.Meta["excerpt_truncated"] = "true"
			}
		}
		out = append(out, e)
	}
	for i, o := range batch.observations {
		if out[i].Result != nil {
			out[i].Result.CallEventID = calls[o.callID]
		}
	}
	return out, nil
}
