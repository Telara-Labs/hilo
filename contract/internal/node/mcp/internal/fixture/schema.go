// Package mcp implements the local memory tool surface. Storage and installed
// credential authority are injected; transport hints never confer a grant.
package fixture

import (
	"encoding/json"
	"errors"
	"math"
	"strings"

	"github.com/Telara-Labs/hilo/contract/internal/node/mcpcatalog"
	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
)

var errArguments = errors.New("invalid_arguments")
var errFilter = errors.New("unsupported_filter")

// Tool is the detached public catalog entry shared with offline setup.
type Tool = mcpcatalog.Tool

func Tools() []Tool { return mcpcatalog.Tools() }

func arguments(name string, raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if len(raw) > 1<<20 {
		return nil, errArguments
	}
	canonical, err := jcs.Canonicalize(raw)
	if err != nil {
		return nil, errArguments
	}
	var a map[string]any
	if json.Unmarshal(canonical, &a) != nil || a == nil {
		return nil, errArguments
	}
	var schema map[string]any
	for _, tool := range Tools() {
		if tool.Name == name {
			_ = json.Unmarshal(tool.InputSchema, &schema)
			break
		}
	}
	if schema == nil {
		return nil, errors.New("unsupported_tool")
	}
	if !validate(schema, a, 0) {
		return nil, errArguments
	}
	for _, k := range []string{"people", "integration_types", "entity_concepts", "topic_concepts", "example_resource_id", "min_similarity", "cursor"} {
		if v, ok := a[k]; ok && meaningful(v) {
			return nil, errFilter
		}
	}
	if name == "telara_get_context" {
		if !kind(a["entity_type"].(string)) {
			return nil, errFilter
		}
		for _, v := range array(a, "edge_types") {
			if !edges[v.(string)] {
				return nil, errFilter
			}
		}
		if !record.IsHex64(a["entity_id"].(string)) {
			return nil, errArguments
		}
	}
	for _, v := range array(a, "resource_types") {
		if !kind(v.(string)) {
			return nil, errFilter
		}
	}
	if id, ok := a["task_id"].(string); ok && !record.IsUUID(id) {
		return nil, errArguments
	}
	for _, k := range []string{"goal", "milestone", "resume_context"} {
		if v, ok := a[k].(string); ok && strings.TrimSpace(v) == "" {
			return nil, errArguments
		}
	}
	if n, ok := a["token_estimate"].(float64); ok && n < 0 {
		return nil, errArguments
	}
	for k, max := range map[string]float64{"limit": 50, "max_related": 20, "max_tokens": 20000} {
		if v, ok := a[k].(float64); ok && (v < 1 || v > max || k == "max_tokens" && v < 200 || name == "telara_task_list" && k == "limit" && v > 25) {
			return nil, errArguments
		}
	}
	return a, nil
}
func meaningful(v any) bool {
	switch v := v.(type) {
	case string:
		return strings.TrimSpace(v) != ""
	case []any:
		return len(v) > 0
	default:
		return v != nil
	}
}
func kind(s string) bool {
	return s == "task_summary" || s == "conclusion" || s == "checkpoint" || s == "session" || s == "evidence" || s == "task" || s == "pause"
}

var edges = map[string]bool{"OF_TASK": true, "WORKED_ON": true, "SUPPORTS": true, "REFERENCES": true, "RECALLED": true, "CONTAINS": true}

func array(a map[string]any, k string) []any { v, _ := a[k].([]any); return v }
func validate(s map[string]any, v any, depth int) bool {
	if depth > 16 {
		return false
	}
	switch s["type"] {
	case "object":
		a, ok := v.(map[string]any)
		if !ok || a == nil {
			return false
		}
		props, _ := s["properties"].(map[string]any)
		for _, req := range array(s, "required") {
			if _, ok := a[req.(string)]; !ok {
				return false
			}
		}
		for k, v := range a {
			p, ok := props[k].(map[string]any)
			if !ok || !validate(p, v, depth+1) {
				return false
			}
		}
	case "array":
		a, ok := v.([]any)
		if !ok || len(a) > 256 {
			return false
		}
		for _, v := range a {
			if !validate(s["items"].(map[string]any), v, depth+1) {
				return false
			}
		}
	case "string":
		if _, ok := v.(string); !ok {
			return false
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return false
		}
	case "integer", "number":
		n, ok := v.(float64)
		if !ok || math.Abs(n) > 9007199254740991 || s["type"] == "integer" && math.Trunc(n) != n {
			return false
		}
	default:
		return false
	}
	if values, ok := s["enum"].([]any); ok {
		for _, x := range values {
			if x == v {
				return true
			}
		}
		return false
	}
	return true
}
