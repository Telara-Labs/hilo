package mcp

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/hilo/contract/internal/node/localpolicy"
)

func normalizedMapping(t *testing.T, tool, raw string) (disclosuretext.NormalizedCommand, error) {
	t.Helper()
	cmd, budget, err := translateCommand(tool, json.RawMessage(raw))
	if err != nil {
		return disclosuretext.NormalizedCommand{}, err
	}
	rules, err := localpolicy.Ruleset()
	if err != nil {
		t.Fatal(err)
	}
	return disclosuretext.NormalizeCommand(cmd, budget, disclosuretext.CurrentSchema(cmd.Tool()), rules.Fingerprint())
}

func TestDisclosureEveryToolMapping(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	tests := []struct{ tool, raw, local string }{
		{"telara_task_create", `{"goal":"test","name":"named","anchors":{"file_paths":["a.go"]}}`, "local.create_task"},
		{"telara_task_checkpoint", `{"task_id":"` + id + `","milestone":"done","next_steps":"next","knowledge_refs":[],"task_tree":[{"step":"test","status":"done"}]}`, "local.checkpoint_task"},
		{"telara_task_pause", `{"task_id":"` + id + `","resume_context":"later","progress_notes":"progress","handoff_hint":"next","token_estimate":2}`, "local.pause_task"},
		{"telara_task_complete", `{"task_id":"` + id + `","final_summary":"finished","changes_made":["a.go"],"token_estimate":3}`, "local.complete_task"},
		{"telara_get_context", `{"entity_id":"` + strings.Repeat("a", 64) + `","entity_type":"checkpoint"}`, "local.lookup_record"},
		{"telara_task_resume", `{"task_id":"` + id + `"}`, "local.resume_task"},
		{"telara_task_list", `{"query":"work","include_completed":true,"include_receipts":false,"mode":"detail","limit":12}`, "local.list_tasks"},
		{"telara_knowledge_search", `{"query":"term","resource_types":["checkpoint","conclusion","task_summary"],"max_tokens":4096}`, "local.lexical_search"},
	}
	for _, tt := range tests {
		t.Run(tt.tool+tt.local, func(t *testing.T) {
			n, err := normalizedMapping(t, tt.tool, tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if n.Tool != tt.local {
				t.Fatalf("%s", n.Tool)
			}
			if tt.tool == "telara_task_create" && (len(n.Args.FilePaths) != 1 || n.Args.FilePaths[0] != "a.go") {
				t.Fatal(n.Args)
			}
			if tt.tool == "telara_knowledge_search" && (n.Budget.MaxBytes != 4096 || len(n.Args.ResourceTypes) != 2) {
				t.Fatal(n)
			}
		})
	}
}

func TestDisclosureUnsupportedArgumentsAndOriginalNumbers(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	tests := []struct{ tool, raw string }{
		{"telara_task_list", `{"task_id":"` + id + `"}`},
		{"telara_task_list", `{"query":"` + id + `"}`},
		{"telara_task_create", `{"goal":"test","anchors":{"repo":"repo"}}`},
		{"telara_task_checkpoint", `{"task_id":"` + id + `","milestone":"test","decisions":["a"]}`},
		{"telara_task_checkpoint", `{"task_id":"` + id + `","milestone":"test","task_tree":[{"step":"a","status":"done","detail":"a"}]}`},
		{"telara_task_list", `{"include_receipts":true}`},
		{"telara_task_list", `{"task_id":"` + id + `","include_receipts":true}`},
		{"telara_knowledge_search", `{"query":"test","people":["a"]}`},
		{"telara_knowledge_search", `{"query":"test","resource_types":["task"]}`},
		{"telara_knowledge_search", `{"query":"test","cursor":"anything"}`},
		{"telara_get_context", `{"entity_id":"` + strings.Repeat("a", 64) + `","entity_type":"checkpoint","max_related":1}`},
		{"telara_get_context", `{"entity_id":"` + strings.Repeat("a", 64) + `","entity_type":"task_summary"}`},
		{"telara_get_context", `{"entity_id":"` + strings.Repeat("a", 64) + `","entity_type":"evidence"}`},
		{"telara_get_context", `{"entity_id":"` + strings.Repeat("a", 64) + `","entity_type":"checkpoint","edge_types":["OF_TASK"]}`},
		{"telara_get_context", `{"entity_id":"` + strings.Repeat("a", 64) + `","entity_type":"checkpoint","focus_query":"x"}`},
		{"telara_task_pause", `{"task_id":"` + id + `","resume_context":"x","token_estimate":1.00000000000000001}`},
		{"telara_task_complete", `{"task_id":"` + id + `","token_estimate":2147483648}`},
		{"telara_task_create", `{"goal":"test","max_tokens":200}`},
		{"telara_task_create", `{"goal":"test","unknown":true}`},
		{"local.next_page", `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.tool+tt.raw, func(t *testing.T) {
			if _, err := normalizedMapping(t, tt.tool, tt.raw); err == nil {
				t.Fatal("accepted unsupported input")
			}
		})
	}
}

func TestDisclosureErrorVocabularyIsContentFree(t *testing.T) {
	if got := adapterError(errArguments); got != "invalid_arguments" {
		t.Fatal(got)
	}
	if got := adapterError(&textError{"secret arbitrary failure"}); got != "storage_error" {
		t.Fatal(got)
	}
}

type textError struct{ s string }

func (e *textError) Error() string { return e.s }

func TestDisclosureEmptyResourceTypesUsesDefaultKinds(t *testing.T) {
	omitted, err := normalizedMapping(t, "telara_knowledge_search", `{"query":"orchard"}`)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := normalizedMapping(t, "telara_knowledge_search", `{"query":"orchard","resource_types":[]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(omitted.Args.ResourceTypes) == 0 || !reflect.DeepEqual(omitted, empty) {
		t.Fatalf("empty filter differs from default kinds: omitted=%+v empty=%+v", omitted, empty)
	}
}

func TestDisclosureContextProjectionAndKind(t *testing.T) {
	for _, kind := range []string{"checkpoint", "task", "pause", "session", "conclusion"} {
		for _, include := range []string{"", `,"include_content":false`, `,"include_content":true`} {
			n, err := normalizedMapping(t, "telara_get_context", `{"entity_id":"`+strings.Repeat("a", 64)+`","entity_type":"`+kind+`"`+include+`}`)
			if err != nil {
				t.Fatal(kind, include, err)
			}
			wantKind := kind
			if string(n.Args.RecordKind) != wantKind || n.Args.IncludeContent != strings.Contains(include, "true") {
				t.Fatal(n.Args)
			}
		}
	}
}

func TestDisclosureBudgetRejectsRoundedFraction(t *testing.T) {
	for _, raw := range []string{"2048.00000000000000001", "4096.0000000000000001", "1e999999999", "0e99999999"} {
		if _, err := normalizedMapping(t, "telara_knowledge_search", `{"query":"x","max_tokens":`+raw+`}`); err == nil {
			t.Fatal("rounded budget accepted", raw)
		}
	}
	for _, raw := range []string{"2048", "2048.0", "2.048e3", "20000"} {
		if _, err := normalizedMapping(t, "telara_knowledge_search", `{"query":"x","max_tokens":`+raw+`}`); err != nil {
			t.Fatal(raw, err)
		}
	}
}
