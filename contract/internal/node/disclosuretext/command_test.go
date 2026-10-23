package disclosuretext

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
)

const taskID = "12345678-1234-4234-8234-123456789abc"

func normalized(t *testing.T, tool, raw string) (NormalizedCommand, error) {
	t.Helper()
	c, e := DecodeCommand(tool, []byte(raw))
	if e != nil {
		return NormalizedCommand{}, e
	}
	r, e := localpolicy.Ruleset()
	if e != nil {
		t.Fatal(e)
	}
	return NormalizeCommand(c, ByteBudget{4096}, CurrentSchema(tool), r.Fingerprint())
}
func TestCompleteCommandCanonicalGolden(t *testing.T) {
	n, e := normalized(t, "local.create_task", `{"goal":"ship","file_paths":[]}`)
	if e != nil {
		t.Fatal(e)
	}
	want := `{"budget_unit":"utf8-bytes","file_paths":[],"goal":"ship","max_bytes":4096,"name":null}`
	if string(n.Canonical) != want || n.Args.Name != nil {
		t.Fatalf("unexpected canonical args %s", n.Canonical)
	}
	x, e := normalized(t, "local.create_task", `{"file_paths":[],"goal":"ship","name":""}`)
	if e != nil || x.Args.Name == nil || n.ArgsHash == x.ArgsHash {
		t.Fatal("missing and supplied empty name collapsed")
	}
	n, e = normalized(t, "local.list_tasks", `{}`)
	if e != nil || n.Args.Limit != 10 || n.Args.Mode != "summary" {
		t.Fatal("list defaults")
	}
	x, e = normalized(t, "local.list_tasks", `{"include_completed":false,"include_receipts":false,"limit":10,"mode":"summary","query":""}`)
	if e != nil || n.ArgsHash != x.ArgsHash {
		t.Fatal("equivalent declared defaults differ")
	}
	n, e = normalized(t, "local.lexical_search", `{"query":""}`)
	if e != nil || n.Args.Query != "" {
		t.Fatal("empty query cannot reach query_required")
	}
	for _, tool := range []string{"local.pause_task", "local.complete_task"} {
		if _, e := normalized(t, tool, `{"task_id":"`+taskID+`","token_estimate":1,"resume_context":"x"}`); tool == "local.pause_task" && e != nil {
			t.Fatal(e)
		}
	}
}
func TestMalformedAndUnsupportedCannotBecomePartialCommand(t *testing.T) {
	cases := []struct{ tool, raw string }{
		{"local.create_task", `{"goal":"x","goal":"y"}`}, {"local.create_task", `{"goal":"\ud800"}`}, {"local.create_task", `{"goal":null}`},
		{"local.create_task", `{"goal":"x","file_paths":[null]}`}, {"local.create_task", `{"goal":"x","repo":"ignored"}`},
		{"local.checkpoint_task", `{"task_id":"` + taskID + `","milestone":"x","done":["d"]}`},
		{"local.pause_task", `{"task_id":"` + taskID + `","resume_context":"x"}`}, {"local.pause_task", `{"task_id":"` + taskID + `","resume_context":"x","token_estimate":"1"}`},
		{"local.pause_task", `{"task_id":"` + taskID + `","resume_context":"x","token_estimate":2147483648}`},
		{"local.list_tasks", `{"include_receipts":true}`}, {"local.lookup_record", `{"record_id":"` + strings.Repeat("a", 64) + `","max_neighbors":1}`},
		{"local.lexical_search", `{"query":"x","include_history":true}`}, {"local.lexical_search", `{"query":"x","resource_types":["checkpoint","checkpoint"]}`},
		{"local.lexical_search", `{"query":"x","resource_types":["foreign"]}`}, {"local.lexical_search", `{"query":"x","min_similarity":0.5}`},
		{"local.complete_task", `{"task_id":"` + taskID + `","token_estimate":0,"changes_made":[null]}`},
		{"local.create_task", `{"goal":` + strings.Repeat("[", 33) + `0` + strings.Repeat("]", 33) + `}`},
	}
	for _, c := range cases {
		if _, e := normalized(t, c.tool, c.raw); e == nil {
			t.Errorf("accepted malformed/unsupported %s", c.tool)
		} else if strings.Contains(e.Error(), "ignored") {
			t.Fatal("error echoed arguments")
		}
	}
	if _, e := DecodeCommand("local.create_task", bytes.Repeat([]byte("x"), MaxEnvelope+1)); e == nil {
		t.Fatal("oversize accepted")
	}
	if _, e := DecodeCommand("local.create_task", []byte{'{', '"', 'g', 'o', 'a', 'l', '"', ':', '"', 0xff, '"', '}'}); e == nil {
		t.Fatal("invalid UTF8 repaired")
	}
}
func TestCompleteRedactionBeforeBoundsAndVersionFence(t *testing.T) {
	secret := "ghp_" + strings.Repeat("A", 36)
	raw, _ := json.Marshal(map[string]any{"goal": strings.Repeat("x", 100) + " " + secret})
	n, e := normalized(t, "local.create_task", string(raw))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(n.Canonical), secret) || n.Args.Goal == strings.Repeat("x", 100)+" "+secret {
		t.Fatal("complete args not redacted")
	}
	if _, e := normalized(t, "local.create_task", `{"goal":"`+strings.Repeat("z", 16385)+`"}`); Code(e) != "argument_limit" {
		t.Fatal("oversize silently fitted")
	}
	c, _ := DecodeCommand("local.create_task", []byte(`{"goal":"x"}`))
	r, _ := localpolicy.Ruleset()
	if _, e := NormalizeCommand(c, ByteBudget{4096}, "future_args_v2", r.Fingerprint()); Code(e) != "op_schema_unavailable" {
		t.Fatal("future schema accepted")
	}
	if _, e := NormalizeCommand(c, ByteBudget{4096}, CurrentSchema(c.Tool()), strings.Repeat("0", 64)); Code(e) != "op_schema_unavailable" {
		t.Fatal("wrong historical redactor accepted")
	}
	// NFKC is a view transform. Argument identity preserves complete Unicode.
	n, e = normalized(t, "local.create_task", `{"goal":"①"}`)
	if e != nil || n.Args.Goal != "①" {
		t.Fatal("view normalization leaked into argument identity")
	}
}

func TestTaskTreeRequiredStringsDoNotCoerceNullOrMissing(t *testing.T) {
	for _, item := range []string{`{"step":null,"status":"done"}`, `{"status":"done"}`, `{"step":1,"status":"done"}`, `{"step":"x","status":null}`, `null`, `{"step":"x","status":"done","detail":"unsupported"}`} {
		if _, e := normalized(t, "local.checkpoint_task", `{"task_id":"`+taskID+`","milestone":"x","task_tree":[`+item+`]}`); e == nil {
			t.Errorf("accepted non-string or incomplete task tree item %s", item)
		}
	}
	n, e := normalized(t, "local.checkpoint_task", `{"task_id":"`+taskID+`","milestone":"x","task_tree":[{"step":"","status":"done"}]}`)
	if e != nil || len(n.Args.TaskTree) != 1 || n.Args.TaskTree[0].Step != "" {
		t.Fatal("explicit empty string must stay a string", e)
	}
}

func TestExactIntegerSourceTokensBeforeJCS(t *testing.T) {
	for _, fraction := range []string{"2147483647.00000001", "1.000000000000000001", "0.0000000000000000000001"} {
		if _, e := normalized(t, "local.pause_task", `{"task_id":"`+taskID+`","resume_context":"x","token_estimate":`+fraction+`}`); e == nil {
			t.Errorf("fractional estimate accepted %s", fraction)
		}
	}
	for _, fraction := range []string{"25.000000000000001", "24.9999999999999999999999"} {
		if _, e := normalized(t, "local.list_tasks", `{"limit":`+fraction+`}`); e == nil {
			t.Errorf("fractional limit accepted %s", fraction)
		}
	}
	for _, integer := range []string{"2147483647", "2147483647.0", "2.147483647e9"} {
		n, e := normalized(t, "local.pause_task", `{"task_id":"`+taskID+`","resume_context":"x","token_estimate":`+integer+`}`)
		if e != nil || n.Args.TokenEstimate == nil || *n.Args.TokenEstimate != 2147483647 {
			t.Fatal("exact integer estimate refused", e)
		}
	}
	var hash string
	for _, integer := range []string{"25", "25.0", "2.5e1", "250e-1", " 25 "} {
		n, e := normalized(t, "local.list_tasks", `{"limit":`+integer+`}`)
		if e != nil || n.Args.Limit != 25 {
			t.Fatal("exact integer limit refused", e)
		}
		if hash != "" && n.ArgsHash != hash {
			t.Fatal("equal exact integers need equal canonical arguments")
		}
		hash = n.ArgsHash
	}
}

func TestExactIntegerWorkHasNoExponentExpansion(t *testing.T) {
	for _, token := range []string{"1e999999999", "1e-999999999", "123456789012345678901234567890"} {
		if _, ok := exactInteger([]byte(token), 0, 2147483647); ok {
			t.Fatal("oversize nonzero exact integer accepted")
		}
	}
	if n, ok := exactInteger([]byte("0e"+strings.Repeat("9", MaxEnvelope-2)), 0, 2147483647); !ok || n != 0 {
		t.Fatal("bounded zero exponent evaluation")
	}
	if n, ok := exactInteger([]byte("0."+strings.Repeat("0", MaxEnvelope-2)), 0, 2147483647); !ok || n != 0 {
		t.Fatal("bounded zero fractional evaluation")
	}
	if _, e := normalized(t, "local.list_tasks", `{"limit":1e999999999}`); e == nil || strings.Contains(e.Error(), "999999999") {
		t.Fatal("huge exponent must fail with a fixed error")
	}
}
