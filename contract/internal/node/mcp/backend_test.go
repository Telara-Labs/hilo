package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	mcp "github.com/Telara-Labs/telara-memory/contract/internal/node/mcp/internal/fixture"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp/internal/teststore"
	"github.com/Telara-Labs/telara-memory/contract/replay"
)

const taskID = "89abcdef-1234-4234-8234-123456789abc"

func call(b *mcp.Backend, name string, args any, op string) daemon.Response {
	raw, _ := json.Marshal(map[string]any{"name": name, "arguments": args, "_meta": map[string]string{"com.telara/op-id": op}})
	return b.Handle(context.Background(), ipc.Hello{Client: "fixture", Shim: "shim-one"}, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: raw})
}
func textOf(t *testing.T, r daemon.Response) string {
	t.Helper()
	b, _ := json.Marshal(r)
	return string(b)
}
func good(t *testing.T, r daemon.Response) mcp.Result {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("RPC %v", r.Error)
	}
	res, ok := r.Result.(mcp.Result)
	if !ok || res.IsError {
		t.Fatalf("result %s", textOf(t, r))
	}
	return res
}
func backend() (*mcp.Backend, *teststore.Store) {
	s := teststore.New()
	return mcp.New(s, teststore.Resolver{}), s
}
func TestHostedFixtures(t *testing.T) {
	data, e := os.ReadFile("testdata/hosted-v1/input-schemas.json")
	if e != nil {
		t.Fatal(e)
	}
	var want map[string]any
	if json.Unmarshal(data, &want) != nil {
		t.Fatal("fixture")
	}
	got := map[string]any{}
	for _, tool := range mcp.Tools() {
		var schema any
		if json.Unmarshal(tool.InputSchema, &schema) != nil {
			t.Fatal(tool.Name)
		}
		got[tool.Name] = schema
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("advertised hosted schema drift")
	}
	first := mcp.Tools()
	first[0].InputSchema[0] = '!'
	if mcp.Tools()[0].InputSchema[0] != '{' {
		t.Fatal("shared schema bytes")
	}
}
func TestValidation(t *testing.T) {
	b, s := backend()
	cases := []struct {
		name string
		args any
		code string
	}{
		{"task_create", map[string]any{}, "invalid_arguments"},
		{"task_create", map[string]any{"goal": " "}, "invalid_arguments"},
		{"task_create", map[string]any{"goal": "x", "unknown": "secret"}, "invalid_arguments"},
		{"task_create", map[string]any{"goal": "x", "anchors": map[string]any{"owner": "x"}}, "invalid_arguments"},
		{"task_checkpoint", map[string]any{"task_id": taskID}, "invalid_arguments"},
		{"task_checkpoint", map[string]any{"task_id": taskID, "milestone": "x", "task_tree": []any{map[string]any{"step": "a", "status": "bad"}}}, "invalid_arguments"},
		{"task_pause", map[string]any{"task_id": taskID, "resume_context": "x"}, "invalid_arguments"},
		{"task_complete", map[string]any{"task_id": taskID}, "invalid_arguments"},
		{"task_complete", map[string]any{"task_id": taskID, "token_estimate": -1}, "invalid_arguments"},
		{"task_complete", map[string]any{"task_id": taskID, "token_estimate": 1.5}, "invalid_arguments"},
		{"task_resume", map[string]any{"task_id": "not-a-uuid"}, "invalid_arguments"},
		{"task_list", map[string]any{"mode": "other"}, "invalid_arguments"},
		{"task_list", map[string]any{"limit": 26}, "invalid_arguments"},
		{"knowledge_search", map[string]any{"max_tokens": 199}, "invalid_arguments"},
		{"knowledge_search", map[string]any{"people": []string{"person"}}, "unsupported_filter"},
		{"knowledge_search", map[string]any{"integration_types": []string{"gitlab"}}, "unsupported_filter"},
		{"knowledge_search", map[string]any{"entity_concepts": []string{"x"}}, "unsupported_filter"},
		{"knowledge_search", map[string]any{"topic_concepts": []string{"x"}}, "unsupported_filter"},
		{"knowledge_search", map[string]any{"example_resource_id": "x"}, "unsupported_filter"},
		{"knowledge_search", map[string]any{"min_similarity": 0.0}, "unsupported_filter"},
		{"knowledge_search", map[string]any{"cursor": "x"}, "unsupported_filter"},
		{"knowledge_search", map[string]any{"resource_types": []string{"code"}}, "unsupported_filter"},
		{"knowledge_search", map[string]any{"people": nil}, "invalid_arguments"},
		{"get_context", map[string]any{"entity_id": strings.Repeat("a", 64)}, "invalid_arguments"},
		{"get_context", map[string]any{"entity_id": strings.Repeat("a", 64), "entity_type": "Ticket"}, "unsupported_filter"},
		{"get_context", map[string]any{"entity_id": strings.Repeat("a", 64), "entity_type": "task", "edge_types": []string{"bad"}}, "unsupported_filter"},
		{"get_context", map[string]any{"entity_id": "hosted:abc", "entity_type": "task"}, "invalid_arguments"},
		{"no_such_tool", map[string]any{}, "unsupported_tool"},
	}
	for n, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", n, tc.name), func(t *testing.T) {
			r := call(b, "telara_"+tc.name, tc.args, fmt.Sprintf("invalid-%d", n))
			if !strings.Contains(textOf(t, r), tc.code) {
				t.Fatalf("%s", textOf(t, r))
			}
		})
	}
	_, n, _ := s.Snapshot()
	if n != 0 || len(s.Calls) != 0 {
		t.Fatal("invalid input mutated")
	}
	for _, raw := range []string{
		`{"name":"telara_task_create","arguments":{"goal":"x","goal":"y"}}`,
		`{"name":"telara_task_create","arguments":{"goal":"\ud800"}}`,
		`{"name":"telara_task_create","arguments":{"goal":"x"},"unexpected":"x"}`,
		`{"name":"telara_task_create","arguments":{"goal":"x"},"_meta":{"com.telara/native":{"client":"fixture","id":"bad id","kind":"local","origin":"local"}}}`,
		`{"name":"telara_task_create","arguments":{"goal":"x"},"_meta":{"com.telara/conversation-handle":""}}`,
		`{"name":"telara_task_create","arguments":{"goal":"x"},"_meta":null}`,
	} {
		r := b.Handle(context.Background(), ipc.Hello{}, daemon.Request{ID: json.RawMessage("1"), Method: "tools/call", Params: json.RawMessage(raw)})
		if r.Error == nil || r.Error.Code != -32602 {
			t.Fatalf("accepted invalid envelope %s", textOf(t, r))
		}
	}
}
func TestTaskRoundTripAndCompletionMonotone(t *testing.T) {
	b, s := backend()
	res := good(t, call(b, "telara_task_create", map[string]any{"goal": "Implement parser", "anchors": map[string]any{"repo": "r", "branch": "main", "file_paths": []string{"parser.go"}}}, "create"))
	if !strings.Contains(res.Content[0].Text, "call_ref m1.") {
		t.Fatal(res)
	}
	rows, n, x := s.Snapshot()
	if n != 1 || x != 1 {
		t.Fatal(n, x)
	}
	id := rows[0].TaskID
	good(t, call(b, "telara_task_checkpoint", map[string]any{"task_id": id, "milestone": "Parser complete", "next_steps": "Test it", "decisions": []string{"strict"}, "blocked": []string{}, "task_tree": []any{map[string]any{"step": "parse", "status": "done", "detail": "all"}}}, "checkpoint"))
	resumed := good(t, call(b, "telara_task_resume", map[string]any{"task_id": id}, "resume"))
	if !strings.Contains(resumed.Content[0].Text, "Parser complete") || !strings.Contains(resumed.Content[0].Text, "none captured") {
		t.Fatal(resumed)
	}
	good(t, call(b, "telara_task_pause", map[string]any{"task_id": id, "resume_context": "Continue tests", "token_estimate": 0}, "pause"))
	good(t, call(b, "telara_task_complete", map[string]any{"task_id": id, "final_summary": "Tested", "token_estimate": 0}, "complete"))
	good(t, call(b, "telara_task_checkpoint", map[string]any{"task_id": id, "milestone": "Late evidence"}, "late"))
	rows, n, _ = s.Snapshot()
	if n != 5 || rows[0].Fields["status"] != "completed" {
		t.Fatal("completion undone", n, rows[0])
	}
	listed := good(t, call(b, "telara_task_list", map[string]any{}, "list"))
	if strings.Contains(listed.Content[0].Text, "Implement parser") {
		t.Fatal("completed task visible by default")
	}
	good(t, call(b, "telara_task_complete", map[string]any{"task_id": newTask(t, b, s), "token_estimate": 0}, "complete-no-checkpoint"))
}
func newTask(t *testing.T, b *mcp.Backend, s *teststore.Store) string {
	t.Helper()
	good(t, call(b, "telara_task_create", map[string]any{"goal": "No checkpoint"}, "new-task"))
	rows, _, _ := s.Snapshot()
	return rows[len(rows)-1].TaskID
}
func TestOwnerAmbiguityAndNonDisclosure(t *testing.T) {
	b, s := backend()
	local := teststore.Item("local", taskID, teststore.Owner, "task")
	tenant := teststore.Item("tenant", taskID, "tenant:one", "task")
	s.Add(local, tenant)
	hidden := call(b, "telara_task_resume", map[string]any{"task_id": taskID}, "hidden")
	good(t, hidden)
	s.AllowedOwners["tenant:one"] = true
	r := call(b, "telara_task_checkpoint", map[string]any{"task_id": taskID, "milestone": "x"}, "ambiguous")
	if !strings.Contains(textOf(t, r), "ambiguous_id") {
		t.Fatal(textOf(t, r))
	}
	_, n, _ := s.Snapshot()
	if n != 0 {
		t.Fatal("ambiguous write")
	}
	b, s = backend()
	s.AllowedOwners["tenant:one"] = true
	s.Add(tenant)
	if !strings.Contains(textOf(t, call(b, "telara_task_complete", map[string]any{"task_id": taskID, "token_estimate": 0}, "read-only")), "read_only") {
		t.Fatal("tenant write")
	}
	b, s = backend()
	s.Add(tenant)
	absent := call(b, "telara_task_resume", map[string]any{"task_id": "00000000-0000-4000-8000-000000000000"}, "absent")
	inaccessible := call(b, "telara_task_resume", map[string]any{"task_id": taskID}, "inaccessible")
	a := absent.Result.(mcp.Result).Content[0].Text
	c := inaccessible.Result.(mcp.Result).Content[0].Text
	if strings.SplitN(a, "\n", 2)[1] != strings.SplitN(c, "\n", 2)[1] {
		t.Fatal("inaccessible existence leaked")
	}
}
func TestAtomicFailureReplayAndRedaction(t *testing.T) {
	b, s := backend()
	s.FailExposure = true
	r := call(b, "telara_task_create", map[string]any{"goal": "Secret fixture"}, "rollback")
	if !r.Result.(mcp.Result).IsError {
		t.Fatal("exposure fail open")
	}
	_, n, x := s.Snapshot()
	if n != 0 || x != 0 {
		t.Fatal("partial mutation committed")
	}
	s.FailExposure = false
	good(t, call(b, "telara_task_create", map[string]any{"goal": "A task"}, "stable"))
	old := good(t, call(b, "telara_task_create", map[string]any{"goal": "A task"}, "stable"))
	_, n, _ = s.Snapshot()
	if n != 1 {
		t.Fatal("retry mutated", n)
	}
	if !strings.Contains(textOf(t, call(b, "telara_task_create", map[string]any{"goal": "Changed"}, "stable")), "op_conflict") {
		t.Fatal("changed op accepted")
	}
	s.Change(2, true)
	replayed := good(t, call(b, "telara_task_create", map[string]any{"goal": "A task"}, "stable"))
	if replayed.Content[0].Text != replay.Unavailable || reflect.DeepEqual(old, replayed) {
		t.Fatal("stale disclosure")
	}
	b, s = backend()
	secret := "ghp_" + strings.Repeat("x", 36)
	good(t, call(b, "telara_task_create", map[string]any{"goal": strings.Repeat("a", 20000) + " " + secret + " tail"}, "redact"))
	for _, c := range s.Calls {
		if strings.Contains(string(c.Arguments), secret) {
			t.Fatal("raw arg persisted")
		}
	}
	for _, m := range s.Mutations {
		raw, _ := json.Marshal(m)
		if strings.Contains(string(raw), secret) {
			t.Fatal("raw mutation persisted")
		}
	}
}
func TestSearchFiltersEmptyRepeatedAndStorageFailures(t *testing.T) {
	b, s := backend()
	task := teststore.Item("task", taskID, teststore.Owner, "task")
	cp := teststore.Item("checkpoint", taskID, teststore.Owner, "checkpoint")
	cp.Fields["milestone"] = "parser evidence"
	s.Add(task, cp)
	good(t, call(b, "telara_knowledge_search", map[string]any{"query": " ", "people": []string{}}, "empty"))
	for _, op := range []string{"one", "two"} {
		r := good(t, call(b, "telara_knowledge_search", map[string]any{"query": "parser", "resource_types": []string{"checkpoint"}}, op))
		if !strings.Contains(r.Content[0].Text, "parser evidence") {
			t.Fatal("explicit repeated search suppressed")
		}
	}
	r := good(t, call(b, "telara_get_context", map[string]any{"entity_id": cp.ID, "entity_type": "checkpoint", "include_content": true}, "context"))
	if !strings.Contains(r.Content[0].Text, "parser evidence") {
		t.Fatal(r)
	}
	s.FailItems = true
	r2 := call(b, "telara_task_list", map[string]any{}, "failed-read")
	if !r2.Result.(mcp.Result).IsError || strings.Contains(textOf(t, r2), "private") {
		t.Fatal("storage failure hidden or leaked")
	}
	s.FailItems = false
	s.FailAppend = true
	r2 = call(b, "telara_task_create", map[string]any{"goal": "x"}, "failed-write")
	if !r2.Result.(mcp.Result).IsError {
		t.Fatal("append failure hidden")
	}
}
func TestMethodsAndUnavailable(t *testing.T) {
	b := mcp.New(nil, nil)
	for _, method := range []string{"tools/list", "resources/list", "prompts/list"} {
		r := b.Handle(context.Background(), ipc.Hello{}, daemon.Request{Method: method, ID: json.RawMessage("1")})
		if r.Error != nil {
			t.Fatal(r.Error)
		}
	}
	if b.Handle(context.Background(), ipc.Hello{}, daemon.Request{Method: "prompts/get"}).Error == nil {
		t.Fatal("withheld prompt must return an RPC error")
	}
	if b.Handle(context.Background(), ipc.Hello{}, daemon.Request{Method: "unknown"}).Error.Code != -32601 {
		t.Fatal("unknown method")
	}
	if b.Handle(context.Background(), ipc.Hello{}, daemon.Request{Method: "tools/list", Params: json.RawMessage(`{"cursor":"x"}`)}).Error.Code != -32602 {
		t.Fatal("ignored list restriction")
	}
	if !strings.Contains(textOf(t, call(b, "telara_task_create", map[string]any{"goal": "x"}, "unavailable")), "store_unavailable") {
		t.Fatal("unwired success")
	}
	if b.Close() != nil {
		t.Fatal("close")
	}
}
func TestConcurrentSameOperation(t *testing.T) {
	b, s := backend()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := call(b, "telara_task_create", map[string]any{"goal": "one"}, "concurrent")
			if r.Error != nil || r.Result.(mcp.Result).IsError {
				t.Error("concurrent call")
			}
		}()
	}
	wg.Wait()
	_, n, _ := s.Snapshot()
	if n != 1 {
		t.Fatal(n)
	}
}

func TestContextMetadataAndExplicitSummaryFilter(t *testing.T) {
	b, s := backend()
	request := teststore.Item("request-conclusion", taskID, teststore.Owner, "conclusion")
	request.Fields["text"] = "needle request body"
	explicit := teststore.Item("explicit-conclusion", taskID, teststore.Owner, "conclusion")
	explicit.Explicit = true
	explicit.Fields["text"] = "needle explicit body"
	s.Add(request, explicit)
	r := good(t, call(b, "telara_knowledge_search", map[string]any{"query": "needle", "resource_types": []string{"task_summary"}}, "explicit-summary"))
	if strings.Contains(r.Content[0].Text, "request body") || !strings.Contains(r.Content[0].Text, "explicit body") {
		t.Fatal("task_summary broadened", r)
	}
	r = good(t, call(b, "telara_get_context", map[string]any{"entity_id": explicit.ID, "entity_type": "conclusion", "include_content": false}, "metadata-only"))
	if strings.Contains(r.Content[0].Text, "needle explicit body") {
		t.Fatal("body leaked through include_content=false")
	}
}
