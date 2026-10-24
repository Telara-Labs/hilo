package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	mcp "github.com/Telara-Labs/telara-memory/contract/internal/node/mcp/internal/fixture"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp/internal/teststore"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

func TestExactTaskListReadsCompletedWithoutMutation(t *testing.T) {
	b, s := backend()
	row := teststore.Item("completed", taskID, teststore.Owner, "task")
	row.Fields["name"] = "Finished target"
	row.Fields["status"] = "completed"
	checkpoint := teststore.Item("checkpoint", taskID, teststore.Owner, "checkpoint")
	checkpoint.Fields["milestone"] = "Full checkpoint detail"
	conclusion := teststore.Item("conclusion", taskID, teststore.Owner, "conclusion")
	conclusion.Fields["final_summary"] = "Completed summary"
	conclusion.Explicit = true
	s.Add(row, checkpoint, conclusion)
	// A newer task must not win a limit=1 selection in an exact read.
	unrelated := teststore.Item("other", "00000000-0000-4000-8000-000000000000", teststore.Owner, "task")
	unrelated.Fields["name"] = "Unrelated result"
	unrelated.Fields["status"] = "active"
	unrelated.Order = 100
	s.Add(unrelated)
	for i, args := range []any{
		map[string]any{"task_id": taskID, "limit": 1, "query": "does not match", "include_completed": false},
		map[string]any{"query": taskID, "limit": 1},
		map[string]any{"query": "  " + taskID + "  ", "mode": "summary"},
	} {
		res := good(t, call(b, "telara_task_list", args, fmt.Sprintf("exact-%d", i)))
		text := res.Content[0].Text
		for _, want := range []string{"Finished target", "Full checkpoint detail", "Completed summary", "completed"} {
			if !strings.Contains(text, want) {
				t.Fatalf("exact read omitted %s", want)
			}
		}
		if strings.Contains(text, "Unrelated result") || strings.Contains(text, "Selection truncated") {
			t.Fatal("exact read used list filters/limits")
		}
	}
	rows, mutations, exposures := s.Snapshot()
	if mutations != 0 || exposures != 3 || rows[0].Fields["status"] != "completed" {
		t.Fatal("exact read changed task lifecycle")
	}
	if r := call(b, "telara_task_list", map[string]any{"task_id": "invalid"}, "invalid-exact"); r.Error == nil || r.Error.Code != -32602 {
		t.Fatal("invalid UUID accepted")
	}
}

func TestExactTaskListOwnerAndUnavailable(t *testing.T) {
	for _, args := range []map[string]any{{"task_id": taskID}, {"query": taskID}} {
		b, s := backend()
		local := teststore.Item("local", taskID, teststore.Owner, "task")
		local.Fields["name"] = "Local visible"
		tenant := teststore.Item("tenant", taskID, "tenant:one", "task")
		tenant.Fields["name"] = "Hidden tenant"
		s.Add(local, tenant)
		res := good(t, call(b, "telara_task_list", args, "scoped"))
		if strings.Contains(res.Content[0].Text, "Hidden tenant") {
			t.Fatal("inaccessible owner leaked")
		}
		s.AllowedOwners["tenant:one"] = true
		r := call(b, "telara_task_list", args, "ambiguous-exact")
		if r.Error != nil || !r.Result.(mcp.Result).IsError || !strings.Contains(textOf(t, r), "ambiguous_id") || strings.Contains(textOf(t, r), "Hidden tenant") {
			t.Fatal("ambiguous exact ID merged owners")
		}
		b, s = backend()
		s.Add(tenant)
		hidden := call(b, "telara_task_list", args, "hidden")
		absent := call(b, "telara_task_list", map[string]any{"task_id": "00000000-0000-4000-8000-000000000000"}, "absent")
		for _, r := range []daemon.Response{hidden, absent} {
			if r.Error != nil || !r.Result.(mcp.Result).IsError {
				t.Fatal("unavailable exact read succeeded")
			}
		}
		a := strings.SplitN(hidden.Result.(mcp.Result).Content[0].Text, "\n", 2)[1]
		c := strings.SplitN(absent.Result.(mcp.Result).Content[0].Text, "\n", 2)[1]
		if a != c {
			t.Fatal("inaccessible existence disclosed")
		}
		// A visible tenant task is readable without changing ownership or status.
		s.AllowedOwners["tenant:one"] = true
		good(t, call(b, "telara_task_list", args, "tenant-read"))
		_, mutations, _ := s.Snapshot()
		if mutations != 0 {
			t.Fatal("exact read mutated")
		}
	}
}

func TestPingNeverTouchesStoreOrResolver(t *testing.T) {
	b, s := backend()
	s.FailItems, s.FailAppend, s.FailExposure, s.Denied = true, true, true, true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, backend := range []*mcp.Backend{b, mcp.New(nil, nil)} {
		r := backend.Handle(ctx, ipc.Hello{}, daemon.Request{Method: "ping", ID: json.RawMessage(`"health"`)})
		if r.Error != nil || string(r.ID) != `"health"` {
			t.Fatal("ping failed")
		}
		obj, ok := r.Result.(map[string]any)
		if !ok || len(obj) != 0 {
			t.Fatal("ping must return empty object")
		}
	}
	if len(s.Calls) != 0 {
		t.Fatal("ping persisted")
	}
}

func TestOpaqueRPCIDsEchoButNeverPersist(t *testing.T) {
	b, s := backend()
	for n, id := range []any{"ghp_" + strings.Repeat("a", 36), "Bearer " + strings.Repeat("b", 64), "\u202e\n", strings.Repeat("c", 1024), 42} {
		params := map[string]any{"name": "telara_task_create", "arguments": map[string]any{"goal": "Opaque ID fixture"}}
		params["_meta"] = map[string]string{"com.telara/op-id": fmt.Sprintf("opaque-%d", n)}
		raw, _ := json.Marshal(params)
		idJSON, _ := json.Marshal(id)
		r := b.Handle(context.Background(), ipc.Hello{Client: "fixture", Shim: "shim-one"}, daemon.Request{JSONRPC: "2.0", ID: idJSON, Method: "tools/call", Params: raw})
		good(t, r)
		if string(r.ID) != string(idJSON) {
			t.Fatal("correlation changed")
		}
		current := s.Calls[len(s.Calls)-1]
		if !record.IsHex64(current.Op) {
			t.Fatal("non-hashed operation")
		}
		if text, ok := id.(string); ok && len(text) > 16 {
			calls, _ := json.Marshal(s.Calls)
			if strings.Contains(string(calls), text) {
				t.Fatal("raw ID in store call")
			}
			for _, sealed := range s.Sealed {
				header, body, _, _ := sealed.Envelope()
				if strings.Contains(string(header), text) || strings.Contains(string(body), text) {
					t.Fatal("raw ID in sealed receipt")
				}
			}
		}
	}
}
