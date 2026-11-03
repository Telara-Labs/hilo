//go:build darwin || linux

package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/shim"
)

// Real local transports and daemon, with the existing explicitly nonpersistent
// store boundary. This proves protocol handling, not SQLite integration.
func TestModernAndLegacyThroughShimAndDaemon(t *testing.T) {
	b, s := backend()
	base := t.TempDir()
	if e := os.Chmod(base, 0700); e != nil {
		t.Fatal(e)
	}
	p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(p.Run)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	done, ready := make(chan error, 1), make(chan struct{})
	go func() {
		done <- daemon.Run(ctx, daemon.Config{Paths: p, Ready: func() { close(ready) }, Open: func(context.Context) (daemon.Backend, error) { return b, nil }})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("daemon shutdown stalled")
		}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("daemon not ready")
	}
	for i, v := range []string{"2024-11-05", "2025-03-26", "2025-06-18", "2026-07-28"} {
		t.Run(v, func(t *testing.T) {
			var input, output bytes.Buffer
			ids := map[string]string{}
			for n, method := range []string{"server/discover", "tools/list", "prompts/list", "resources/list", "tools/call", "ping"} {
				id := fmt.Sprintf("900719925474%d%d", i, n)
				ids[id] = method
				meta := map[string]any{"io.modelcontextprotocol/protocolVersion": v, "io.modelcontextprotocol/clientInfo": map[string]string{"name": "fixture", "version": "1"}, "io.modelcontextprotocol/clientCapabilities": map[string]any{}, "com.telara/conversation": fmt.Sprintf("chat-%d", i), "progressToken": "p", "example.com/trace-id": "ignored"}
				params := map[string]any{"_meta": meta}
				if method == "tools/call" {
					params["name"] = "telara_task_create"
					params["arguments"] = map[string]string{"goal": "Modern transport"}
					meta["com.telara/op-id"] = fmt.Sprintf("modern-%d", i)
				}
				raw, _ := json.Marshal(params)
				if e := json.NewEncoder(&input).Encode(daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(id), Method: method, Params: raw}); e != nil {
					t.Fatal(e)
				}
			}
			// No initialize and no MCP session id precedes any request.
			if e := shim.Run(ctx, &input, &output, shim.Config{Paths: p}); e != nil {
				t.Fatal(e)
			}
			decoder := json.NewDecoder(&output)
			count := len(ids)
			for n := 0; n < count; n++ {
				var r struct {
					ID     json.RawMessage            `json:"id"`
					Result map[string]json.RawMessage `json:"result"`
					Error  *daemon.RPCError           `json:"error"`
				}
				if e := decoder.Decode(&r); e != nil || r.Error != nil {
					t.Fatal("transport failed", e, r.Error)
				}
				id := string(r.ID)
				method, ok := ids[id]
				if !ok {
					t.Fatal("id changed or duplicated", id)
				}
				delete(ids, id)
				if string(r.Result["resultType"]) != `"complete"` {
					t.Fatal("missing result type", method)
				}
				if method == "tools/call" && string(r.Result["isError"]) != "false" {
					t.Fatal("call failed")
				}
			}
			if len(ids) != 0 {
				t.Fatal("missing responses")
			}
		})
	}
	calls, _ := s.Audit()
	if len(calls) != 4 {
		t.Fatal("calls missing")
	}
	for i := 1; i < len(calls); i++ {
		if calls[i-1].Access.ScopeID == calls[i].Access.ScopeID {
			t.Fatal("conversation scopes merged")
		}
	}
}
