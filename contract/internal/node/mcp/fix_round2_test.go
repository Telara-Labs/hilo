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

func TestProtocolMetadataOnListAndCall(t *testing.T) {
	for _, version := range []string{"2024-11-05", "2025-03-26", "2025-06-18", "2026-07-28"} {
		for _, method := range []string{"tools/list", "prompts/list", "resources/list", "resources/templates/list", "tools/call"} {
			t.Run(version+method, func(t *testing.T) {
				b, s := backend()
				meta := map[string]any{"io.modelcontextprotocol/protocolVersion": version, "io.modelcontextprotocol/clientInfo": map[string]any{"name": "forged-owner", "version": "1"}, "io.modelcontextprotocol/clientCapabilities": map[string]any{"roots": map[string]any{}}, "com.telara/conversation": "request-chat", "progressToken": "p", "example.com/trace-id": map[string]any{"authority": "unknown-meta-must-not-persist"}}
				params := map[string]any{"_meta": meta}
				if method == "tools/call" {
					params["name"] = "telara_task_create"
					params["arguments"] = map[string]any{"goal": "Metadata fixture"}
					meta["com.telara/op-id"] = "request-op"
				}
				raw, _ := json.Marshal(params)
				out := b.Handle(context.Background(), ipc.Hello{}, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`9007199254740993`), Method: method, Params: raw})
				if out.Error != nil {
					t.Fatal(out.Error)
				}
				if method == "tools/call" {
					good(t, out)
				}
				wire, e := json.Marshal(out)
				if e != nil || !strings.Contains(string(wire), `"resultType":"complete"`) {
					t.Fatal("missing modern envelope", e)
				}
				if strings.HasSuffix(method, "/list") && (!strings.Contains(string(wire), `"ttlMs":15000`) || !strings.Contains(string(wire), `"cacheScope":"private"`)) {
					t.Fatal("missing list hints")
				}
				calls, sealed := s.Audit()
				if method == "tools/call" {
					if len(calls) != 1 || calls[0].Access.ScopeID != record.H("handle", teststore.Access().CredentialID, "request-chat") || calls[0].Access.Client != "fixture" {
						t.Fatal("per-request handle or installed authority lost")
					}
					stored, _ := json.Marshal(calls)
					for _, forbidden := range []string{"unknown-meta-must-not-persist", "forged-owner"} {
						if strings.Contains(string(stored), forbidden) {
							t.Fatal("unrelated metadata persisted in Call")
						}
						for _, sealedRecord := range sealed {
							header, body, _, _ := sealedRecord.Envelope()
							if strings.Contains(string(header), forbidden) || strings.Contains(string(body), forbidden) {
								t.Fatal("unrelated metadata persisted in Seal")
							}
						}
					}
					// Tracing is not part of the operation or argument identity.
					meta["example.com/trace-id"] = "changed-trace"
					retried, _ := json.Marshal(params)
					good(t, b.Handle(context.Background(), ipc.Hello{}, daemon.Request{ID: json.RawMessage(`2`), Method: method, Params: retried}))
					after, _ := s.Audit()
					if len(after) != 1 {
						t.Fatal("tracing changed retry identity")
					}

				} else if len(calls) != 0 {
					t.Fatal("static catalog accessed storage")
				}
				// Invalid Telara identity is rejected even when valid tracing accompanies it.
				meta["com.telara/conversation"] = 123
				raw, _ = json.Marshal(params)
				bad := b.Handle(context.Background(), ipc.Hello{}, daemon.Request{ID: json.RawMessage(`1`), Method: method, Params: raw})
				if bad.Error == nil || bad.Error.Code != -32602 {
					t.Fatal("invalid identity fell back")
				}
			})
		}
	}
}

func TestCanonicalConversationRotatesEveryRequest(t *testing.T) {
	s := teststore.New()
	source := &teststore.Source{Access: teststore.Access()}
	b := mcp.New(s, mcp.IdentityResolver{Source: source})
	for i, handle := range []string{"first", "second", ""} {
		meta := map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": map[string]any{}, "io.modelcontextprotocol/clientInfo": map[string]string{"name": "pretend-client"}, "com.telara/op-id": fmt.Sprintf("rotate-%d", i)}
		if handle != "" {
			meta["com.telara/conversation"] = handle
		}
		params, _ := json.Marshal(map[string]any{"name": "telara_task_create", "arguments": map[string]string{"goal": "Rotate"}, "_meta": meta})
		good(t, b.Handle(context.Background(), ipc.Hello{}, daemon.Request{ID: json.RawMessage(`1`), Method: "tools/call", Params: params}))
	}
	calls, _ := s.Audit()
	if len(calls) != 3 || source.Drains != 3 || calls[0].Access.ScopeID == calls[1].Access.ScopeID || calls[2].Access.ScopeID != "" || calls[2].Access.SessionKey != "" {
		t.Fatal("identity cached across requests")
	}
}

func TestProtocolMetadataIsNotAToolArgument(t *testing.T) {
	b, s := backend()
	out := call(b, "telara_task_create", map[string]any{"goal": "Strict arguments", "_meta": map[string]any{"example.com/trace-id": "t"}}, "argument-meta")
	if out.Error == nil || out.Error.Code != -32602 {
		t.Fatal("protocol metadata accepted inside tool arguments")
	}
	calls, _ := s.Audit()
	if len(calls) != 0 {
		t.Fatal("invalid arguments reached storage")
	}
}
