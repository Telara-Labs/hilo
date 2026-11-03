package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/jcs"
)

type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
type Result struct {
	IsError bool      `json:"isError"`
	Content []Content `json:"content"`
}

func result(text string, bad bool) Result { return Result{bad, []Content{{"text", text}}} }

// Backend exposes only the store-owned disclosure kernel. Fixture callback
// stores, signers and renderers are isolated in internal/fixture for old tests.
type Backend struct {
	disclosure *DisclosureAdapter
	control    *ownerControl
}
type Metadata = daemon.Metadata
type Native = daemon.Native

func (b *Backend) StoreWired() bool {
	return b.disclosure != nil && b.disclosure.ready.Load()
}

func (b *Backend) Close() error {
	if b.disclosure != nil {
		return b.disclosure.close()
	}
	return nil
}

// ConnectionClosed runs only after daemon-owned in-flight calls have drained.
// Request cancellation alone must never evict live fallback retry identity.
func (b *Backend) ConnectionClosed(id string) {
	if b.disclosure == nil || id == "" {
		return
	}
	a := b.disclosure
	a.mu.Lock()
	defer a.mu.Unlock()
	if cached, ok := a.connections[id]; ok {
		_ = cached.client.Close()
		delete(a.connections, id)
	}
}

func rpcError(req daemon.Request, code int, message string) daemon.Response {
	return daemon.Response{JSONRPC: "2.0", ID: req.ID, Error: &daemon.RPCError{Code: code, Message: message}}
}
func (b *Backend) Handle(ctx context.Context, h ipc.Hello, req daemon.Request) daemon.Response {
	if out, ok := daemon.Setup(req); ok {
		if req.Method == "initialize" && out.Error == nil && b.disclosure != nil {
			tokens, err := b.disclosure.issueTokens(ctx, h)
			if err != nil {
				return rpcError(req, -32000, adapterError(err))
			}
			out.Result.(map[string]any)["_meta"] = map[string]any{"com.telara/op-ids": tokens}
		}
		return out
	}
	out := daemon.Response{JSONRPC: "2.0", ID: req.ID}
	params, m, e := daemon.RequestParams(req.Params)
	if e != nil {
		return rpcError(req, -32602, e.Error())
	}
	switch req.Method {
	case "resources/list":
		if !emptyParams(params) {
			return rpcError(req, -32602, "invalid_arguments")
		}
		out.Result = map[string]any{"resources": []any{}, "ttlMs": 15000, "cacheScope": "private"}
		return out
	case "resources/templates/list":
		if !emptyParams(params) {
			return rpcError(req, -32602, "invalid_arguments")
		}
		out.Result = map[string]any{"resourceTemplates": []any{}, "ttlMs": 15000, "cacheScope": "private"}
		return out
	case "prompts/list":
		if !emptyParams(params) {
			return rpcError(req, -32602, "invalid_arguments")
		}
		out.Result = map[string]any{"ttlMs": 15000, "cacheScope": "private", "prompts": []any{map[string]any{"name": "start-task", "description": "Use explicit local task tools when useful."}, map[string]any{"name": "checkpoint", "description": "Record an explicit milestone."}, map[string]any{"name": "finish-task", "description": "Record an agent-declared conclusion."}}}
		return out
	case "prompts/get":
		// P requires verified complete coverage and a committed exposure boundary.
		return rpcError(req, -32000, "prompt_unavailable")
	case "tools/call":
	default:
		return rpcError(req, -32601, "method_not_found")
	}
	if len(req.Params) > 1<<20 {
		return rpcError(req, -32602, "invalid_arguments")
	}
	raw := params
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if ipc.DecodeStrict(raw, &p) != nil {
		return rpcError(req, -32602, "invalid_arguments")
	}
	_, e = arguments(p.Name, p.Arguments)
	if e != nil {
		if e.Error() == "unsupported_tool" || errors.Is(e, errFilter) {
			out.Result = result(e.Error(), true)
			return out
		}
		return rpcError(req, -32602, "invalid_arguments")
	}
	if b.disclosure != nil {
		if !daemon.ValidRPCID(req.ID) {
			return rpcError(daemon.Request{ID: json.RawMessage("null")}, -32602, "invalid_identity")
		}
		out.Result = b.disclosure.call(ctx, h, m, req, p.Name, p.Arguments)
		return out
	}
	out.Result = result("store_unavailable", true)
	return out
}
func emptyParams(raw []byte) bool {
	if len(raw) == 0 {
		return true
	}
	b, err := jcs.Canonicalize(raw)
	return err == nil && string(b) == "{}"
}
