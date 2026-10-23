package mcp_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp/internal/teststore"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

func modernCreate4(meta map[string]any) daemon.Request {
	if meta == nil {
		meta = map[string]any{}
	}
	meta["io.modelcontextprotocol/protocolVersion"] = daemon.LatestProtocolVersion
	meta["io.modelcontextprotocol/clientCapabilities"] = map[string]any{}
	raw, _ := json.Marshal(map[string]any{"name": "telara_task_create", "arguments": map[string]string{"goal": "Independent conversation"}, "_meta": meta})
	return daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: raw}
}

func TestModernNativeResolutionRemainsFresh(t *testing.T) {
	p := ipc.Proc{PID: 123, StartMS: 1000}
	source := &teststore.Source{Access: teststore.Access()}
	r := mcp.IdentityResolver{Source: source, LegacySupported: true}
	h := ipc.Hello{Shim: "shared", Ancestry: []ipc.Proc{p}}
	meta := mcp.Metadata{ProtocolVersion: daemon.LatestProtocolVersion, Legacy: "ignored"}
	var previous string
	for _, id := range []string{"first", "second"} {
		n := native(id)
		source.Signals = []mcp.Announcement{{Native: n, Ancestor: p}}
		a, err := r.Resolve(context.Background(), h, meta)
		if err != nil || a.SessionKey == "" || a.SessionKey == previous || a.ScopeID != a.SessionKey || a.Confidence != "process-matched" {
			t.Fatal("fresh native announcement lost", a, err)
		}
		previous = a.SessionKey
	}
	n := native("explicit")
	meta.Native, meta.Handle = &n, "handle"
	a, err := r.Resolve(context.Background(), h, meta)
	if err != nil || a.ScopeID != record.H("handle", teststore.Access().CredentialID, "handle") || a.Confidence != "stated" || !a.Disagreement {
		t.Fatal("explicit native/handle precedence lost", a, err)
	}
	meta.Native, meta.Handle = nil, ""
	source.Signals = nil // A still-writing hook is not a completed announcement.
	a, err = r.Resolve(context.Background(), h, meta)
	if err != nil || a.ScopeID != "" || a.SessionKey != "" || a.Confidence != "" {
		t.Fatal("modern hook gap restored old process scope", a, err)
	}
	source.Signals = []mcp.Announcement{{Native: native("first"), Ancestor: p}, {Native: native("second"), Ancestor: p}}
	a, err = r.Resolve(context.Background(), h, meta)
	if err != nil || !a.Ambiguous || a.ScopeID != "" || a.SessionKey != "" {
		t.Fatal("ambiguous modern native announcements restored process scope", a, err)
	}
	source.Signals = nil
	// Legacy callers still retain the documented fallback.
	a, err = r.Resolve(context.Background(), h, mcp.Metadata{})
	if err != nil || a.ScopeID != record.H("shim", teststore.Access().CredentialID, "shared") || a.Confidence != "inferred" {
		t.Fatal("legacy shim fallback changed", a, err)
	}
}

type countingResolver4 struct{ calls int }

func (r *countingResolver4) Resolve(context.Context, ipc.Hello, mcp.Metadata) (mcp.Access, error) {
	r.calls++
	return teststore.Access(), nil
}

func TestMalformedModernMetadataDoesNotReachResolverOrStore(t *testing.T) {
	s := teststore.New()
	r := &countingResolver4{}
	b := mcp.New(s, r)
	for _, meta := range []string{
		`{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`,
		`{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":null}`,
		`{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":42}`,
		`{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"sampling":{"tools":false}}}`,
		`{"io.modelcontextprotocol/clientCapabilities":{}}`,
	} {
		params := json.RawMessage(`{"name":"telara_task_create","arguments":{"goal":"Must not execute"},"_meta":` + meta + `}`)
		out := b.Handle(context.Background(), ipc.Hello{Shim: "shared"}, daemon.Request{ID: json.RawMessage(`1`), Method: "tools/call", Params: params})
		if out.Error == nil || out.Error.Code != -32602 || out.Result != nil {
			t.Fatal("invalid metadata dispatched")
		}
	}
	calls, _ := s.Audit()
	_, mutations, _ := s.Snapshot()
	if r.calls != 0 || len(calls) != 0 || mutations != 0 {
		t.Fatal("invalid modern metadata reached resolver/store")
	}
}
