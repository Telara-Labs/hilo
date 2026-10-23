package daemon

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcpcatalog"
)

func TestParse(t *testing.T) {
	for _, s := range []string{`{}`, `{"jsonrpc":"2.0","method":"x","id":{}}`, `{"jsonrpc":"2.0","method":"x","id":true}`, `{"jsonrpc":"2.0","method":"x","id":null}`} {
		if _, e := Parse([]byte(s)); e == nil {
			t.Fatal("accepted invalid request")
		}
	}
	// Correlation IDs are opaque, even when they resemble credentials or contain
	// characters that are forbidden in installed/native identity. Bound by frame.
	secret, _ := json.Marshal("ghp_" + strings.Repeat("a", 36))
	for _, id := range []string{`1`, `"a"`, `1.5`, `""`, string(secret), `"\u202e\n"`, `"` + strings.Repeat("b", 1024) + `"`} {
		r, e := Parse([]byte(`{"jsonrpc":"2.0","method":"x","id":` + id + `}`))
		var got, want any
		_ = json.Unmarshal(r.ID, &got)
		_ = json.Unmarshal([]byte(id), &want)
		if e != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("opaque request ID rejected or changed")
		}
	}
}

func TestSetupAndErrors(t *testing.T) {
	for _, method := range []string{"initialize", "tools/list", "ping"} {
		out, ok := Setup(Request{Method: method, ID: json.RawMessage("1")})
		if !ok || out.Error != nil || out.Result == nil || string(out.ID) != "1" {
			t.Fatal(method)
		}
		if method == "tools/list" && !reflect.DeepEqual(out.Result.(map[string]any)["tools"], mcpcatalog.Tools()) {
			t.Fatal("catalog mismatch")
		}
		if method == "ping" && len(out.Result.(map[string]any)) != 0 {
			t.Fatal("nonempty ping")
		}
	}
	if _, ok := Setup(Request{Method: "write"}); ok {
		t.Fatal("unknown setup")
	}
	if string(Error(nil, "busy").ID) != "null" {
		t.Fatal("null id")
	}
	for _, params := range []string{`{"cursor":"x"}`, `null`, `[]`, `{"unknown":true}`, `{"a":1,"a":2}`} {
		out, ok := Setup(Request{Method: "tools/list", Params: json.RawMessage(params)})
		if !ok || out.Error == nil || out.Error.Code != -32602 {
			t.Fatal("ignored catalog restriction")
		}
	}
}

func TestProtocolNegotiation(t *testing.T) {
	for _, proposal := range []string{"2024-11-05", "2025-03-26", "2025-06-18", "2026-07-28", "2025-11-25", "2099-01-01", "unknown", "2020-01-01", ""} {
		t.Run(proposal, func(t *testing.T) {
			params, _ := json.Marshal(map[string]any{"protocolVersion": proposal, "clientInfo": map[string]string{"name": "fixture"}, "capabilities": map[string]any{}})
			out, ok := Setup(Request{Method: "initialize", Params: params, ID: json.RawMessage("1")})
			if !ok || out.Error != nil {
				t.Fatal("initialize refused proposal")
			}
			want := proposal
			if proposal != "2024-11-05" && proposal != "2025-03-26" && proposal != "2025-06-18" {
				want = LatestLegacyProtocolVersion
			}
			if out.Result.(map[string]any)["protocolVersion"] != want {
				t.Fatal("incorrect negotiated version")
			}
		})
	}
}

func TestProtocolAndIdentityValidation(t *testing.T) {
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":1,"id":2,"method":"x"}`,
		`{"jsonrpc":"2.0","id":1,"method":"x","extra":1}`,
		`{"jsonrpc":"2.0","id":"\ud800","method":"x"}`,
	} {
		if _, e := Parse([]byte(raw)); e == nil {
			t.Fatal("malformed envelope accepted")
		}
	}
	for _, p := range []string{`{"protocolVersion":1}`, `[]`, `{`} {
		out, ok := Setup(Request{Method: "initialize", Params: json.RawMessage(p), ID: json.RawMessage("1")})
		if !ok || out.Error == nil || out.Error.Code != -32602 {
			t.Fatal("malformed initialize accepted")
		}
	}
	out, _ := Setup(Request{Method: "initialize"})
	if len(out.Result.(map[string]any)["instructions"].(string)) >= 600 {
		t.Fatal("instructions oversized")
	}
	if storeWired(nil) {
		t.Fatal("unwired store")
	}
}

func TestReadinessRequiresSuccessfulBoundPeerStatus(t *testing.T) {
	good := Response{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: map[string]any{"state": "running", "pid": float64(42), "resultType": "complete"}}
	if !validStatus(good, 42) {
		t.Fatal("valid status refused")
	}
	for _, out := range []Response{
		{JSONRPC: "2.0", ID: json.RawMessage("1"), Error: &RPCError{Message: "unsupported_control"}},
		{JSONRPC: "2.0", ID: json.RawMessage("2"), Result: good.Result},
		{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: map[string]any{"state": "running", "pid": float64(43), "resultType": "complete"}},
		{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: map[string]any{"state": "stopped", "pid": float64(42), "resultType": "complete"}},
		{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: map[string]any{"state": "running", "pid": float64(42)}},
		{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: "running"},
		{JSONRPC: "1.0", ID: json.RawMessage("1"), Result: good.Result},
	} {
		if validStatus(out, 42) {
			t.Fatal("unproven status accepted")
		}
	}
}
