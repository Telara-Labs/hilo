package daemon

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestModernDiscoveryAndMetadata(t *testing.T) {
	for _, version := range []string{"2024-11-05", "2025-03-26", "2025-06-18", "2026-07-28"} {
		for _, method := range []string{"server/discover", "tools/list", "ping"} {
			t.Run(version+method, func(t *testing.T) {
				params := json.RawMessage(fmt.Sprintf(`{"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientInfo":{"name":"untrusted"},"io.modelcontextprotocol/clientCapabilities":{"tools":{}},"com.telara/conversation":"chat-1","progressToken":"p","example.com/trace-id":{"nested":[null,42]}}}`, version))
				out, ok := Setup(Request{ID: json.RawMessage(`9007199254740993`), Method: method, Params: params})
				if !ok || out.Error != nil {
					t.Fatalf("setup failed %+v", out)
				}
				raw, e := json.Marshal(out)
				if e != nil {
					t.Fatal(e)
				}
				var wire struct {
					ID     json.RawMessage            `json:"id"`
					Result map[string]json.RawMessage `json:"result"`
				}
				if json.Unmarshal(raw, &wire) != nil || string(wire.ID) != "9007199254740993" || string(wire.Result["resultType"]) != `"complete"` {
					t.Fatalf("invalid modern wire %s", raw)
				}
				if method != "ping" && (len(wire.Result["ttlMs"]) == 0 || len(wire.Result["cacheScope"]) == 0) {
					t.Fatal("missing cache hints")
				}
				if method == "server/discover" {
					var versions []string
					_ = json.Unmarshal(wire.Result["supportedVersions"], &versions)
					if len(versions) != 4 || versions[0] != "2026-07-28" {
						t.Fatal(versions)
					}
					if !strings.Contains(string(wire.Result["_meta"]), "io.modelcontextprotocol/serverInfo") {
						t.Fatal("missing server identity")
					}
				}
			})
		}
	}
	unsupported, _ := Setup(Request{Method: "ping", Params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}`)})
	if unsupported.Error == nil || unsupported.Error.Code != -32022 || unsupported.Error.Data == nil {
		t.Fatal("unsupported request lacks retry versions")
	}
}

func TestMetadataIdentityStrictAndUnrelatedIgnored(t *testing.T) {
	for _, bad := range []string{
		`null`, `[]`, `{"com.telara/conversation":null}`, `{"com.telara/conversation":42}`, `{"com.telara/conversation":""}`, `{"com.telara/conversation":"a/b"}`,
		`{"com.telara/conversation":"ghp_` + strings.Repeat("a", 36) + `"}`,
		`{"com.telara/conversation":"a","com.telara/conversation-handle":"b"}`, `{"com.telara/op-id":false}`, `{"com.telara/legacy-session-id":"bad space"}`,
		`{"com.telara/native":{"client":"ok","id":"x","kind":"local","origin":"local","admin":true}}`,
		`{"com.telara/native":{"client":"ok","id":"x","kind":"global","origin":"local"}}`,
		`{"com.telara/native":{"Client":"fixture","id":"x","kind":"local","origin":"local"}}`, `{"progressToken":{}}`,
		`{"io.modelcontextprotocol/protocolVersion":null}`, `{"io.modelcontextprotocol/protocolVersion":"2026-99-99"}`,
	} {
		for _, method := range []string{"server/discover", "tools/list", "prompts/list", "resources/list", "tools/call", "ping"} {
			out, handled := Setup(Request{Method: method, Params: json.RawMessage(`{"_meta":` + bad + `}`)})
			if !handled || out.Error == nil || out.Error.Code != -32602 {
				t.Fatalf("invalid identity accepted %s %s", method, bad)
			}
		}
	}
	for _, raw := range []string{`{"com.telara/conversation":"same","com.telara/conversation-handle":"same"}`, `{"com.telara/conversation-handle":"legacy"}`, `{"example.com/trace-id":null,"clientInfo":{"owner":"attacker"},"com.telara/unknown":{"admin":true}}`} {
		_, m, e := RequestParams([]byte(`{"_meta":` + raw + `}`))
		if e != nil {
			t.Fatal(e)
		}
		encoded, _ := json.Marshal(m)
		if strings.Contains(string(encoded), "attacker") || strings.Contains(string(encoded), "admin") || strings.Contains(string(encoded), "trace-id") {
			t.Fatal("unrelated metadata retained")
		}
	}
}

func TestLosslessEnvelopeIDs(t *testing.T) {
	for _, id := range []string{`9007199254740992`, `9007199254740993`, `18446744073709551617`, `-9007199254740993`, `1.00000000000000001`, `1e400`, `"\\u0061"`} {
		r, e := Parse([]byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"ping"}`))
		if e != nil || string(r.ID) != id {
			t.Fatalf("id changed %s -> %s (%v)", id, r.ID, e)
		}
		raw, _ := json.Marshal(Response{JSONRPC: "2.0", ID: r.ID, Result: map[string]any{}})
		var out struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(raw, &out)
		if string(out.ID) != id {
			t.Fatalf("response id changed %s", raw)
		}
	}
	for _, raw := range []string{
		`{"jsonrpc":"2.0","method":"ping","id":1,"params":{"x":1,"x":2}}`,
		`{"jsonrpc":"2.0","method":"ping","id":1,"params":{"\u0078":1,"x":2}}`,
		`{"jsonrpc":"2.0","method":"ping","id":"\ud800"}`,
		`{"jsonrpc":"2.0","method":"ping","id":1} {}`,
		`{"jsonrpc":"2.0","method":"ping","params":` + strings.Repeat("[", 65) + `0` + strings.Repeat("]", 65) + `}`,
	} {
		if _, e := Parse([]byte(raw)); e == nil {
			t.Fatal("malformed envelope accepted")
		}
	}
}
func TestResultTypeDefaultPreservesExplicitAndErrors(t *testing.T) {
	for _, r := range []Response{
		{Result: map[string]any{"resultType": "partial"}},
		{Result: map[string]any{"resultType": ""}},
		{Result: map[string]any{"resultType": nil}},
		Error(json.RawMessage(`1`), "refused"),
	} {
		raw, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		if r.Error != nil && strings.Contains(string(raw), "resultType") {
			t.Fatal("error gained a result")
		}
		if r.Error == nil && !strings.Contains(string(raw), `"resultType":"complete"`) && !strings.Contains(string(raw), `"resultType":"partial"`) {
			t.Fatal(string(raw))
		}
	}
}
