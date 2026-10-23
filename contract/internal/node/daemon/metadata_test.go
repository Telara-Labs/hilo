package daemon

import (
	"encoding/json"
	"testing"
)

func TestModernProtocolMetadataRequiredBeforeDispatch(t *testing.T) {
	for _, meta := range []string{
		``, `"_meta":{}`, `"_meta":{"example.com/trace":true}`,
		`"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}`,
		`"_meta":{"io.modelcontextprotocol/clientInfo":{"name":"fixture"}}`,
		`"_meta":{"io.modelcontextprotocol/protocolVersion":null,"io.modelcontextprotocol/clientCapabilities":{}}`,
		`"_meta":{"io.modelcontextprotocol/protocolVersion":42,"io.modelcontextprotocol/clientCapabilities":{}}`,
	} {
		r, ok := Setup(Request{Method: "server/discover", Params: json.RawMessage(`{` + meta + `}`)})
		if !ok || r.Error == nil || r.Error.Code != -32602 || r.Result != nil {
			t.Fatalf("discovery accepted missing/malformed required metadata %s %+v", meta, r)
		}
	}
	for _, caps := range []string{
		``, `null`, `42`, `true`, `"caps"`, `[]`,
		`{"roots":null}`, `{"roots":false}`, `{"sampling":[]}`,
		`{"sampling":{"context":false}}`, `{"sampling":{"tools":null}}`,
		`{"elicitation":false}`, `{"elicitation":{"form":[]}}`, `{"elicitation":{"url":1}}`,
		`{"experimental":[]}`, `{"experimental":{"test":true}}`,
		`{"extensions":null}`, `{"extensions":{"com.example/test":"settings"}}`,
	} {
		meta := `"io.modelcontextprotocol/protocolVersion":"2026-07-28"`
		if caps != "" {
			meta += `,"io.modelcontextprotocol/clientCapabilities":` + caps
		}
		for _, method := range []string{"initialize", "server/discover", "tools/list", "ping", "prompts/list", "resources/list", "tools/call", "unknown/method"} {
			r, ok := Setup(Request{Method: method, Params: json.RawMessage(`{"_meta":{` + meta + `}}`)})
			if !ok || r.Error == nil || r.Error.Code != -32602 || r.Result != nil {
				t.Fatalf("malformed capabilities escaped predispatch validation %s %s %+v", method, caps, r)
			}
		}
	}
}

func TestModernCapabilitiesShapeAndLegacyCompatibility(t *testing.T) {
	for _, caps := range []string{
		`{}`,
		`{"roots":{},"sampling":{"context":{},"tools":{}},"elicitation":{"form":{},"url":{}},"experimental":{"test":{"enabled":true}},"extensions":{"com.example/test":{"types":["text"]}}}`,
		`{"example.com/future":{"arbitrary":[null,1,true]},"sampling":{"future":true}}`,
	} {
		r, ok := Setup(Request{Method: "server/discover", Params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":` + caps + `,"example.com/trace":null,"com.telara/unknown":[true]}}`)})
		if !ok || r.Error != nil || r.Result == nil {
			t.Fatalf("valid modern metadata rejected %s %+v", caps, r)
		}
	}
	for _, params := range []string{
		`{}`, `{"_meta":{"example.com/trace":null}}`,
		`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}`,
		`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-03-26","io.modelcontextprotocol/clientCapabilities":null}}`,
	} {
		for _, method := range []string{"initialize", "tools/list", "ping"} {
			r, ok := Setup(Request{Method: method, Params: json.RawMessage(params)})
			if !ok || r.Error != nil || r.Result == nil {
				t.Fatalf("legacy compatibility changed %s %s %+v", method, params, r)
			}
		}
	}
	// A version-less request with modern protocol fields cannot be downgraded to
	// a legacy data call merely because discovery was skipped.
	for _, field := range []string{`"io.modelcontextprotocol/clientCapabilities":{}`, `"io.modelcontextprotocol/clientInfo":{}`} {
		r, ok := Setup(Request{Method: "tools/call", Params: json.RawMessage(`{"_meta":{` + field + `}}`)})
		if !ok || r.Error == nil || r.Error.Code != -32602 {
			t.Fatal("modern request without version downgraded to legacy")
		}
	}
}
