package daemon

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCancellationParsing(t *testing.T) {
	for _, tc := range []struct {
		params string
		want   bool
	}{
		{`{"requestId":9007199254740993}`, true},
		{`{"requestId":"opaque","reason":"stop","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`, true},
		{`{}`, false}, {`null`, false}, {`{"requestId":null}`, false}, {`{"requestId":true}`, false},
		{`{"requestId":1,"requestId":2}`, false}, {`{"requestId":1,"reason":42}`, false},
		{`{"requestId":"\ud800"}`, false},
	} {
		r := Request{JSONRPC: "2.0", Method: "notifications/cancelled", Params: json.RawMessage(tc.params)}
		_, ok := CancellationID(r)
		if ok != tc.want {
			t.Fatalf("cancellation %s accepted=%v", tc.params, ok)
		}
		r.ID = json.RawMessage(`1`)
		if _, ok := CancellationID(r); ok {
			t.Fatal("request mistaken for notification")
		}
		r.ID = nil
		r.Method = "notifications/initialized"
		if _, ok := CancellationID(r); ok {
			t.Fatal("unrelated notification cancelled work")
		}
	}
}
func TestInflightCancellationIsolationAndReuse(t *testing.T) {
	var pending Inflight
	a, ok := pending.Begin(context.Background(), json.RawMessage(`9007199254740993`))
	if !ok {
		t.Fatal("begin")
	}
	b, ok := pending.Begin(context.Background(), json.RawMessage(`"9007199254740993"`))
	if !ok {
		t.Fatal("string ID aliased numeric")
	}
	if _, ok := pending.Begin(context.Background(), json.RawMessage(`9007199254740993.0`)); ok {
		t.Fatal("duplicate active exact decimal ID admitted")
	}
	pending.Cancel(json.RawMessage(`9007199254740992`))
	if a.Context.Err() != nil || b.Context.Err() != nil {
		t.Fatal("unknown ID cancelled work")
	}
	pending.Cancel(json.RawMessage(`9007199254740993e0`))
	if a.Context.Err() != context.Canceled || b.Context.Err() != nil {
		t.Fatal("exact cancellation crossed requests")
	}
	emitted := 0
	a.Reply(func() { emitted++ })
	b.Reply(func() { emitted++ })
	if emitted != 1 {
		t.Fatal("cancelled reply escaped or sibling suppressed")
	}
	// A reply frees its correlation atomically before the old goroutine unwinds.
	replacement, ok := pending.Begin(context.Background(), json.RawMessage(`9007199254740993`))
	if !ok {
		t.Fatal("reply did not free id")
	}
	a.Finish()
	pending.Cancel(json.RawMessage(`9007199254740993`))
	if replacement.Context.Err() != context.Canceled {
		t.Fatal("old completion removed newer call")
	}
	replacement.Finish()
	b.Finish()
	c, ok := pending.Begin(context.Background(), json.RawMessage(`"\u0061"`))
	if !ok {
		t.Fatal("begin escaped")
	}
	pending.Cancel(json.RawMessage(`"a"`))
	if c.Context.Err() != context.Canceled {
		t.Fatal("escaped string failed correlation")
	}
	c.Finish()
}
func TestForwardedCorrelationPrivateToIPC(t *testing.T) {
	for _, id := range []string{`"secret-looking"`, `9007199254740993`, `1e400`} {
		r := Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", OriginalID: json.RawMessage(`"not-on-wire"`)}
		raw, e := json.Marshal(ForwardedRequest{Request: r, ClientRequestID: json.RawMessage(id)})
		if e != nil {
			t.Fatal(e)
		}
		if _, e := Parse(raw); e == nil {
			t.Fatal("stdio accepted private correlation override")
		}
		got, e := parseForwarded(raw)
		if e != nil || string(got.ID) != "1" || string(got.CorrelationID()) != id {
			t.Fatal("IPC correlation lost", e)
		}
		plain, _ := json.Marshal(got)
		parsed, e := Parse(plain)
		if e != nil || string(parsed.CorrelationID()) != "1" {
			t.Fatal("original correlation leaked onto ordinary RPC")
		}
	}
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"x","client_request_id":null}`,
		`{"jsonrpc":"2.0","id":1,"method":"x","client_request_id":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","client_request_id":1}`,
		`{"jsonrpc":"2.0","id":1,"method":"x","client_request_id":1,"client_request_id":2}`,
		`{"jsonrpc":"2.0","id":true,"method":"x"}`,
		`{"jsonrpc":"1.0","id":1,"method":"x"}`,
		`{"jsonrpc":"2.0","id":1,"method":"x","extra":1}`,
	} {
		if _, e := parseForwarded([]byte(raw)); e == nil {
			t.Fatal("invalid IPC accepted", raw)
		}
	}
	raw := []byte(`{"jsonrpc":"2.0","id":9007199254740993,"method":"ping"}`)
	r, e := parseForwarded(raw)
	if e != nil || string(r.CorrelationID()) != "9007199254740993" {
		t.Fatal("direct IPC correlation changed")
	}
}
