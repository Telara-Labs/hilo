package daemon

import (
	"encoding/json"
	"testing"
)

func TestParse(t *testing.T) {
	for _, s := range []string{`{}`, `{"jsonrpc":"2.0","method":"x","id":{}}`, `{"jsonrpc":"2.0","method":"x","id":true}`, `{"jsonrpc":"2.0","method":"x","id":null}`} {
		if _, e := Parse([]byte(s)); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	for _, id := range []string{`1`, `"a"`, `1.5`} {
		r, e := Parse([]byte(`{"jsonrpc":"2.0","method":"x","id":` + id + `}`))
		if e != nil || string(r.ID) != id {
			t.Fatalf("request %v", e)
		}
	}
}
func TestSetupAndErrors(t *testing.T) {
	for _, method := range []string{"initialize", "tools/list"} {
		out, ok := Setup(Request{Method: method, ID: json.RawMessage("1")})
		if !ok || out.Result == nil {
			t.Fatal(method)
		}
	}
	if _, ok := Setup(Request{Method: "write"}); ok {
		t.Fatal("unknown setup")
	}
	if string(Error(nil, "busy").ID) != "null" {
		t.Fatal("null id")
	}
}
