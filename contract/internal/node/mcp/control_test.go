package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
)

func TestOwnerControlFailsClosedWithoutStore(t *testing.T) {
	b, err := Open(context.Background(), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, method := range []string{"erase", "scrub"} {
		out, handled := b.Control(context.Background(), daemon.Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: method, Params: json.RawMessage(`{}`)})
		if !handled || out.Error == nil || out.Error.Message != "store_unavailable" {
			t.Fatal(method, out)
		}
	}
	if _, handled := b.Control(context.Background(), daemon.Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call"}); handled {
		t.Fatal("control claimed a non-owner method")
	}
}
