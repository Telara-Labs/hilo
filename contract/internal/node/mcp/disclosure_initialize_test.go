//go:build darwin || linux

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// This harness routes ONLY a test method to the real initialize handler with
// real authenticated daemon context. Standard initialize routing is separately
// blocked in unowned shim/daemon Setup and is NOT proven by this test.
type initializeHarness struct{ *Backend }

func (b initializeHarness) Handle(ctx context.Context, h ipc.Hello, r daemon.Request) daemon.Response {
	if r.Method == "test/initialize" {
		r.Method = "initialize"
	}
	return b.Backend.Handle(ctx, h, r)
}
func TestDisclosureInitializeHandlerIssuesOnlyDurableTokens(t *testing.T) {
	w := newAdapterWorld(t)
	w.startWith(func(b *Backend) daemon.Backend { return initializeHarness{b} })
	c, r := w.ipcSession()
	request := daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "test/initialize", Params: json.RawMessage(`{"protocolVersion":"2025-06-18"}`)}
	if err := ipc.WriteFrame(c, request); err != nil {
		t.Fatal(err)
	}
	raw, err := ipc.ReadFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Error  *daemon.RPCError `json:"error"`
		Result struct {
			Meta map[string][]string `json:"_meta"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &response) != nil || response.Error != nil {
		t.Fatalf("initialize handler %s", raw)
	}
	tokens := response.Result.Meta["com.telara/op-ids"]
	if len(tokens) != 8 {
		t.Fatal("not node-issued batch", len(tokens))
	}
	for _, token := range tokens {
		if !record.ValidCallerOpID(token) || w.count("SELECT count(*) FROM operation_token WHERE token=? AND credential=? AND consumed=0", token, w.proof.CredentialID) != 1 {
			t.Fatal("token not durable before reply")
		}
	}
	if n := w.count("SELECT count(*) FROM operation"); n != 0 {
		t.Fatal("initialize created call", n)
	}
	s := w.session()
	meta := Metadata{Handle: "initialized", OpID: tokens[0]}
	goodText(t, s.callMeta("telara_task_create", map[string]any{"goal": "issued token"}, meta))
	goodText(t, s.callMeta("telara_task_create", map[string]any{"goal": "issued token"}, meta))
	if n := w.count("SELECT count(*) FROM operation"); n != 1 {
		t.Fatal("issued replay duplicated", n)
	}
	unissued := s.callMeta("telara_task_create", map[string]any{"goal": "not issued"}, Metadata{Handle: "initialized", OpID: "op1:" + strings.Repeat("f", 32)})
	if !unissued.IsError || textOf(t, unissued) != "unissued_operation" {
		t.Fatal(unissued)
	}
	if n := w.count("SELECT count(*) FROM operation"); n != 1 {
		t.Fatal("unissued token mutated", n)
	}
	w.waitConnections(1)
	w.mu.Lock()
	w.deny = true
	w.mu.Unlock()
	request.ID = json.RawMessage(`2`)
	if err = ipc.WriteFrame(c, request); err != nil {
		t.Fatal(err)
	}
	raw, err = ipc.ReadFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	response.Error = nil
	response.Result.Meta = nil
	if json.Unmarshal(raw, &response) != nil || response.Error == nil || response.Error.Message != "unauthorized" || len(response.Result.Meta) > 0 {
		t.Fatalf("denied initialize %s", raw)
	}
	c.Close()
}
func TestDisclosureInitializeRefusesUnauthenticatedContext(t *testing.T) {
	b := NewDisclosure(nil, nil, nil)
	out := b.Handle(context.Background(), ipc.Hello{}, daemon.Request{Method: "initialize", ID: json.RawMessage(`1`)})
	if out.Error == nil || out.Error.Message != "runtime_authority_unavailable" {
		t.Fatal(out)
	}
	w := newAdapterWorld(t)
	backend, err := Open(context.Background(), w.paths.Data, w)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	out = backend.Handle(context.Background(), ipc.Hello{}, daemon.Request{Method: "initialize", ID: json.RawMessage(`1`)})
	if out.Error == nil || out.Error.Message != "unauthorized" {
		t.Fatal(out)
	}
	if n := w.count("SELECT count(*) FROM operation_token"); n != 0 {
		t.Fatal("untrusted initialize issued", n)
	}
}
