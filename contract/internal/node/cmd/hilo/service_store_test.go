package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/mcp"
)

func TestProductionOpenerRequiresInstalledAuthority(t *testing.T) {
	backend, err := existingOpener(t.TempDir(), nil)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	wired, ok := backend.(interface{ StoreWired() bool })
	if !ok || wired.StoreWired() {
		t.Fatal("unprovisioned authority claims readiness")
	}
	response := backend.Handle(context.Background(), ipc.Hello{}, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: json.RawMessage(`{"name":"telara_task_create","arguments":{"goal":"no authority"}}`)})
	result, ok := response.Result.(mcp.Result)
	if response.Error != nil || !ok || !result.IsError || len(result.Content) != 1 || result.Content[0].Text != "runtime_authority_unavailable" {
		t.Fatal(response)
	}
}
