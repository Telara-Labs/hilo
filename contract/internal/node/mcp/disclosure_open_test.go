package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

type failingRuntimeProvider struct {
	runtime Runtime
	err     error
}

func (p failingRuntimeProvider) Load(context.Context) (Runtime, error) { return p.runtime, p.err }
func TestDisclosureOpenFailsClosedWithoutAuthority(t *testing.T) {
	b, err := Open(context.Background(), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if b.StoreWired() {
		t.Fatal("missing authority wired")
	}
	req := daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: json.RawMessage(`{"name":"telara_task_create","arguments":{"goal":"unprovisioned"}}`)}
	out := b.Handle(context.Background(), ipc.Hello{Client: "forged"}, req)
	r, ok := out.Result.(Result)
	if !ok || !r.IsError || r.Content[0].Text != "runtime_authority_unavailable" {
		t.Fatal(out)
	}
	if b.Close() != nil || b.Close() != nil {
		t.Fatal("close not idempotent")
	}
	for _, provider := range []RuntimeProvider{failingRuntimeProvider{err: errors.New("secret error")}, failingRuntimeProvider{}} {
		if _, err := Open(context.Background(), t.TempDir(), provider); err == nil || err.Error() != "runtime_authority_unavailable" {
			t.Fatal(err)
		}
	}
}
func TestDisclosureDirectCallsCannotClaimDaemonIdentity(t *testing.T) {
	b := NewDisclosure(nil, nil, nil)
	b.disclosure.service = nil
	if got := b.disclosure.call(context.Background(), ipc.Hello{Client: "claimed"}, Metadata{}, daemon.Request{}, "telara_task_create", json.RawMessage(`{"goal":"x"}`)); !got.IsError {
		t.Fatal(got)
	}
	// Closing the underlying store must be retried on failure, as required by
	// daemon lock handoff. No success is cached before actual settlement.
	attempts := 0
	b = NewDisclosure(nil, nil, func() error {
		attempts++
		if attempts == 1 {
			return errors.New("busy")
		}
		return nil
	})
	if b.Close() == nil || b.Close() != nil || attempts != 2 {
		t.Fatal(attempts)
	}
}

func TestReadinessNeverWaitsForDisclosureWriter(t *testing.T) {
	b := NewDisclosure(nil, nil, nil)
	b.disclosure.mu.Lock()
	done := make(chan bool, 1)
	go func() { done <- b.StoreWired() }()
	select {
	case ready := <-done:
		if ready {
			t.Error("unavailable store wired")
		}
	case <-time.After(time.Second):
		t.Error("readiness waits for writer")
	}
	b.disclosure.mu.Unlock()
}
