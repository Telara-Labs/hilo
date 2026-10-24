//go:build darwin || linux

package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

func (w *adapterWorld) ipcSession() (net.Conn, *bufio.Reader) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := ipc.Dial(ctx, w.paths)
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { c.Close() })
	if err = c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		w.t.Fatal(err)
	}
	if err = ipc.WriteFrame(c, ipc.Hello{T: "hello", V: ipc.WireVersion, Kind: "mcp", PID: os.Getpid(), Client: "quota-test"}); err != nil {
		w.t.Fatal(err)
	}
	r := bufio.NewReader(c)
	if _, err = ipc.ReadFrame(r); err != nil {
		w.t.Fatal(err)
	}
	return c, r
}
func quotaRequest(id int, token string) any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": "telara_task_list", "arguments": map[string]any{}, "_meta": Metadata{Handle: "same-conversation", OpID: token}}}
}
func (w *adapterWorld) waitConnections(n int) {
	w.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a := w.backend.disclosure
		a.mu.Lock()
		count := len(a.connections)
		a.mu.Unlock()
		if count == n {
			return
		}
		if time.Now().After(deadline) {
			w.t.Fatalf("cached transports %d, want %d", count, n)
		}
		time.Sleep(time.Millisecond)
	}
}
func TestDisclosureDisconnectedTransportsReclaimQuota(t *testing.T) {
	w := newAdapterWorld(t)
	w.start()
	token := w.operation("quota-replay")
	for i := 0; i < 129; i++ {
		c, r := w.ipcSession()
		if err := ipc.WriteFrame(c, quotaRequest(1, token)); err != nil {
			t.Fatal(err)
		}
		raw, err := ipc.ReadFrame(r)
		if err != nil {
			t.Fatal(err)
		}
		var response struct {
			Result Result           `json:"result"`
			Error  *daemon.RPCError `json:"error"`
		}
		if json.Unmarshal(raw, &response) != nil || response.Error != nil || response.Result.IsError {
			t.Fatalf("transport %d failed %s", i+1, raw)
		}
		c.Close()
		w.waitConnections(0)
	}
	if n := w.count("SELECT count(*) FROM operation"); n != 1 {
		t.Fatalf("retry duplicated %d operations", n)
	}
}
func TestDisclosureUnidentifiedScopesReclaimDurableQuota(t *testing.T) {
	w := newAdapterWorld(t)
	w.start()
	for i := 0; i < 4096; i++ {
		proof, err := w.Proof(context.Background(), ipc.Hello{})
		if err != nil {
			t.Fatal(err)
		}
		c, err := w.backend.disclosure.service.Authenticate(context.Background(), proof)
		clear(proof.Token)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = c.Resolve(context.Background(), disclosure.IdentityInput{}); err != nil {
			t.Fatalf("scope %d %v", i, err)
		}
		if err = c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if n := w.count("SELECT count(*) FROM local_scope WHERE identity_kind='connection'"); n != 0 {
		t.Fatalf("retired connection scopes %d", n)
	}
	s := w.session()
	goodText(t, s.callMeta("telara_task_list", map[string]any{}, Metadata{ProtocolVersion: daemon.LatestProtocolVersion}))
	// Early refusal happens after Authenticate but before Resolve. Each owned
	// ephemeral handle and its transport callback must also be reclaimed.
	for i := 0; i < 129; i++ {
		got := s.callMeta("telara_task_list", map[string]any{}, Metadata{ProtocolVersion: daemon.LatestProtocolVersion, Native: &Native{Client: "test", ID: "unverified", Kind: "local", Origin: "local"}})
		if !got.IsError || textOf(t, got) != "scope_resolution_unsupported" {
			t.Fatal(got)
		}
	}
	goodText(t, s.callMeta("telara_task_list", map[string]any{}, Metadata{ProtocolVersion: daemon.LatestProtocolVersion}))
	w.waitConnections(0)
	if n := w.count("SELECT count(*) FROM local_scope WHERE identity_kind='connection'"); n != 0 {
		t.Fatalf("unidentified retained %d scopes", n)
	}
}

type canceledProof struct {
	entered  chan struct{}
	finished chan struct{}
}

func (p canceledProof) Proof(ctx context.Context, h ipc.Hello) (disclosure.CredentialProof, error) {
	close(p.entered)
	if p.finished != nil {
		defer close(p.finished)
	}
	<-ctx.Done()
	return disclosure.CredentialProof{}, ctx.Err()
}
func TestDisclosureDisconnectDrainsCallBeforeCacheRetirement(t *testing.T) {
	w := newAdapterWorld(t)
	w.start()
	token := w.operation("cancel-replay")
	c, r := w.ipcSession()
	if err := ipc.WriteFrame(c, quotaRequest(1, token)); err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.ReadFrame(r); err != nil {
		t.Fatal(err)
	}
	w.waitConnections(1)
	a := w.backend.disclosure
	entered := make(chan struct{})
	a.mu.Lock()
	a.source = canceledProof{entered: entered}
	a.mu.Unlock()
	if err := ipc.WriteFrame(c, quotaRequest(2, token)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("call not admitted")
	}
	c.Close() // daemon cancels the in-flight proof, drains, then calls cleanup.
	w.waitConnections(0)
	a.mu.Lock()
	a.source = w
	a.mu.Unlock()
	goodText(t, w.session().call("telara_task_list", map[string]any{}, "cancel-replay", "same-conversation"))
	if n := w.count("SELECT count(*) FROM operation"); n != 1 {
		t.Fatalf("canceled replay remutated %d", n)
	}
}

func TestDisclosureRequestCancellationPreservesLiveRetryIdentity(t *testing.T) {
	w := newAdapterWorld(t)
	w.start()
	token := w.operation("live-cancel")
	c, r := w.ipcSession()
	if err := ipc.WriteFrame(c, quotaRequest(1, token)); err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.ReadFrame(r); err != nil {
		t.Fatal(err)
	}
	entered, finished := make(chan struct{}), make(chan struct{})
	a := w.backend.disclosure
	a.mu.Lock()
	a.source = canceledProof{entered: entered, finished: finished}
	a.mu.Unlock()
	if err := ipc.WriteFrame(c, quotaRequest(2, token)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("call not admitted")
	}
	if err := ipc.WriteFrame(c, map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": 2}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("call not canceled")
	}
	a.mu.Lock()
	a.source = w
	a.mu.Unlock()
	w.waitConnections(1)
	if err := ipc.WriteFrame(c, quotaRequest(3, token)); err != nil {
		t.Fatal(err)
	}
	raw, err := ipc.ReadFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		ID     int    `json:"id"`
		Result Result `json:"result"`
	}
	if json.Unmarshal(raw, &response) != nil || response.ID != 3 || response.Result.IsError {
		t.Fatalf("live retry failed %s", raw)
	}
	if n := w.count("SELECT count(*) FROM operation"); n != 1 {
		t.Fatal("cancellation remutated", n)
	}
	c.Close()
	w.waitConnections(0)
}
