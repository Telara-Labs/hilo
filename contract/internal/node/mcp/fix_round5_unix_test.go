//go:build darwin || linux

package mcp_test

import (
	"encoding/json"
	"os"
	"syscall"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	mcp "github.com/Telara-Labs/hilo/contract/internal/node/mcp/internal/fixture"
	"github.com/Telara-Labs/hilo/contract/internal/node/mcp/internal/teststore"
	"github.com/Telara-Labs/hilo/contract/record"
)

// Two live native announcements on one shim ancestor make the legacy shim scope
// ambiguous. Use real shim/daemon IPC so fallbackOpID receives the daemon's
// connection identity. The injected store/source remain unit-test boundaries.
func TestAmbiguousLegacyScopeDoesNotDeduplicateWrites(t *testing.T) {
	// The shim runs in this test process. Its actual parent is a live ancestor;
	// Read its real start time without launching another process.
	pid := os.Getppid()
	p := ipc.Proc{PID: pid, StartMS: ancestorStart5(t, pid)}
	if err := syscall.Kill(p.PID, 0); err != nil {
		t.Fatal("shim ancestor is not live", err)
	}
	store := teststore.New()
	source := &teststore.Source{Access: teststore.Access()}
	source.Signals = []mcp.Announcement{{Native: native("first"), Ancestor: p}, {Native: native("second"), Ancestor: p}}
	b := mcp.New(store, mcp.IdentityResolver{Source: source, LegacySupported: true})
	observer := &observedBackend{delegate: b, entered: make(chan observedCall, 8)}
	ctx, paths := realDaemon(t, observer)
	h := ipc.Hello{Client: "fixture", Shim: "shared", Ancestry: []ipc.Proc{p}}
	s := realShim(t, ctx, paths, h)
	raw := json.RawMessage(`{"name":"telara_task_create","arguments":{"goal":"Independent conversation"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}`)
	req := daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: raw}
	var connection string
	for i := 0; i < 2; i++ {
		s.send(t, req) // Identical RPC ID and arguments; no handle or op-id.
		assertWireSuccess3(t, s.read(t), `1`)
		entered := entered3(t, observer)
		if entered.connection == "" || (i > 0 && entered.connection != connection) {
			t.Fatal("regression must reuse the same live daemon connection")
		}
		if string(entered.req.CorrelationID()) != `1` {
			t.Fatal("shim changed the original RPC identity")
		}
		connection = entered.connection
	}
	s.finish(t)
	calls, _ := store.Audit()
	rows, mutations, _ := store.Snapshot()
	if len(calls) != 2 || mutations != 2 || len(rows) != 2 || source.Drains != 2 {
		t.Fatalf("ambiguous legacy scope reused fallback identity or skipped resolution: calls=%d mutations=%d rows=%d drains=%d", len(calls), mutations, len(rows), source.Drains)
	}
	wantScope := record.H("shim", teststore.Access().CredentialID, h.Shim)
	for _, call := range calls {
		if !call.Access.Ambiguous || call.Access.SessionKey != "" || call.Access.ScopeID != wantScope || call.Access.Confidence != "inferred" {
			t.Fatal("regression did not reach ambiguous legacy shim fallback", call.Access)
		}
	}
	if calls[0].ArgsHash != calls[1].ArgsHash || calls[0].Tool != calls[1].Tool {
		t.Fatal("regression changed tool or arguments between creates")
	}
	if calls[0].Op == calls[1].Op || rows[0].TaskID == rows[1].TaskID {
		t.Fatal("ambiguous conversations shared an operation or task")
	}
}
