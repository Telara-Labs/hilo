//go:build darwin || linux

package mcp_test

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	mcp "github.com/Telara-Labs/hilo/contract/internal/node/mcp/internal/fixture"
	"github.com/Telara-Labs/hilo/contract/internal/node/mcp/internal/teststore"
	"github.com/Telara-Labs/hilo/contract/record"
)

// Fallback operation identity requires the daemon-generated connection ID. Use
// the shipped shim/daemon over real IPC rather than a bare background context.
// The nonpersistent store remains unit/transport evidence, not SQLite acceptance.
func TestModernSharedShimDoesNotDeduplicateUnidentifiedConversations(t *testing.T) {
	for _, tc := range []struct {
		name string
		meta map[string]any
	}{
		{name: "no_identity"},
		{name: "legacy_identity", meta: map[string]any{"com.telara/legacy-session-id": "old-session"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := teststore.New()
			source := &teststore.Source{Access: teststore.Access()}
			b := mcp.New(store, mcp.IdentityResolver{Source: source, LegacySupported: true})
			observer := &observedBackend{delegate: b, entered: make(chan observedCall, 8)}
			ctx, paths := realDaemon(t, observer)
			s := realShim(t, ctx, paths)
			req := modernCreate4(tc.meta)
			var connection string
			for conversation := 0; conversation < 2; conversation++ {
				s.send(t, req) // Same args and RPC ID, without handle/op ID.
				assertWireSuccess3(t, s.read(t), `1`)
				entered := entered3(t, observer)
				if entered.connection == "" || (conversation > 0 && connection != entered.connection) {
					t.Fatal("regression must reuse the same live daemon connection")
				}
				connection = entered.connection
			}
			s.finish(t)
			calls, _ := store.Audit()
			rows, mutations, _ := store.Snapshot()
			if len(calls) != 2 || len(rows) != 2 || mutations != 2 || rows[0].TaskID == rows[1].TaskID || calls[0].Op == calls[1].Op || source.Drains != 2 {
				t.Fatal("shared shim collapsed unrelated conversations or skipped fresh resolution")
			}
			for _, call := range calls {
				if call.Access.ScopeID != "" || call.Access.SessionKey != "" || call.Access.Confidence != "" {
					t.Fatal("modern request inherited shim/legacy/stale credential continuity")
				}
			}
		})
	}
}

func TestModernExplicitRetryIdentityStillDeduplicates(t *testing.T) {
	for _, tc := range []struct {
		name string
		meta map[string]any
	}{
		{name: "conversation", meta: map[string]any{"com.telara/conversation": "explicit-chat"}},
		{name: "operation", meta: map[string]any{"com.telara/op-id": "explicit-operation"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, store := backend()
			observer := &observedBackend{delegate: b, entered: make(chan observedCall, 8)}
			ctx, paths := realDaemon(t, observer)
			s := realShim(t, ctx, paths)
			req := modernCreate4(tc.meta)
			var first observedCall
			var result any
			for retry := 0; retry < 2; retry++ {
				s.send(t, req)
				r := s.read(t)
				assertWireSuccess3(t, r, `1`)
				entered := entered3(t, observer)
				if entered.connection == "" {
					t.Fatal("missing daemon connection identity")
				}
				if retry == 0 {
					first, result = entered, r.Result
				} else if first.connection != entered.connection || !reflect.DeepEqual(result, r.Result) {
					t.Fatal("retry changed connection or persisted result")
				}
			}
			s.finish(t)
			calls, _ := store.Audit()
			rows, mutations, _ := store.Snapshot()
			if len(calls) != 1 || len(rows) != 1 || mutations != 1 {
				t.Fatal("explicit retry identity lost")
			}
			call := calls[0]
			if tc.name == "conversation" {
				wantScope := record.H("handle", teststore.Access().CredentialID, "explicit-chat")
				id, err := daemon.RPCIDKey(req.ID)
				wantOp, hashErr := record.HE("op", wantScope, first.connection, id, call.Tool, call.ArgsHash)
				if err != nil || hashErr != nil || call.Access.ScopeID != wantScope || call.Access.Confidence != "handle-only" || call.Op != wantOp {
					t.Fatal("explicit conversation lost credential scope or original correlation")
				}
			} else {
				wantOp, err := record.HE("fixture-supplied", teststore.Access().CredentialID, "explicit-operation")
				if err != nil || call.Access.ScopeID != "" || call.Access.SessionKey != "" || call.Op != wantOp {
					t.Fatal("explicit operation lost credential namespace or inferred continuity")
				}
			}
		})
	}
}

func TestModernMetadataRefusedByDaemonBeforeBackend(t *testing.T) {
	b, store := backend()
	observer := &observedBackend{delegate: b, entered: make(chan observedCall, 8)}
	ctx, paths := realDaemon(t, observer)
	c, err := ipc.Dial(ctx, paths)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(c)
	if err = ipc.WriteFrame(c, ipc.Hello{T: "hello", V: ipc.WireVersion, Kind: "mcp", PID: os.Getpid(), Client: "fixture", Shim: "shared"}); err != nil {
		t.Fatal(err)
	}
	if _, err = ipc.ReadFrame(reader); err != nil {
		t.Fatal(err)
	}
	for _, params := range []string{
		`{}`,
		`{"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}}`,
		`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`,
		`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":null}}`,
		`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":1}}`,
	} {
		methods := []string{"server/discover", "tools/call"}
		if params == `{}` {
			methods = []string{"server/discover"} // No markers on tools/call means legacy.
		}
		for _, method := range methods {
			req := daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: method, Params: json.RawMessage(params)}
			if err = ipc.WriteFrame(c, req); err != nil {
				t.Fatal(err)
			}
			raw, err := ipc.ReadFrame(reader)
			if err != nil {
				t.Fatal(err)
			}
			var response daemon.Response
			if json.Unmarshal(raw, &response) != nil || response.Error == nil || response.Error.Code != -32602 || response.Error.Message != "invalid_protocol_metadata" {
				t.Fatal("daemon failed metadata validation before method dispatch", string(raw))
			}
		}
	}
	select {
	case <-observer.entered:
		t.Fatal("invalid modern metadata reached backend")
	default:
	}
	calls, _ := store.Audit()
	if len(calls) != 0 {
		t.Fatal("invalid modern metadata reached store")
	}
}
