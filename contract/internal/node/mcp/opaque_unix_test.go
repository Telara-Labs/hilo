//go:build darwin || linux

package mcp_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

func TestOpaqueFallbackIDThroughActualDaemon(t *testing.T) {
	b, s := backend()
	base := t.TempDir()
	if e := os.Chmod(base, 0700); e != nil {
		t.Fatal(e)
	}
	paths, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(paths.Run)
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Config{Paths: paths, Ready: func() { close(ready) }, Open: func(context.Context) (daemon.Backend, error) { return b, nil }})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("daemon shutdown stalled")
		}
	}()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("daemon startup stalled")
	}
	c, e := ipc.Dial(ctx, paths)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if e = c.SetDeadline(time.Now().Add(3 * time.Second)); e != nil {
		t.Fatal(e)
	}
	reader := bufio.NewReader(c)
	if e = ipc.WriteFrame(c, ipc.Hello{T: "hello", V: ipc.WireVersion, Kind: "mcp", PID: os.Getpid(), Client: "fixture", Shim: "opaque-shim"}); e != nil {
		t.Fatal(e)
	}
	raw, e := ipc.ReadFrame(reader)
	if e != nil {
		t.Fatal(e)
	}
	var hello struct {
		ConnectionID string `json:"connection_id"`
	}
	if json.Unmarshal(raw, &hello) != nil || hello.ConnectionID == "" {
		t.Fatal("no server connection identity")
	}
	for _, id := range []string{"ghp_" + strings.Repeat("a", 36), "Bearer " + strings.Repeat("b", 64), "\u202e\n", strings.Repeat("c", 1024)} {
		idJSON, _ := json.Marshal(id)
		req := daemon.Request{JSONRPC: "2.0", ID: idJSON, Method: "tools/call", Params: json.RawMessage(`{"name":"telara_task_create","arguments":{"goal":"Opaque ID fixture"}}`)}
		calls, _ := s.Audit()
		before := len(calls)
		for retry := 0; retry < 2; retry++ {
			if e = ipc.WriteFrame(c, req); e != nil {
				t.Fatal(e)
			}
			raw, e = ipc.ReadFrame(reader)
			if e != nil {
				t.Fatal(e)
			}
			var response daemon.Response
			if json.Unmarshal(raw, &response) != nil || response.Error != nil {
				t.Fatal("opaque fallback call failed")
			}
			var correlation string
			if json.Unmarshal(response.ID, &correlation) != nil || correlation != id {
				t.Fatal("correlation changed")
			}
			result, ok := response.Result.(map[string]any)
			if !ok || result["isError"] == true {
				t.Fatal("fallback tool result failed")
			}
		}
		calls, sealedRecords := s.Audit()
		if len(calls) != before+1 {
			t.Fatal("same-connection retry duplicated mutation")
		}
		call := calls[len(calls)-1]
		expected, e := record.FallbackOpID(call.Access.ScopeID, hello.ConnectionID, idJSON, call.Tool, call.ArgsHash)
		if e != nil || call.Op != expected {
			t.Fatal("fallback did not use hashed transport correlation")
		}
		persisted, _ := json.Marshal(calls)
		encodedID, _ := json.Marshal(id)
		if strings.Contains(string(persisted), string(encodedID)) {
			t.Fatal("raw ID persisted in Call")
		}
		for _, sealed := range sealedRecords {
			header, body, _, _ := sealed.Envelope()
			if strings.Contains(string(header), string(encodedID)) || strings.Contains(string(body), string(encodedID)) {
				t.Fatal("raw ID persisted in receipt")
			}
		}
	}

	// Exact integer ids must stay distinct all the way into fallback-operation
	// hashing, including retries on the same authenticated IPC connection.
	for _, id := range []string{"9007199254740992", "9007199254740993", "18446744073709551617", "-9007199254740993"} {
		req := daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(id), Method: "tools/call", Params: json.RawMessage(`{"name":"telara_task_create","arguments":{"goal":"Numeric ID fixture"}}`)}
		beforeCalls, _ := s.Audit()
		for retry := 0; retry < 2; retry++ {
			if e = ipc.WriteFrame(c, req); e != nil {
				t.Fatal(e)
			}
			raw, e = ipc.ReadFrame(reader)
			if e != nil {
				t.Fatal(e)
			}
			var r daemon.Response
			if json.Unmarshal(raw, &r) != nil || r.Error != nil || string(r.ID) != id {
				t.Fatal("numeric correlation changed", id, string(raw))
			}
			if res, ok := r.Result.(map[string]any); !ok || res["isError"] == true {
				t.Fatal("numeric fallback call failed")
			}
		}
		calls, _ := s.Audit()
		if len(calls) != len(beforeCalls)+1 {
			t.Fatal("distinct integer id aliased or retry repeated mutation", id)
		}
		call := calls[len(calls)-1]
		want, e := record.HE("op", call.Access.ScopeID, hello.ConnectionID, id, call.Tool, call.ArgsHash)
		if e != nil || want != call.Op {
			t.Fatal("fallback rounded integer id", id)
		}
	}
	// A subsequent request proves the secret-looking ID kept the session alive.
	if e = ipc.WriteFrame(c, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`"after"`), Method: "ping"}); e != nil {
		t.Fatal(e)
	}
	raw, e = ipc.ReadFrame(reader)
	if e != nil {
		t.Fatal(e)
	}
	var ping daemon.Response
	if json.Unmarshal(raw, &ping) != nil || ping.Error != nil || string(ping.ID) != `"after"` {
		t.Fatal("session lost after opaque IDs")
	}
}
