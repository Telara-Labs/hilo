package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// These tests cover the trusted hook boundary without needing a valid peer.
// The native installed integration covers the successful authenticated path.
func TestBoundServeRefusesBeforeReadingHello(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	called := false
	bind := func(ctx context.Context, c net.Conn) (context.Context, func(), error) {
		called = true
		return ctx, func() { t.Error("error-path release must be owned by binder") }, errors.New("refused kernel binding")
	}
	if serveBound(context.Background(), a, nil, nil, bind) {
		t.Fatal("connection transferred")
	}
	if !called {
		t.Fatal("binding not requested")
	}
}
func TestBoundServeReleasesAfterFailedKernelPeerCheck(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	released := 0
	bind := func(ctx context.Context, c net.Conn) (context.Context, func(), error) {
		return ctx, func() { released++ }, nil
	}
	// net.Pipe has no kernel peer credentials. A successful binding still owns
	// exactly one cleanup when the existing kernel-peer check refuses it.
	if serveBound(context.Background(), a, nil, nil, bind) {
		t.Fatal("connection transferred")
	}
	if released != 1 {
		t.Fatal("lost or duplicated release", released)
	}
}

// The custody callback is outside MCP dispatch, including forwarded envelopes
// whose hello falsely claims the control role.
func TestCustodyHandoffControlBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		forwarded  bool
		wantCalls  int
	}{
		{"direct-control", "control", false, 1},
		{"mcp", "mcp", false, 0},
		{"forwarded-control", "control", true, 0},
		{"forwarded-mcp", "mcp", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			if e := os.Chmod(base, 0700); e != nil {
				t.Fatal(e)
			}
			p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready := make(chan struct{})
			done := make(chan error, 1)
			var calls atomic.Int32
			go func() {
				done <- Run(ctx, Config{Paths: p, Ready: func() { close(ready) }, CustodyHandoff: func(context.Context, json.RawMessage) error { calls.Add(1); return nil }})
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("daemon did not stop")
				}
			})
			select {
			case <-ready:
			case <-time.After(3 * time.Second):
				t.Fatal("not ready")
			}
			c, e := ipc.Dial(ctx, p)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			if e = ipc.WriteFrame(c, ipc.Hello{T: "hello", V: ipc.WireVersion, Kind: tc.kind, PID: os.Getpid(), Client: "test"}); e != nil {
				t.Fatal(e)
			}
			reader := bufio.NewReader(c)
			if _, e = ipc.ReadFrame(reader); e != nil {
				t.Fatal(e)
			}
			req := ForwardedRequest{Request: Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "custody-handoff", Params: json.RawMessage(`{"sha256":"invalid"}`)}}
			if tc.forwarded {
				req.ClientRequestID = json.RawMessage("2")
			}
			if e = ipc.WriteFrame(c, req); e != nil {
				t.Fatal(e)
			}
			b, e := ipc.ReadFrame(reader)
			if e != nil {
				t.Fatal(e)
			}
			var response struct {
				Error *RPCError `json:"error"`
			}
			if e = json.Unmarshal(b, &response); e != nil {
				t.Fatal(e)
			}
			if int(calls.Load()) != tc.wantCalls || (response.Error == nil) != (tc.wantCalls == 1) {
				t.Fatalf("calls %d response %s", calls.Load(), b)
			}
		})
	}
}
