//go:build darwin || linux

package shim

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

func TestConcurrentCallsActualDaemon(t *testing.T) {
	base := t.TempDir()
	os.Chmod(base, 0700)
	p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(p.Run)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx, daemon.Config{Paths: p, Ready: func() { close(ready) }}) }()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("not ready")
	}
	cl := &client{cfg: Config{Paths: p}, connecting: make(chan struct{}, 1)}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := cl.call(ctx, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`"original"`), Method: "status"})
			if out.Error != nil || string(out.ID) != `"original"` {
				t.Errorf("call %+v", out)
			}
		}()
	}
	wg.Wait()
	cl.mu.Lock()
	g := cl.g
	cl.mu.Unlock()
	if g == nil {
		t.Fatal("connection lost")
	}
	cl.lost(g)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown")
	}
}

func TestStartCallbackCanReachDaemonReadiness(t *testing.T) {
	base := t.TempDir()
	os.Chmod(base, 0700)
	p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(p.Run)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	start := func() error {
		go func() { done <- daemon.Run(ctx, daemon.Config{Paths: p, Ready: func() { close(ready) }}) }()
		// Force the child to initialize while Ensure still owns its launch lock.
		select {
		case <-ready:
			return nil
		case e := <-done:
			return e
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if e = Ensure(ctx, p, start); e != nil {
		t.Fatal(e)
	}
	cancel()
	select {
	case e = <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon stuck")
	}
}
func TestPreflightFrameErrorKeepsGenerationAndPendingCall(t *testing.T) {
	base := t.TempDir()
	os.Chmod(base, 0700)
	p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(p.Run)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	b := &heldCall{entered: make(chan struct{}), release: make(chan struct{})}
	go func() {
		done <- daemon.Run(ctx, daemon.Config{Paths: p, Ready: func() { close(ready) }, Open: func(context.Context) (daemon.Backend, error) { return b, nil }})
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("not ready")
	}
	cl := &client{cfg: Config{Paths: p}, connecting: make(chan struct{}, 1)}
	first := make(chan daemon.Response, 1)
	go func() {
		first <- cl.call(ctx, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "hold"})
	}()
	select {
	case <-b.entered:
	case <-time.After(time.Second):
		t.Fatal("not pending")
	}
	cl.mu.Lock()
	original := cl.g
	cl.mu.Unlock()
	req := daemon.Request{JSONRPC: "2.0", ID: json.RawMessage("2"), Method: "tools/call", Params: json.RawMessage(`{"s":"` + strings.Repeat("<", 1000000) + `"}`)}
	out := cl.call(ctx, req)
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), "invalid_frame") || strings.Contains(string(raw), "outcome_unknown") {
		t.Fatal(string(raw))
	}
	cl.mu.Lock()
	current := cl.g
	cl.mu.Unlock()
	if current != original {
		t.Fatal("preflight closed unrelated connection")
	}
	original.mu.Lock()
	pending := len(original.pending)
	original.mu.Unlock()
	if pending != 1 {
		t.Fatalf("pending %d", pending)
	}
	close(b.release)
	select {
	case out = <-first:
		if out.Error != nil {
			t.Fatal(out.Error)
		}
	case <-time.After(time.Second):
		t.Fatal("unrelated call lost")
	}
	out = cl.call(ctx, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage("3"), Method: "status"})
	if out.Error != nil {
		t.Fatal(out.Error)
	}
	cl.lost(original)
	cancel()
	<-done
}

type heldCall struct{ entered, release chan struct{} }

func (b *heldCall) Handle(_ context.Context, _ ipc.Hello, r daemon.Request) daemon.Response {
	close(b.entered)
	<-b.release
	return daemon.Response{Result: map[string]bool{"ok": true}}
}
func (*heldCall) Close() error { return nil }
