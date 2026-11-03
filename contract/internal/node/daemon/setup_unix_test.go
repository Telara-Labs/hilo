//go:build darwin || linux

package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

// A transport-only backend that occupies every transaction slot. No Telara
// service is mocked. Setup/health must be answered before backend admission.
type blockedBackend struct{ entered chan struct{} }

func (b *blockedBackend) Handle(ctx context.Context, _ ipc.Hello, r Request) Response {
	b.entered <- struct{}{}
	<-ctx.Done()
	return Error(r.ID, "canceled")
}
func (*blockedBackend) Close() error { return nil }

func TestPingBypassesSaturatedBackend(t *testing.T) {
	base := t.TempDir()
	if e := os.Chmod(base, 0700); e != nil {
		t.Fatal(e)
	}
	p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(p.Run)
	backend := &blockedBackend{entered: make(chan struct{}, ipc.MaxInFlight)}
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Paths: p, Ready: func() { close(ready) }, Open: func(context.Context) (Backend, error) { return backend, nil }})
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
	c, e := ipc.Dial(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if e = c.SetDeadline(time.Now().Add(3 * time.Second)); e != nil {
		t.Fatal(e)
	}
	reader := bufio.NewReader(c)
	if e = ipc.WriteFrame(c, ipc.Hello{T: "hello", V: ipc.WireVersion, Kind: "mcp", PID: os.Getpid(), Client: "fixture"}); e != nil {
		t.Fatal(e)
	}
	if _, e = ipc.ReadFrame(reader); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < ipc.MaxInFlight; i++ {
		if e = ipc.WriteFrame(c, Request{JSONRPC: "2.0", ID: json.RawMessage(fmt.Sprint(i)), Method: "hold"}); e != nil {
			t.Fatal(e)
		}
	}
	for i := 0; i < ipc.MaxInFlight; i++ {
		select {
		case <-backend.entered:
		case <-time.After(time.Second):
			t.Fatal("backend slots not occupied")
		}
	}
	if e = ipc.WriteFrame(c, Request{JSONRPC: "2.0", ID: json.RawMessage(`"health"`), Method: "ping"}); e != nil {
		t.Fatal(e)
	}
	raw, e := ipc.ReadFrame(reader)
	if e != nil {
		t.Fatal(e)
	}
	var r Response
	if json.Unmarshal(raw, &r) != nil || r.Error != nil || string(r.ID) != `"health"` {
		t.Fatal("ping waited for a store slot")
	}
	if result, ok := r.Result.(map[string]any); !ok || result["resultType"] != "complete" {
		t.Fatal("ping result must carry completeness")
	}
}
