package shim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

func TestLocalSetupWithoutDaemon(t *testing.T) {
	var out bytes.Buffer
	e := Run(context.Background(), strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n"), &out, Config{})
	if e != nil || !strings.Contains(out.String(), "protocolVersion") || !strings.Contains(out.String(), `"tools":[]`) {
		t.Fatalf("setup %s %v", out.String(), e)
	}
}
func TestMalformedStdio(t *testing.T) {
	var out bytes.Buffer
	if Run(context.Background(), strings.NewReader("private-secret\n"), &out, Config{}) == nil || strings.Contains(out.String(), "secret") || !strings.Contains(out.String(), "invalid_frame") {
		t.Fatal(out.String())
	}
}
func TestDiagnostic(t *testing.T) {
	r := diagnostic(daemon.Request{Method: "tools/call", ID: json.RawMessage("1")}, "outcome_unknown")
	b, _ := json.Marshal(r)
	if !bytes.Contains(b, []byte(`"isError":true`)) {
		t.Fatal(string(b))
	}
}
func TestReconnectLimit(t *testing.T) {
	cl := &client{connecting: make(chan struct{}, 1), attempts: []time.Time{time.Now(), time.Now(), time.Now()}}
	if _, e := cl.connect(context.Background()); e == nil || e.Error() != "restart_limited" {
		t.Fatal(e)
	}
}
func TestContextWhileConnecting(t *testing.T) {
	cl := &client{connecting: make(chan struct{}, 1)}
	cl.connecting <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := cl.connect(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("output_closed") }
func TestOutputFailure(t *testing.T) {
	e := Run(context.Background(), strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n"), failedWriter{}, Config{})
	if e == nil {
		t.Fatal("output failure ignored")
	}
}
func TestCancelClosesInput(t *testing.T) {
	in, out := io.Pipe()
	defer out.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, in, io.Discard, Config{}) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stdin stayed blocked")
	}
}

func TestCancelClosesOutput(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n"), writer, Config{})
	}()
	// An io.Pipe write cannot complete without a reader. Verify that the
	// response starts, then stop reading so cancellation must close output.
	if _, e := io.ReadFull(reader, make([]byte, 1)); e != nil {
		t.Fatal(e)
	}
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("blocked write unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("stdout stayed blocked")
	}
}

func TestUnverifiedAutostartRefusesWithoutLaunch(t *testing.T) {
	var refused *AutostartError
	if e := Spawn(ipc.Paths{}); !errors.As(e, &refused) || e.Error() != "autostart_unverified_install" {
		t.Fatalf("untyped refusal %v", e)
	}
}
