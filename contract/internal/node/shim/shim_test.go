package shim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcpcatalog"
)

func TestLocalSetupWithoutDaemon(t *testing.T) {
	for _, proposal := range []string{"2024-11-05", "2025-03-26", "2025-06-18", "2026-07-28", "2025-11-25", "2099-01-01", "unknown"} {
		t.Run(proposal, func(t *testing.T) {
			var out bytes.Buffer
			// This would fail immediately if any setup request tried daemon startup.
			starts := 0
			cfg := Config{Start: func() error { starts++; return errors.New("must_not_start") }}
			input := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":%q}}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"ping"}
`, proposal)
			if e := Run(context.Background(), strings.NewReader(input), &out, cfg); e != nil {
				t.Fatal(e)
			}
			decoder := json.NewDecoder(&out)
			var init, catalog, ping daemon.Response
			for _, response := range []*daemon.Response{&init, &catalog, &ping} {
				if e := decoder.Decode(response); e != nil || response.Error != nil {
					t.Fatal("offline setup failed", e)
				}
			}
			wantVersion := proposal
			if proposal != "2024-11-05" && proposal != "2025-03-26" && proposal != "2025-06-18" {
				wantVersion = daemon.LatestLegacyProtocolVersion
			}
			if init.Result.(map[string]any)["protocolVersion"] != wantVersion {
				t.Fatal("incorrect negotiated version")
			}
			raw, _ := json.Marshal(catalog.Result)
			var listed struct {
				Tools []mcpcatalog.Tool `json:"tools"`
			}
			if e := json.Unmarshal(raw, &listed); e != nil || len(listed.Tools) != 8 || !reflect.DeepEqual(listed.Tools, mcpcatalog.Tools()) {
				t.Fatal("offline catalog differs from compiled schemas")
			}
			if string(ping.ID) != "3" || ping.Result.(map[string]any)["resultType"] != "complete" || starts != 0 {
				t.Fatal("ping or local setup reached daemon")
			}
		})
	}
}

func TestOpaqueIDKeepsOfflineSessionAlive(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a", 36)
	input := new(bytes.Buffer)
	for i, id := range []string{secret, "followup", strings.Repeat("x", 1024)} {
		_ = json.NewEncoder(input).Encode(daemon.Request{JSONRPC: "2.0", ID: mustID(t, id), Method: []string{"initialize", "tools/list", "ping"}[i]})
	}
	var out bytes.Buffer
	if err := Run(context.Background(), input, &out, Config{}); err != nil {
		t.Fatal("opaque ID terminated session")
	}
	decoder := json.NewDecoder(&out)
	for _, id := range []string{secret, "followup", strings.Repeat("x", 1024)} {
		var response daemon.Response
		if err := decoder.Decode(&response); err != nil || response.Error != nil {
			t.Fatal("missing correlation response")
		}
		var got string
		if json.Unmarshal(response.ID, &got) != nil || got != id {
			t.Fatal("transport correlation changed")
		}
	}
}
func mustID(t *testing.T, id string) json.RawMessage {
	t.Helper()
	raw, e := json.Marshal(id)
	if e != nil {
		t.Fatal(e)
	}
	return raw
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
