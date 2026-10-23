//go:build darwin || linux

package mcp_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/shim"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

type observedCall struct {
	req        daemon.Request
	connection string
	ctx        context.Context
}
type observedBackend struct {
	delegate  daemon.Backend
	entered   chan observedCall
	gates     map[string]<-chan struct{}
	cancelled chan string
}

func (b *observedBackend) Close() error { return b.delegate.Close() }
func (b *observedBackend) Handle(ctx context.Context, h ipc.Hello, r daemon.Request) daemon.Response {
	b.entered <- observedCall{r, daemon.ConnectionID(ctx), ctx}
	if gate := b.gates[string(r.CorrelationID())]; gate != nil {
		select {
		case <-ctx.Done():
			b.cancelled <- string(r.CorrelationID())
			// Even an adapter that returns a result after cancellation must be silenced.
			return daemon.Response{Result: map[string]any{"cancelled-result-must-not-escape": true}}
		case <-gate:
		}
	}
	return b.delegate.Handle(ctx, h, r)
}
func realDaemon(t *testing.T, backend daemon.Backend) (context.Context, ipc.Paths) {
	t.Helper()
	base := t.TempDir()
	if e := os.Chmod(base, 0700); e != nil {
		t.Fatal(e)
	}
	p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Config{Paths: p, Ready: func() { close(ready) }, Open: func(context.Context) (daemon.Backend, error) { return backend, nil }})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("daemon shutdown stalled")
		}
		os.RemoveAll(p.Run)
	})
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("daemon not ready")
	}
	return ctx, p
}

type shimSession struct {
	in        *io.PipeWriter
	responses chan daemon.Response
	done      chan error
}

func realShim(t *testing.T, ctx context.Context, p ipc.Paths, hello ...ipc.Hello) *shimSession {
	t.Helper()
	in, input := io.Pipe()
	output, out := io.Pipe()
	cfg := shim.Config{Paths: p}
	if len(hello) > 1 {
		t.Fatal("at most one shim hello is supported")
	}
	if len(hello) == 1 {
		cfg.Hello = hello[0]
	}
	s := &shimSession{in: input, responses: make(chan daemon.Response, 32), done: make(chan error, 1)}
	go func() {
		defer close(s.responses)
		reader := bufio.NewReader(output)
		for {
			raw, e := ipc.ReadFrame(reader)
			if e != nil {
				return
			}
			var r daemon.Response
			if json.Unmarshal(raw, &r) != nil {
				return
			}
			s.responses <- r
		}
	}()
	go func() { e := shim.Run(ctx, in, out, cfg); out.Close(); s.done <- e }()
	t.Cleanup(func() { input.Close(); in.Close(); output.Close(); out.Close() })
	return s
}

func (s *shimSession) send(t *testing.T, r daemon.Request) {
	t.Helper()
	if e := ipc.WriteFrame(s.in, r); e != nil {
		t.Fatal(e)
	}
}
func (s *shimSession) read(t *testing.T) daemon.Response {
	t.Helper()
	select {
	case r, ok := <-s.responses:
		if !ok {
			t.Fatal("shim output closed")
		}
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("shim reply stalled")
		return daemon.Response{}
	}
}
func (s *shimSession) finish(t *testing.T) {
	t.Helper()
	s.in.Close()
	select {
	case e := <-s.done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shim shutdown stalled")
	}
	for r := range s.responses {
		t.Fatalf("unexpected extra reply %s", r.ID)
	}
}
func request3(id, version string) daemon.Request {
	raw, _ := json.Marshal(map[string]any{"name": "telara_task_create", "arguments": map[string]any{"goal": "Transport retry"}, "_meta": map[string]any{"com.telara/conversation": "round-three-chat", "io.modelcontextprotocol/protocolVersion": version, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}})
	return daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(id), Method: "tools/call", Params: raw}
}
func entered3(t *testing.T, b *observedBackend) observedCall {
	t.Helper()
	select {
	case v := <-b.entered:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("backend not entered")
		return observedCall{}
	}
}
func assertWireSuccess3(t *testing.T, r daemon.Response, id string) {
	t.Helper()
	res, ok := r.Result.(map[string]any)
	if r.Error != nil || string(r.ID) != id || !ok || res["isError"] == true {
		t.Fatalf("failed transport response %+v", r)
	}
}

// Uses the shipped stdio shim and daemon over real IPC. The nonpersistent store
// boundary establishes mutation counts and Seal receipts, not SQLite acceptance.
func TestFallbackRetryThroughRealShimAndDaemon(t *testing.T) {
	b, store := backend()
	observer := &observedBackend{delegate: b, entered: make(chan observedCall, 32)}
	ctx, p := realDaemon(t, observer)
	s := realShim(t, ctx, p)
	ids := []string{`"ghp_` + strings.Repeat("a", 36) + `"`, `9007199254740992`, `9007199254740993`, `"9007199254740993"`}
	for _, id := range ids {
		calls, _ := store.Audit()
		before := len(calls)
		_, beforeMutations, _ := store.Snapshot()
		var first observedCall
		var result any
		for retry := 0; retry < 2; retry++ {
			s.send(t, request3(id, "2026-07-28"))
			r := s.read(t)
			assertWireSuccess3(t, r, id)
			observed := entered3(t, observer)
			if string(observed.req.ID) == id || string(observed.req.CorrelationID()) != id {
				t.Fatal("multiplexed and original correlation not separated")
			}
			if retry == 0 {
				first = observed
				result = r.Result
			} else {
				if !reflect.DeepEqual(result, r.Result) || first.connection != observed.connection || string(first.req.ID) == string(observed.req.ID) {
					t.Fatal("retry changed result/connection or reused multiplexed ID")
				}
			}
		}
		calls, seals := store.Audit()
		if len(calls) != before+1 {
			t.Fatal("same-connection shim retry duplicated mutation or distinct IDs aliased")
		}
		_, mutations, _ := store.Snapshot()
		if mutations != beforeMutations+1 {
			t.Fatal("retry performed more than one mutation")
		}
		call := calls[len(calls)-1]
		canonical, e := daemon.RPCIDKey(json.RawMessage(id))
		if e != nil {
			t.Fatal(e)
		}
		want, e := record.HE("op", call.Access.ScopeID, first.connection, canonical, call.Tool, call.ArgsHash)
		if e != nil || want != call.Op {
			t.Fatal("fallback hash used multiplexed correlation")
		}
		if strings.HasPrefix(id, `"ghp_`) {
			raw, _ := json.Marshal(calls)
			if strings.Contains(string(raw), "ghp_") {
				t.Fatal("original correlation persisted in Call")
			}
			for _, seal := range seals {
				h, body, _, _ := seal.Envelope()
				if strings.Contains(string(h)+string(body), "ghp_") {
					t.Fatal("original correlation persisted in Seal")
				}
			}
		}
	}
	s.finish(t)
}
func TestUnsupportedVersionsThroughRealShimAndDaemon(t *testing.T) {
	b, store := backend()
	observer := &observedBackend{delegate: b, entered: make(chan observedCall, 32)}
	ctx, p := realDaemon(t, observer)
	s := realShim(t, ctx, p)
	for _, v := range []string{"2099-01-01", "2025-11-25", "1900-01-01"} {
		for _, method := range []string{"ping", "server/discover", "tools/list", "prompts/list", "resources/list", "tools/call", "unknown/method"} {
			req := request3(`"unsupported"`, v)
			req.Method = method
			if method != "tools/call" {
				req.Params = json.RawMessage(fmt.Sprintf(`{"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":{}}}`, v))
			}
			s.send(t, req)
			r := s.read(t)
			if r.Error == nil || r.Error.Code != -32022 || r.Result != nil {
				t.Fatal("unsupported revision dispatched", v, method, r)
			}
			data, ok := r.Error.Data.(map[string]any)
			if !ok || data["requested"] != v {
				t.Fatal("missing requested version")
			}
			encoded, _ := json.Marshal(data["supported"])
			want, _ := json.Marshal(daemon.SupportedProtocolVersions())
			if string(encoded) != string(want) {
				t.Fatal("missing supported revisions")
			}
		}
	}
	s.send(t, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`"init"`), Method: "initialize", Params: json.RawMessage(`{"protocolVersion":"2025-11-25"}`)})
	r := s.read(t)
	if r.Error != nil || r.Result.(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Fatal("legacy fallback selected modern semantics")
	}
	// Prove the same live shim remains usable after refusals and legacy setup.
	s.send(t, request3(`"supported"`, "2026-07-28"))
	assertWireSuccess3(t, s.read(t), `"supported"`)
	entered3(t, observer)
	calls, _ := store.Audit()
	if len(calls) != 1 {
		t.Fatal("unsupported call mutated")
	}
	select {
	case <-observer.entered:
		t.Fatal("unsupported request reached backend")
	default:
	}
	s.finish(t)
}
func TestCancellationThroughRealShimAndDaemon(t *testing.T) {
	b, store := backend()
	keep, cancelledGate := make(chan struct{}), make(chan struct{})
	target, other := `9007199254740993`, `9007199254740992`
	observer := &observedBackend{delegate: b, entered: make(chan observedCall, 32), cancelled: make(chan string, 8), gates: map[string]<-chan struct{}{target: cancelledGate, other: keep}}
	ctx, p := realDaemon(t, observer)
	s := realShim(t, ctx, p)
	s.send(t, request3(target, "2026-07-28"))
	a := entered3(t, observer)
	s.send(t, request3(other, "2026-07-28"))
	z := entered3(t, observer)
	if a.connection != z.connection {
		t.Fatal("calls not multiplexed")
	}
	// Wrong JSON type, unknown ID, and malformed notification cannot cancel either.
	for _, raw := range []string{`{"requestId":"9007199254740993"}`, `{"requestId":0}`, `{"requestId":{}}`} {
		s.send(t, daemon.Request{JSONRPC: "2.0", Method: "notifications/cancelled", Params: json.RawMessage(raw)})
	}
	s.send(t, daemon.Request{JSONRPC: "2.0", Method: "notifications/cancelled", Params: json.RawMessage(`{"requestId":9007199254740993,"reason":"cancel only this call"}`)})
	select {
	case id := <-observer.cancelled:
		if id != target {
			t.Fatal("wrong call cancelled")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not reach daemon context")
	}
	if a.ctx.Err() != context.Canceled || z.ctx.Err() != nil {
		t.Fatal("cancellation crossed calls")
	}
	close(keep)
	assertWireSuccess3(t, s.read(t), other)
	// Another data call proves cancellation left the same daemon connection alive.
	s.send(t, request3(`"after"`, "2026-07-28"))
	assertWireSuccess3(t, s.read(t), `"after"`)
	next := entered3(t, observer)
	if next.connection != z.connection {
		t.Fatal("cancellation forced reconnect")
	}
	calls, _ := store.Audit()
	if len(calls) != 2 {
		t.Fatal("cancelled work mutated, or sibling lost")
	}
	s.finish(t)
}

func TestDaemonCancellationAndVersionBeforeDispatch(t *testing.T) {
	b, store := backend()
	keep, stop := make(chan struct{}), make(chan struct{})
	observer := &observedBackend{delegate: b, entered: make(chan observedCall, 32), cancelled: make(chan string, 8), gates: map[string]<-chan struct{}{`"cancel"`: stop, `"keep"`: keep}}
	ctx, p := realDaemon(t, observer)
	c, e := ipc.Dial(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if e = c.SetDeadline(time.Now().Add(5 * time.Second)); e != nil {
		t.Fatal(e)
	}
	reader := bufio.NewReader(c)
	if e = ipc.WriteFrame(c, ipc.Hello{T: "hello", V: ipc.WireVersion, Kind: "mcp", PID: os.Getpid(), Client: "fixture"}); e != nil {
		t.Fatal(e)
	}
	if _, e = ipc.ReadFrame(reader); e != nil {
		t.Fatal(e)
	}
	send := func(r daemon.Request) {
		t.Helper()
		if e := ipc.WriteFrame(c, r); e != nil {
			t.Fatal(e)
		}
	}
	read := func() daemon.Response {
		t.Helper()
		raw, e := ipc.ReadFrame(reader)
		if e != nil {
			t.Fatal(e)
		}
		var r daemon.Response
		if e = json.Unmarshal(raw, &r); e != nil {
			t.Fatal(e)
		}
		return r
	}
	for _, method := range []string{"tools/call", "ping", "server/discover", "unknown/method"} {
		r := request3(`"refuse"`, "2099-01-01")
		r.Method = method
		send(r)
		got := read()
		if got.Error == nil || got.Error.Code != -32022 {
			t.Fatal("daemon accepted unsupported revision", method, got)
		}
	}
	select {
	case <-observer.entered:
		t.Fatal("daemon dispatched unsupported request")
	default:
	}
	send(request3(`"cancel"`, "2026-07-28"))
	target := entered3(t, observer)
	send(request3(`"keep"`, "2026-07-28"))
	other := entered3(t, observer)
	send(daemon.Request{JSONRPC: "2.0", Method: "notifications/cancelled", Params: json.RawMessage(`{"requestId":"cancel"}`)})
	select {
	case id := <-observer.cancelled:
		if id != `"cancel"` {
			t.Fatal("wrong cancellation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon context not cancelled")
	}
	if target.ctx.Err() != context.Canceled || other.ctx.Err() != nil {
		t.Fatal("daemon cancellation not isolated")
	}
	close(keep)
	assertWireSuccess3(t, read(), `"keep"`)
	send(daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`"after"`), Method: "ping"})
	r := read()
	if r.Error != nil || string(r.ID) != `"after"` {
		t.Fatal("cancelled reply escaped daemon")
	}
	calls, _ := store.Audit()
	if len(calls) != 1 {
		t.Fatal("cancelled or unsupported work mutated")
	}
}
