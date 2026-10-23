// Package shim bridges bounded stdio requests without replaying application calls.
package shim

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

// Ensure serializes the re-dial/spawn decision. Managed installs supply their
// manager as Start rather than detaching a replacement process.
func Ensure(ctx context.Context, p ipc.Paths, start func() error) error {
	if e := p.Prepare(); e != nil {
		return e
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	spawned := false
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		probe, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		c, e := ipc.Dial(probe, p)
		cancel()
		if e == nil {
			c.Close()
			return nil
		}
		if !spawned && start != nil {
			lock, le := ipc.Lock(filepath.Join(p.Data, "spawn.lock"))
			if le == nil {
				probe, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				c, e = ipc.Dial(probe, p)
				cancel()
				if e == nil {
					c.Close()
					lock.Close()
					return nil
				}
				e = start()
				lock.Close()
				if e != nil {
					return e
				}
				spawned = true
			} else if !errors.Is(le, ipc.ErrBusy) {
				return le
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// AutostartError reports a refused launch without exposing filesystem details.
type AutostartError struct{}

func (*AutostartError) Error() string { return "autostart_unverified_install" }

// Spawn fails closed. This source tree has no installed artifact verifier or
// OS-specific identity-preserving launch adapter. os.Executable is not proof of
// either installation or executable identity. Managed installs supply Config.Start
// only after verifying and pinning their installed artifact through launch.
func Spawn(p ipc.Paths) error { return &AutostartError{} }

type Config struct {
	Paths ipc.Paths
	Start func() error
	Hello ipc.Hello
}
type generation struct {
	c       net.Conn
	mu      sync.Mutex
	pending map[string]chan daemon.Response
	send    chan struct{}
}
type client struct {
	cfg        Config
	mu         sync.Mutex
	g          *generation
	connecting chan struct{}
	attempts   []time.Time
	seq        atomic.Uint64
}

func (cl *client) connect(ctx context.Context) (*generation, error) {
	select {
	case cl.connecting <- struct{}{}:
		defer func() { <-cl.connecting }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	cl.mu.Lock()
	if cl.g != nil {
		g := cl.g
		cl.mu.Unlock()
		return g, nil
	}
	now := time.Now()
	kept := cl.attempts[:0]
	for _, t := range cl.attempts {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	cl.attempts = kept
	if len(cl.attempts) >= 3 {
		cl.mu.Unlock()
		return nil, errors.New("restart_limited")
	}
	cl.attempts = append(cl.attempts, now)
	cl.mu.Unlock()
	if e := Ensure(ctx, cl.cfg.Paths, cl.cfg.Start); e != nil {
		return nil, e
	}
	c, e := ipc.Dial(ctx, cl.cfg.Paths)
	if e != nil {
		return nil, e
	}
	deadline, _ := ctx.Deadline()
	if e = c.SetDeadline(deadline); e != nil {
		c.Close()
		return nil, e
	}
	h := cl.cfg.Hello
	if h.Client == "" {
		h.Client = "stdio"
	}
	h.T = "hello"
	h.V = ipc.WireVersion
	h.Kind = "mcp"
	h.PID = os.Getpid()
	h.NodeVersion = daemon.Version
	if e = ipc.WriteFrame(c, h); e != nil {
		c.Close()
		return nil, e
	}
	r := bufio.NewReader(c)
	b, e := ipc.ReadFrame(r)
	var ack struct {
		T          string `json:"t"`
		V          int    `json:"v"`
		Connection string `json:"connection_id"`
	}
	if e != nil || json.Unmarshal(b, &ack) != nil || ack.T != "hello" || ack.V != ipc.WireVersion || ack.Connection == "" {
		c.Close()
		return nil, ipc.ErrFrame
	}
	if e = c.SetDeadline(time.Time{}); e != nil {
		c.Close()
		return nil, e
	}
	g := &generation{c: c, pending: map[string]chan daemon.Response{}, send: make(chan struct{}, 1)}
	cl.mu.Lock()
	cl.g = g
	cl.mu.Unlock()
	go func() {
		for {
			b, e := ipc.ReadFrame(r)
			if e != nil {
				cl.lost(g)
				return
			}
			var out daemon.Response
			if json.Unmarshal(b, &out) != nil || out.JSONRPC != "2.0" {
				cl.lost(g)
				return
			}
			g.mu.Lock()
			ch := g.pending[string(out.ID)]
			delete(g.pending, string(out.ID))
			g.mu.Unlock()
			if ch != nil {
				ch <- out
			}
		}
	}()
	return g, nil
}
func (cl *client) lost(g *generation) {
	cl.mu.Lock()
	if cl.g == g {
		cl.g = nil
	}
	cl.mu.Unlock()
	g.c.Close()
	g.mu.Lock()
	for key, ch := range g.pending {
		ch <- daemon.Error(json.RawMessage(key), "outcome_unknown")
		delete(g.pending, key)
	}
	g.mu.Unlock()
}
func diagnostic(req daemon.Request, code string) daemon.Response {
	if req.Method == "tools/call" {
		return daemon.Response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"isError": true, "content": []any{map[string]string{"type": "text", "text": code}}}}
	}
	return daemon.Error(req.ID, code)
}
func (cl *client) call(ctx context.Context, req daemon.Request) daemon.Response {
	ctx, cancel := context.WithTimeout(ctx, ipc.HandshakeTimeout)
	defer cancel()
	id := json.RawMessage(strconv.FormatUint(cl.seq.Add(1), 10))
	wire := req
	wire.ID = id
	frame, e := ipc.EncodeFrame(daemon.ForwardedRequest{Request: wire, ClientRequestID: req.ID})
	if e != nil {
		return diagnostic(req, "invalid_frame")
	}
	g, e := cl.connect(ctx)
	if e != nil {
		var refused *AutostartError
		if errors.As(e, &refused) {
			return diagnostic(req, refused.Error())
		}
		return diagnostic(req, "daemon_unavailable")
	}
	select {
	case g.send <- struct{}{}:
	case <-ctx.Done():
		return diagnostic(req, "daemon_timeout")
	}
	if ctx.Err() != nil {
		<-g.send
		return diagnostic(req, "daemon_timeout")
	}
	ch := make(chan daemon.Response, 1)
	g.mu.Lock()
	g.pending[string(id)] = ch
	g.mu.Unlock()
	deadline, _ := ctx.Deadline()
	if e = g.c.SetWriteDeadline(deadline); e != nil {
		g.mu.Lock()
		delete(g.pending, string(id))
		g.mu.Unlock()
		<-g.send
		cl.lost(g)
		return diagnostic(req, "daemon_unavailable")
	}
	e = ipc.WriteEncodedFrame(g.c, frame)
	<-g.send
	if e != nil {
		cl.lost(g)
		return diagnostic(req, "outcome_unknown")
	}
	select {
	case out := <-ch:
		out.ID = req.ID
		if out.Error != nil && out.Error.Message == "outcome_unknown" {
			return diagnostic(req, "outcome_unknown")
		}
		return out
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			cl.cancelCall(g, id)
		} else {
			cl.lost(g)
		}
		return diagnostic(req, "outcome_unknown")
	}
}

// cancelCall removes only this pending reply and forwards the multiplexed ID.
// A cancelled call never closes a healthy connection or cancels its siblings.
func (cl *client) cancelCall(g *generation, id json.RawMessage) {
	g.mu.Lock()
	delete(g.pending, string(id))
	g.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), ipc.HandshakeTimeout)
	defer cancel()
	select {
	case g.send <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-g.send }()
	raw, _ := json.Marshal(map[string]json.RawMessage{"requestId": id})
	if g.c.SetWriteDeadline(time.Now().Add(ipc.HandshakeTimeout)) != nil || ipc.WriteFrame(g.c, daemon.Request{JSONRPC: "2.0", Method: "notifications/cancelled", Params: raw}) != nil {
		cl.lost(g)
	}
}

func Run(ctx context.Context, in io.Reader, out io.Writer, cfg Config) (result error) {
	if f, ok := in.(*os.File); ok {
		adapted, cleanup, e := cancelableFile(ctx, f)
		if e != nil {
			return e
		}
		defer cleanup()
		in = adapted
	}
	if f, ok := out.(*os.File); ok {
		adapted, cleanup, e := cancelableFile(ctx, f)
		if e != nil {
			return e
		}
		defer cleanup()
		out = adapted
	}
	watchDone := make(chan struct{})
	defer close(watchDone)
	for _, stream := range []any{in, out} {
		if closer, ok := stream.(io.Closer); ok {
			go func() {
				select {
				case <-ctx.Done():
					closer.Close()
				case <-watchDone:
				}
			}()
		}
	}
	cl := &client{cfg: cfg, connecting: make(chan struct{}, 1)}
	defer func() {
		cl.mu.Lock()
		g := cl.g
		cl.mu.Unlock()
		if g != nil {
			cl.lost(g)
		}
	}()
	r := bufio.NewReader(in)
	var writes sync.Mutex
	var calls sync.WaitGroup
	var pending daemon.Inflight
	var writeErr error
	defer func() {
		calls.Wait()
		writes.Lock()
		defer writes.Unlock()
		if result == nil {
			result = writeErr
		}
	}()
	slots := make(chan struct{}, ipc.MaxInFlight)
	write := func(v any) error {
		writes.Lock()
		defer writes.Unlock()
		if e := ctx.Err(); e != nil {
			return e
		}
		e := ipc.WriteFrame(out, v)
		if writeErr == nil {
			writeErr = e
		}
		return e
	}
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		b, e := ipc.ReadFrame(r)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e == io.EOF {
			return nil
		}
		if e != nil {
			write(daemon.Error(nil, "invalid_frame"))
			return e
		}
		req, e := daemon.Parse(b)
		if e != nil {
			write(daemon.Error(nil, "invalid_request"))
			return e
		}
		if len(req.ID) == 0 {
			if id, ok := daemon.CancellationID(req); ok {
				pending.Cancel(id)
			}
			continue
		}
		if response, ok := daemon.Setup(req); ok {
			if e = write(response); e != nil {
				return e
			}
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			if e = write(diagnostic(req, "busy")); e != nil {
				return e
			}
			continue
		}
		flight, ok := pending.Begin(ctx, req.ID)
		if !ok {
			<-slots
			return ipc.ErrFrame
		}
		calls.Add(1)
		go func(req daemon.Request, flight *daemon.Flight) {
			defer calls.Done()
			defer flight.Finish()
			defer func() { <-slots }()
			response := cl.call(flight.Context, req)
			flight.Reply(func() { write(response) })
		}(req, flight)
	}
}
