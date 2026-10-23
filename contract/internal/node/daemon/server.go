// Package daemon owns the single writer lifetime. Store adapters are opened only
// after the exclusive database lock, and closed before that lock is released.
package daemon

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

const Version = "dev"

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Backend must settle all transactions before Close returns. Calls receive only
// kernel-authenticated connections; Hello fields remain untrusted identity hints.
// Handle must drain the client's spool before resolving any memory scope.
// Close must be safe to retry after an error. Shutdown retains db.lock until
// Close succeeds; a failing adapter cannot hand ownership to a new writer.
type Backend interface {
	Handle(context.Context, ipc.Hello, Request) Response
	Close() error
}
type Opener func(context.Context) (Backend, error)
type Config struct {
	Paths ipc.Paths
	Open  Opener
	Ready func()
}

func Error(id json.RawMessage, code string) Response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return Response{JSONRPC: "2.0", ID: id, Error: &RPCError{-32000, code}}
}
func Parse(b []byte) (Request, error) {
	var r Request
	if json.Unmarshal(b, &r) != nil || r.JSONRPC != "2.0" || r.Method == "" {
		return r, ipc.ErrFrame
	}
	if len(r.ID) > 0 {
		var s string
		var n json.Number
		if string(r.ID) == "null" || (json.Unmarshal(r.ID, &s) != nil && json.Unmarshal(r.ID, &n) != nil) {
			return r, ipc.ErrFrame
		}
	}
	return r, nil
}
func Setup(r Request) (Response, bool) {
	out := Response{JSONRPC: "2.0", ID: r.ID}
	switch r.Method {
	case "initialize":
		out.Result = map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "telara-memory", "version": Version}}
		return out, true
	case "tools/list":
		out.Result = map[string]any{"tools": []any{}}
		return out, true
	}
	return out, false
}
func Probe(ctx context.Context, p ipc.Paths) (Response, error) {
	c, e := ipc.Dial(ctx, p)
	if e != nil {
		return Response{}, e
	}
	defer c.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if e = c.SetDeadline(deadline); e != nil {
			return Response{}, e
		}
	}
	h := ipc.Hello{T: "hello", V: ipc.WireVersion, Kind: "control", PID: os.Getpid(), Client: "status", NodeVersion: Version}
	if e = ipc.WriteFrame(c, h); e != nil {
		return Response{}, e
	}
	r := bufio.NewReader(c)
	b, e := ipc.ReadFrame(r)
	if e != nil {
		return Response{}, e
	}
	var ack struct {
		T string `json:"t"`
		V int    `json:"v"`
	}
	if json.Unmarshal(b, &ack) != nil || ack.T != "hello" || ack.V != ipc.WireVersion {
		return Response{}, ipc.ErrFrame
	}
	if e = ipc.WriteFrame(c, Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "status"}); e != nil {
		return Response{}, e
	}
	b, e = ipc.ReadFrame(r)
	if e != nil {
		return Response{}, e
	}
	var out Response
	e = json.Unmarshal(b, &out)
	return out, e
}
func Run(ctx context.Context, cfg Config) error {
	p := cfg.Paths
	if e := p.Prepare(); e != nil {
		return e
	}
	startup, cancelStartup := context.WithTimeout(ctx, ipc.HandshakeTimeout)
	defer cancelStartup()
	var start io.Closer
	var e error
	for {
		start, e = ipc.Lock(filepath.Join(p.Data, "start.lock"))
		if e == nil {
			break
		}
		if !errors.Is(e, ipc.ErrBusy) {
			return e
		}
		probe, cancel := context.WithTimeout(startup, 100*time.Millisecond)
		_, pe := Probe(probe, p)
		cancel()
		if pe == nil {
			return nil
		}
		select {
		case <-startup.Done():
			return startup.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	defer start.Close()
	probe, cancel := context.WithTimeout(ctx, time.Second)
	_, e = Probe(probe, p)
	cancel()
	if e == nil {
		return nil
	}
	db, e := ipc.Lock(filepath.Join(p.Data, "db.lock"))
	if e != nil {
		return e
	}
	defer db.Close()
	l, e := ipc.Listen(p)
	if e != nil {
		return e
	}
	defer l.Close()
	if e = ipc.RecordOwner(p); e != nil {
		return e
	}
	defer ipc.Cleanup(p)
	var backend Backend
	if cfg.Open != nil {
		backend, e = cfg.Open(ctx)
		if e != nil {
			return e
		}
		defer func() {
			for backend.Close() != nil {
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}
	// Release startup serialization only once the listener and backend are ready.
	start.Close()
	var wg sync.WaitGroup
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	slots := make(chan struct{}, 64)
	serving, cancelServing := context.WithCancel(ctx)
	defer cancelServing()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
			mu.Lock()
			for c := range active {
				c.Close()
			}
			mu.Unlock()
		case <-done:
		}
	}()
	if cfg.Ready != nil {
		cfg.Ready()
	}
	var acceptErr error
	for {
		conn, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				break
			}
			var temporary interface{ Temporary() bool }
			if errors.As(e, &temporary) && temporary.Temporary() {
				select {
				case <-ctx.Done():
				case <-time.After(10 * time.Millisecond):
				}
				continue
			}
			acceptErr = e
			cancelServing()
			break
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		mu.Lock()
		active[conn] = true
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots; mu.Lock(); delete(active, conn); mu.Unlock(); conn.Close() }()
			serve(serving, conn, backend)
		}()
	}
	cancelServing()
	mu.Lock()
	for c := range active {
		c.Close()
	}
	mu.Unlock()
	// Deliberately retain db.lock while any backend call is unsettled.
	wg.Wait()
	if acceptErr != nil {
		return acceptErr
	}
	return ctx.Err()
}
func serve(parent context.Context, c net.Conn, backend Backend) {
	pid, e := ipc.Peer(c)
	if e != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if c.SetDeadline(time.Now().Add(ipc.HandshakeTimeout)) != nil {
		return
	}
	r := bufio.NewReader(c)
	b, e := ipc.ReadFrame(r)
	if e != nil {
		ipc.WriteFrame(c, map[string]string{"error": "invalid_frame"})
		return
	}
	var tag struct {
		T string `json:"t"`
	}
	json.Unmarshal(b, &tag)
	if tag.T == "nudge" {
		var n struct {
			T      string `json:"t"`
			V      int    `json:"v"`
			Client string `json:"client"`
		}
		if ipc.DecodeStrict(b, &n) == nil && n.V == 1 && n.Client != "" {
			if wake, ok := backend.(interface{ Nudge(string) }); ok {
				wake.Nudge(n.Client)
			}
		}
		return
	}
	var h ipc.Hello
	if ipc.DecodeStrict(b, &h) != nil || !h.Valid() || h.PID != pid {
		ipc.WriteFrame(c, map[string]string{"error": "invalid_hello"})
		return
	}
	token := make([]byte, 16)
	if _, e = rand.Read(token); e != nil {
		return
	}
	if ipc.WriteFrame(c, map[string]any{"t": "hello", "v": ipc.WireVersion, "connection_id": hex.EncodeToString(token)}) != nil {
		return
	}
	if c.SetDeadline(time.Time{}) != nil {
		return
	}
	var writeMu sync.Mutex
	write := func(v any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if e := c.SetWriteDeadline(time.Now().Add(ipc.HandshakeTimeout)); e != nil {
			cancel()
			c.Close()
			return e
		}
		e := ipc.WriteFrame(c, v)
		if e != nil {
			cancel()
			c.Close()
		}
		return e
	}
	slots := make(chan struct{}, ipc.MaxInFlight)
	var calls sync.WaitGroup
	defer calls.Wait()
	for {
		b, e = ipc.ReadFrame(r)
		if e != nil {
			if !errors.Is(e, io.EOF) {
				write(map[string]string{"error": "invalid_frame"})
			}
			cancel()
			return
		}
		req, e := Parse(b)
		if e != nil {
			write(map[string]string{"error": "invalid_request"})
			cancel()
			return
		}
		if len(req.ID) == 0 {
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			if write(Error(req.ID, "busy")) != nil {
				return
			}
			continue
		}
		calls.Add(1)
		go func(req Request) {
			defer calls.Done()
			defer func() { <-slots }()
			var out Response
			if req.Method == "status" {
				out = Response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"state": "running", "pid": os.Getpid(), "store_wired": backend != nil, "autostart": "refused_unverified_install"}}
			} else if setup, ok := Setup(req); ok {
				out = setup
			} else if h.Kind != "mcp" {
				out = Error(req.ID, "unsupported_control")
			} else if backend == nil {
				out = Error(req.ID, "store_unavailable")
			} else {
				out = backend.Handle(ctx, h, req)
				out.JSONRPC = "2.0"
				out.ID = req.ID
			}
			if ctx.Err() == nil {
				write(out)
			}
		}(req)
	}
}
