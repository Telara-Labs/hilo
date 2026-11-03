package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

// ErrSettlement means shutdown could not be proved. It never authorizes handoff.
var ErrSettlement = errors.New("settlement_unknown")

// lifecycle serializes shutdown against call admission and connection admission.
// Existing calls retain their contexts and response writers during a drain.
type lifecycle struct {
	mu        sync.Mutex
	draining  bool
	listener  net.Listener
	active    map[net.Conn]bool
	control   net.Conn
	controlID json.RawMessage
}

func (s *lifecycle) isDraining() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.draining }
func (s *lifecycle) admit(add func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining {
		return false
	}
	add()
	return true
}
func (s *lifecycle) drain(c net.Conn, id json.RawMessage) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining {
		return false
	}
	s.draining = true
	s.control, s.controlID = c, append(json.RawMessage(nil), id...)
	s.listener.Close()
	for conn := range s.active {
		if conn != c {
			_ = conn.SetReadDeadline(time.Now())
		}
	}
	return true
}
func (s *lifecycle) closeConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.active {
		c.Close()
	}
}
func (s *lifecycle) settled(p ipc.Paths) {
	if err := writeSettlement(p, true); err != nil {
		if s.control != nil {
			s.control.Close()
		}
		return
	}
	// Run calls this only after all handlers settled and Backend.Close succeeded,
	// while it still holds db.lock. Failure to deliver the receipt stays unknown.
	if s.control != nil {
		defer s.control.Close()
		_ = s.control.SetWriteDeadline(time.Now().Add(ipc.HandshakeTimeout))
		_ = ipc.WriteFrame(s.control, Response{JSONRPC: "2.0", ID: s.controlID, Result: map[string]any{"state": "settled"}})
	}
}

// Quiesce authenticates the daemon's kernel peer, pins its process lifetime,
// requests a graceful drain and requires an explicit settlement receipt, actual
// process exit and exclusive db.lock acquisition. It never signals a process.
// An absent daemon needs a retained clean-close receipt and process-exit proof.
// A crash or missing receipt is unknown, even when db.lock is free.
func Quiesce(ctx context.Context, p ipc.Paths) error {
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return ErrSettlement
	}
	// Windows retries an absent pipe until the dial deadline. Reserve the
	// lifecycle context for receipt, process-exit and exclusive-lock proof.
	dialCtx, cancelDial := context.WithTimeout(ctx, 100*time.Millisecond)
	c, err := ipc.Dial(dialCtx, p)
	cancelDial()
	if err != nil {
		return proveStopped(ctx, p, 0)
	}
	defer c.Close()
	pid, err := ipc.Peer(c)
	if err != nil || pid == os.Getpid() {
		return ErrSettlement
	}
	wait, release, err := watchProcess(pid)
	if err != nil {
		return ErrSettlement
	}
	defer release()
	deadline, _ := ctx.Deadline()
	if err = c.SetDeadline(deadline); err != nil {
		return ErrSettlement
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-done:
		}
	}()
	h := ipc.Hello{T: "hello", V: ipc.WireVersion, Kind: "control", PID: os.Getpid(), Client: "lifecycle", NodeVersion: Version}
	if ipc.WriteFrame(c, h) != nil {
		return ErrSettlement
	}
	r := bufio.NewReader(c)
	raw, err := ipc.ReadFrame(r)
	var ack struct {
		T          string `json:"t"`
		V          int    `json:"v"`
		Connection string `json:"connection_id"`
	}
	if err != nil || ipc.DecodeStrict(raw, &ack) != nil || ack.T != "hello" || ack.V != ipc.WireVersion || ack.Connection == "" {
		return ErrSettlement
	}
	if ipc.WriteFrame(c, Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "drain-and-exit"}) != nil {
		return ErrSettlement
	}
	raw, err = ipc.ReadFrame(r)
	var receipt struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			State      string `json:"state"`
			ResultType string `json:"resultType"`
		} `json:"result"`
	}
	if err != nil || ipc.DecodeStrict(raw, &receipt) != nil || receipt.JSONRPC != "2.0" || receipt.ID != 1 || receipt.Result.State != "settled" || receipt.Result.ResultType != "complete" {
		return ErrSettlement
	}
	if wait(ctx) != nil {
		return ErrSettlement
	}
	return proveStopped(ctx, p, pid)
}
