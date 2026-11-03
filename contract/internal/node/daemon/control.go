package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"os"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

// Call sends one owner control request on a direct control connection and
// returns the daemon's response. The deadline of ctx bounds the whole exchange.
func Call(ctx context.Context, p ipc.Paths, client, method string, params any) (Response, error) {
	c, err := ipc.Dial(ctx, p)
	if err != nil {
		return Response{}, err
	}
	defer c.Close()
	if _, err = ipc.Peer(c); err != nil {
		return Response{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err = c.SetDeadline(deadline); err != nil {
			return Response{}, err
		}
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
	h := ipc.Hello{T: "hello", V: ipc.WireVersion, Kind: "control", PID: os.Getpid(), Client: client, NodeVersion: Version}
	if err = ipc.WriteFrame(c, h); err != nil {
		return Response{}, err
	}
	r := bufio.NewReader(c)
	b, err := ipc.ReadFrame(r)
	if err != nil {
		return Response{}, err
	}
	var ack struct {
		T string `json:"t"`
		V int    `json:"v"`
	}
	if json.Unmarshal(b, &ack) != nil || ack.T != "hello" || ack.V != ipc.WireVersion {
		return Response{}, ipc.ErrFrame
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return Response{}, ipc.ErrFrame
	}
	if err = ipc.WriteFrame(c, Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: method, Params: raw}); err != nil {
		return Response{}, err
	}
	if b, err = ipc.ReadFrame(r); err != nil {
		return Response{}, err
	}
	var out struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result,omitempty"`
		Error   *RPCError       `json:"error,omitempty"`
	}
	if json.Unmarshal(b, &out) != nil || out.JSONRPC != "2.0" || string(out.ID) != "1" {
		return Response{}, ipc.ErrFrame
	}
	return Response{JSONRPC: out.JSONRPC, ID: out.ID, Result: out.Result, Error: out.Error}, nil
}
