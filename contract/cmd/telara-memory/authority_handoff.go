package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/peer"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/vault"
)

type custodyRequest struct {
	Digest string `json:"sha256"`
}

func installedCustodyHandoff(record install.Record) func(context.Context, json.RawMessage) error {
	return func(ctx context.Context, raw json.RawMessage) error {
		var req custodyRequest
		if ipc.DecodeStrict(raw, &req) != nil {
			return install.ErrUnverified
		}
		if e := peer.VerifyLifecycle(ctx, record); e != nil {
			return e
		}
		if e := vault.New().PrepareUpgrade(ctx, record, req.Digest); e != nil {
			return e
		}
		return peer.VerifyLifecycle(ctx, record)
	}
}

func requestCustodyHandoff(ctx context.Context, p ipc.Paths, digest string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c, e := ipc.Dial(ctx, p)
	if e != nil {
		return e
	}
	defer c.Close()
	pid, e := ipc.Peer(c)
	if e != nil || pid == os.Getpid() {
		return ipc.ErrPeer
	}
	deadline, _ := ctx.Deadline()
	if e = c.SetDeadline(deadline); e != nil {
		return e
	}
	h := ipc.Hello{T: "hello", V: ipc.WireVersion, Kind: "control", PID: os.Getpid(), Client: "lifecycle", NodeVersion: daemon.Version}
	if e = ipc.WriteFrame(c, h); e != nil {
		return e
	}
	reader := bufio.NewReader(c)
	raw, e := ipc.ReadFrame(reader)
	if e != nil {
		return e
	}
	var ack struct {
		T          string `json:"t"`
		V          int    `json:"v"`
		Connection string `json:"connection_id"`
	}
	if ipc.DecodeStrict(raw, &ack) != nil || ack.T != "hello" || ack.V != ipc.WireVersion || ack.Connection == "" {
		return ipc.ErrFrame
	}
	params, _ := json.Marshal(custodyRequest{digest})
	if e = ipc.WriteFrame(c, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "custody-handoff", "params": json.RawMessage(params)}); e != nil {
		return e
	}
	raw, e = ipc.ReadFrame(reader)
	if e != nil {
		return e
	}
	var response struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			State      string `json:"state"`
			ResultType string `json:"resultType"`
		} `json:"result"`
	}
	if ipc.DecodeStrict(raw, &response) != nil || response.JSONRPC != "2.0" || response.ID != 1 || response.Result.State != "custody_ready" || response.Result.ResultType != "complete" {
		return errors.New("custody_handoff_unavailable")
	}
	return nil
}

// The owning retained image deletes its native item after settled uninstall.
// This also removes staging custody left by an interrupted upgrade.
type installedDeletionVault struct {
	*vault.Vault
	record install.Record
}

func (v installedDeletionVault) Delete(ctx context.Context, handle string) error {
	return v.Vault.DeleteForInstall(ctx, v.record, handle)
}
