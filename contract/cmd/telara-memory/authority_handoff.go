package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/peer"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
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
	if vault.UpgradeHandoffRequired() {
		// A prior daemon may predate capability negotiation. Derive only the install
		// directory from durable creator evidence, then revalidate the current receipt.
		pending, e := readPending(p.Data)
		if e != nil || pending.Creator == nil {
			return install.ErrUnverified
		}
		report, e := install.Status(ctx, pending.Creator.Dir)
		if e != nil && !errors.Is(e, install.ErrUnavailable) {
			return install.ErrUnverified
		}
		paths, e := ipc.Resolve(report.Record.DataDir, report.Record.RunDir)
		if e != nil || paths.Data != p.Data || paths.Run != p.Run || paths.Endpoint != p.Endpoint {
			return install.ErrUnverified
		}
		if e = vault.CheckUpgradeTarget(ctx, report.Record, digest); e != nil {
			return e
		}
	}
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
type installationCustody interface {
	disclosure.SecretVault
	DeleteForInstall(context.Context, install.Record, string) error
	DeleteCreatedForInstall(context.Context, install.Record, string) error
	ReadForInstall(context.Context, install.Record, string) ([]byte, error)
}

type installedDeletionVault struct {
	installationCustody
	record install.Record
}

func (v installedDeletionVault) Delete(ctx context.Context, handle string) error {
	p, e := readPending(v.record.DataDir)
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if e == nil && p.Phase != "provisioning" && p.Creator == nil && vault.UpgradeHandoffRequired() {
		if p.Handle != handle {
			return install.ErrUnverified
		}
		// Old installers could bind custody to a different calling build. Absence
		// in the receipt image is not deletion proof. A successful own-slot read
		// establishes custody, then persist it before any idempotent deletion.
		secret, err := v.installationCustody.ReadForInstall(ctx, v.record, handle)
		size := len(secret)
		clear(secret)
		if err != nil || size != 96 {
			return install.ErrUnverified
		}
		p.Creator = &v.record
		if err = writePending(v.record.DataDir, p); err != nil {
			return err
		}
	}
	if e == nil && p.Phase == "provisioning" {
		if p.Handle != handle {
			return install.ErrUnverified
		}
		if p.Creator == nil {
			return install.ErrUnverified
		} else if !validAuthorityCreator(*p.Creator, v.record.DataDir) || *p.Creator != v.record {
			return install.ErrUnverified
		}
		// An interrupted provision can already have a valid manifest and a
		// prepared transfer. Use the full staging-aware path when it does.
		path := filepath.Join(v.record.DataDir, "installed-authority.json")
		if st, e := os.Lstat(path); e == nil {
			if !safeAuthorityFile(path, st) {
				return install.ErrUnverified
			}
			raw, e := store.ReadInstalledRecord(v.record.DataDir)
			if e != nil {
				return e
			}
			var m struct {
				Version    int    `json:"version"`
				Owner      string `json:"owner"`
				Machine    string `json:"machine"`
				Credential string `json:"credential"`
				Handle     string `json:"vault_handle"`
			}
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			if d.Decode(&m) == nil && d.Decode(new(any)) == io.EOF && m.Version == 1 && len(m.Handle) == 32 {
				if m.Handle != handle {
					return install.ErrUnverified
				}
				return v.installationCustody.DeleteForInstall(ctx, v.record, handle)
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		// No manifest is required for a crash during provisioning. The durable
		// creator and handle precede Put and the receipt must still select it.
		if _, e := os.Lstat(filepath.Join(v.record.DataDir, "custody-upgrade.json")); !os.IsNotExist(e) {
			return install.ErrUnverified
		}
		return v.installationCustody.DeleteCreatedForInstall(ctx, v.record, handle)
	}
	return v.installationCustody.DeleteForInstall(ctx, v.record, handle)
}
