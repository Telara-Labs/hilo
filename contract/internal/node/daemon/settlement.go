package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
)

type settlement struct {
	Schema int    `json:"schema"`
	PID    int    `json:"pid"`
	Data   string `json:"data"`
	Run    string `json:"run"`
}

// This receipt is invalidated under db.lock before any backend is opened. It is
// written only after every admitted call and Backend.Close settle, before db.lock
// is released. Empty, malformed, stale or missing receipts prove nothing.
func writeSettlement(p ipc.Paths, clean bool) error {
	f, err := ipc.Lock(filepath.Join(p.Data, "shutdown.receipt"))
	if err != nil {
		return err
	}
	defer f.Close()
	if err = f.Truncate(0); err != nil {
		return err
	}
	if clean {
		if err = json.NewEncoder(f).Encode(settlement{1, os.Getpid(), p.Data, p.Run}); err != nil {
			return err
		}
	}
	return f.Sync()
}
func proveStopped(ctx context.Context, p ipc.Paths, expectedPID int) error {
	if ctx.Err() != nil {
		return ErrSettlement
	}
	db, err := ipc.Lock(filepath.Join(p.Data, "db.lock"))
	if err != nil {
		return ErrSettlement
	}
	defer db.Close()
	f, err := ipc.Lock(filepath.Join(p.Data, "shutdown.receipt"))
	if err != nil {
		return ErrSettlement
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		return ErrSettlement
	}
	if _, err := jcs.Canonicalize(raw); err != nil {
		return ErrSettlement
	}
	var receipt settlement
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil {
		return ErrSettlement
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrSettlement
	}
	if receipt.Schema != 1 || receipt.PID <= 0 || receipt.Data != p.Data || receipt.Run != p.Run || (expectedPID != 0 && receipt.PID != expectedPID) {
		return ErrSettlement
	}
	if receipt.PID == os.Getpid() {
		return ErrSettlement
	}
	wait, release, err := watchProcess(receipt.PID)
	if processAbsent(err) {
		if ctx.Err() != nil {
			return ErrSettlement
		}
		return nil
	}
	if err != nil {
		return ErrSettlement
	}
	defer release()
	if wait(ctx) != nil {
		return ErrSettlement
	}
	return nil
}
