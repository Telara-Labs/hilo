package peer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

func TestCaptureDrainUsesLiveCollectorAndPropagatesFailure(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	dir := filepath.Join(data, "spool", "codex", "new")
	if err := ipc.ValidateDir(dir, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "signal.json")
	if err := os.WriteFile(path, []byte("identity"), 0600); err != nil {
		t.Fatal(err)
	}
	a := Authority{DataDir: data}
	if err := a.drain(context.Background(), "credential"); err == nil {
		t.Fatal("pending signal bypassed without collector")
	}
	calls := 0
	ctx := daemon.WithCaptureDrain(context.Background(), func(_ context.Context, credential string) error {
		calls++
		if credential != "credential" {
			t.Fatal("credential changed")
		}
		return errors.New("admission unavailable")
	})
	if err := a.drain(ctx, "credential"); err == nil || calls != 1 {
		t.Fatal("collector error swallowed")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("failed drain lost signal")
	}
	ctx = daemon.WithCaptureDrain(context.Background(), func(context.Context, string) error { return nil })
	if err := a.drain(ctx, "credential"); err != nil {
		t.Fatal("processed pending identity refused", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("pending transcript prematurely removed", err)
	}
	ctx = daemon.WithCaptureDrain(context.Background(), func(context.Context, string) error { return os.Remove(path) })
	if err := a.drain(ctx, "credential"); err != nil {
		t.Fatal("drained spool refused", err)
	}
	if err := a.drain(context.Background(), "credential"); err != nil {
		t.Fatal(err)
	}
	// The existing explicit callback remains authoritative over the opener context.
	a.Drain = func(context.Context, string) error { return errors.New("explicit failure") }
	if err := a.drain(ctx, "credential"); err == nil {
		t.Fatal("explicit callback bypassed")
	}
}

func TestUnverifiedHelloCannotInvokeContextCapture(t *testing.T) {
	ctx := daemon.WithCaptureDrain(context.Background(), func(context.Context, string) error { t.Fatal("drain before peer verification"); return nil })
	if err := (Authority{}).VerifyAndDrain(ctx, ipc.Hello{PID: os.Getpid()}, "credential"); err == nil {
		t.Fatal("unverified hello accepted")
	}
}
