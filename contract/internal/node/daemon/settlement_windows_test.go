package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

func TestWindowsQuiesceAbsentPipeRetainsSettlementBudget(t *testing.T) {
	base := t.TempDir()
	p, err := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Prepare(); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// An actual exited process supplies the clean-close receipt's identity.
	// Retain a kernel handle so its PID cannot be reused during the proof.
	child := exec.Command(exe, "-test.run=^$")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Process.Kill() })
	_, release, err := watchProcess(child.Process.Pid)
	if err != nil {
		child.Process.Kill()
		child.Wait()
		t.Fatal(err)
	}
	defer release()
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(settlement{1, child.Process.Pid, p.Data, p.Run})
	if err != nil {
		t.Fatal(err)
	}
	f, err := ipc.Lock(filepath.Join(p.Data, "shutdown.receipt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// No listener exists. Windows Dial must exhaust only its short child
	// context, leaving enough lifecycle budget for retained-receipt proof.
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := Quiesce(ctx, p)
		parentErr := ctx.Err()
		cancel()
		if err != nil || parentErr != nil {
			t.Fatalf("already stopped attempt %d, quiesce %v, lifecycle %v", attempt, err, parentErr)
		}
	}
	// An absent pipe still cannot establish settlement with a live writer.
	lock, err := ipc.Lock(filepath.Join(p.Data, "db.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := Quiesce(ctx, p); !errors.Is(err, ErrSettlement) {
		t.Fatal("busy writer accepted", err)
	}
}
