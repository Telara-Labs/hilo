package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

func TestSettlementReceiptInvalidationAndUnknown(t *testing.T) {
	base := t.TempDir()
	os.Chmod(base, 0700)
	p, err := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(p.Run)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, raw := range []string{"", `{}`, `{"schema":1,"schema":1}`, `{"schema":1} {}`, `[]`} {
		if err := os.WriteFile(filepath.Join(p.Data, "shutdown.receipt"), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if err := proveStopped(ctx, p, 0); !errors.Is(err, ErrSettlement) {
			t.Fatal("unproven settlement", err)
		}
	}
	if err := writeSettlement(p, true); err != nil {
		t.Fatal(err)
	}
	if err := proveStopped(ctx, p, 0); !errors.Is(err, ErrSettlement) {
		t.Fatal("self is not exited", err)
	}
	if err := writeSettlement(p, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(p.Data, "shutdown.receipt"))
	if err != nil || len(b) != 0 {
		t.Fatal("old receipt survived startup", err)
	}
	ctxCancelled, cancelEarly := context.WithCancel(ctx)
	cancelEarly()
	if Quiesce(ctxCancelled, p) == nil {
		t.Fatal("cancelled quiesce accepted")
	}
	if Quiesce(context.Background(), p) == nil {
		t.Fatal("unbounded quiesce accepted")
	}
}

func TestDrainAdmissionFence(t *testing.T) {
	life := &lifecycle{}
	calls := 0
	if !life.admit(func() { calls++ }) {
		t.Fatal("normal admission refused")
	}
	life.draining = true
	if life.admit(func() { calls++ }) || calls != 1 {
		t.Fatal("admission escaped drain")
	}
}

func TestStartupVerificationHoldsWriterLockBeforeStorage(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	p, err := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Prepare(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(p.Run) })
	if err := writeSettlement(p, true); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(p.Data, "shutdown.receipt")
	prior, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	refused := errors.New("startup authority revoked")
	verified, opened := false, false
	err = Run(context.Background(), Config{Paths: p, Verify: func() error {
		verified = true
		lock, err := ipc.Lock(filepath.Join(p.Data, "db.lock"))
		if lock != nil {
			lock.Close()
		}
		if !errors.Is(err, ipc.ErrBusy) {
			t.Fatal("verification ran without writer lock", err)
		}
		return refused
	}, Open: func(context.Context) (Backend, error) {
		opened = true
		return nil, nil
	}})
	if !errors.Is(err, refused) || !verified || opened {
		t.Fatalf("verification %v, open %v, error %v", verified, opened, err)
	}
	after, err := os.ReadFile(receiptPath)
	if err != nil || string(after) != string(prior) {
		t.Fatal("verification failure invalidated receipt", err)
	}
	lock, err := ipc.Lock(filepath.Join(p.Data, "db.lock"))
	if err != nil {
		t.Fatal("verification failure retained writer lock", err)
	}
	lock.Close()
}
