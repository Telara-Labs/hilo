package peer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

func TestAuthorityNeverTrustsHelloAlone(t *testing.T) {
	a := Authority{InstallDir: t.TempDir(), DataDir: t.TempDir(), Drain: func(context.Context, string) error { t.Fatal("drain before authentication"); return nil }}
	for _, pid := range []int{0, -1, os.Getpid()} {
		if err := a.VerifyAndDrain(context.Background(), ipc.Hello{PID: pid, Client: "installed", Cwd: a.InstallDir}, "credential"); err == nil {
			t.Fatal("hello granted authority")
		}
	}
	if err := a.VerifyAndDrain(nil, ipc.Hello{PID: os.Getpid()}, "credential"); err == nil {
		t.Fatal("nil context")
	}
	if err := a.verify(os.Getpid()); err == nil {
		t.Fatal("missing receipt")
	}
}

func TestProcessImageRequiresLivePID(t *testing.T) {
	for _, pid := range []int{0, -1, 2147483647} {
		if _, _, err := executable(pid); err == nil {
			t.Fatal(pid)
		}
	}
}

func TestSpoolRequiresEmptySafeDirectories(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	if err := ipc.ValidateDir(data, true); err != nil {
		t.Fatal(err)
	}
	if err := emptySpool(data); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(data, "spool", "codex", "new")
	if err := ipc.ValidateDir(p, true); err != nil {
		t.Fatal(err)
	}
	if err := emptySpool(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "signal.json"), []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := emptySpool(data); err == nil {
		t.Fatal("pending signal ignored")
	}
	if err := emptySpool("relative"); err == nil {
		t.Fatal("relative spool")
	}
}

type guardTestVault struct {
	cancel   context.CancelFunc
	returned []byte
}

func (v *guardTestVault) Put(context.Context, string, []byte) error { return nil }
func (v *guardTestVault) Delete(context.Context, string) error      { return nil }
func (v *guardTestVault) Get(context.Context, string) ([]byte, error) {
	if v.cancel != nil {
		v.cancel()
	}
	v.returned = []byte("synthetic")
	return v.returned, nil
}
func TestVaultGuardClearsMaterialWhenCustodyOutlivesContext(t *testing.T) {
	ctx, c := context.WithCancel(context.Background())
	defer c()
	v := &guardTestVault{cancel: c}
	if b, e := GuardVault(v).Get(ctx, "handle"); b != nil || e == nil {
		t.Fatal("cancelled custody returned material")
	}
	for _, b := range v.returned {
		if b != 0 {
			t.Fatal("failed custody material retained")
		}
	}
	v = &guardTestVault{}
	b, e := GuardVault(v).Get(context.Background(), "handle")
	if e != nil || string(b) != "synthetic" {
		t.Fatal("startup custody", e)
	}
	clear(b)
}

func TestVaultGuardRejectsMissingInputs(t *testing.T) {
	if b, e := GuardVault(nil).Get(context.Background(), "h"); b != nil || e == nil {
		t.Fatal("nil vault")
	}
	if b, e := GuardVault(&guardTestVault{}).Get(nil, "h"); b != nil || e == nil {
		t.Fatal("nil context")
	}
}
