package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

func interruptedPublication(t *testing.T, stage int) (upgradePublication, context.Context, string) {
	t.Helper()
	r, _ := receiptFixture(t)
	m := &managerFixture{record: r}
	ctx := adapted(m.command)
	if _, e := Register(ctx, r.Dir); e != nil {
		t.Fatal(e)
	}
	if e := ipc.ValidateDir(r.DataDir, true); e != nil {
		t.Fatal(e)
	}
	next := r
	next.Version = "successor"
	// A distinct source image catches digest and immutable-path mistakes.
	src := filepath.Join(r.Dir, "next-source")
	if e := writeAtomic(src, []byte("different executable image"), 0700); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte("different executable image"))
	digest := hex.EncodeToString(sum[:])
	next.SHA256, next.Executable = digest, imagePath(r.Dir, digest)
	if e := copyImage(src, next); e != nil {
		t.Fatal(e)
	}
	if e := writeIntent(r.Dir, r, "stop", ""); e != nil {
		t.Fatal(e)
	}
	p := upgradePublication{1, r, next}
	if e := writeJSON(filepath.Join(r.Dir, upgradePublicationFile), p); e != nil {
		t.Fatal(e)
	}
	if stage >= 1 {
		if e := writeJSON(filepath.Join(r.Dir, "install.json"), next); e != nil {
			t.Fatal(e)
		}
	}
	if stage >= 2 {
		b, _ := Definition(next.Platform, next)
		if e := writeAtomic(definitionPath(next), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if stage >= 3 {
		if e := writeIntent(r.Dir, next, "upgrade", ""); e != nil {
			t.Fatal(e)
		}
	}
	if runtime.GOOS == "darwin" {
		m.present = false
	}
	ctx = adapted(func(ctx context.Context, platform string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if (len(args) > 0 && (args[0] == "bootstrap" || args[0] == "/Create")) || joined == "--user daemon-reload" {
			m.record = next
		}
		return m.command(ctx, platform, args...)
	})
	if stage >= 4 {
		m.record = next
		m.present = true
	}
	return p, ctx, src
}

func TestInterruptedUpgradePublicationConverges(t *testing.T) {
	for stage := 0; stage <= 4; stage++ {
		for _, entry := range []string{"managed-startup", "upgrade-retry", "third-build-uninstall"} {
			t.Run(fmt.Sprintf("%d/%s", stage, entry), func(t *testing.T) {
				p, ctx, src := interruptedPublication(t, stage)
				switch entry {
				case "managed-startup":
					if e := ReconcileUpgrade(ctx, p.Source.Dir); e != nil {
						t.Fatal(e)
					}
					if _, e := VerifiedExecutable(p.Source.Dir); e != nil {
						t.Fatal(e)
					}
					// This test image is not B. Publication recovery cannot grant it admission.
					if _, e := VerifyRunning(p.Source.Dir); !errors.Is(e, ErrUnverified) {
						t.Fatal("self-path bypass", e)
					}
				case "upgrade-retry":
					if _, e := Upgrade(ctx, p.Source.Dir, src, p.Target.SHA256, p.Target.Version, func(context.Context) error { t.Fatal("settled transition quiesced again"); return nil }); e != nil {
						t.Fatal(e)
					}
				case "third-build-uninstall":
					called := false
					if e := Uninstall(ctx, p.Source.Dir, func(context.Context) error { called = true; return nil }); e != nil {
						t.Fatal(e)
					}
					if !called {
						t.Fatal("uninstall bypassed settlement")
					}
				}
				if _, e := os.Lstat(filepath.Join(p.Source.Dir, upgradePublicationFile)); !os.IsNotExist(e) {
					t.Fatal("journal retained", e)
				}
				if entry != "third-build-uninstall" {
					r, e := readReceipt(p.Source.Dir)
					if e != nil || r != p.Target || verifyDefinition(r) != nil || checkIntent(r.Dir, r) != nil {
						t.Fatal(r, e)
					}
				}
			})
		}
	}
}

func TestUpgradeReconciliationRefusesUnknownTransitionAndActiveWriter(t *testing.T) {
	for _, kind := range []string{"profile", "source-image", "target-image", "receipt", "definition", "intent", "journal", "writer"} {
		t.Run(kind, func(t *testing.T) {
			p, ctx, _ := interruptedPublication(t, 1)
			switch kind {
			case "profile":
				p.Target.DataDir += "other"
				_ = writeJSON(filepath.Join(p.Source.Dir, upgradePublicationFile), p)
			case "source-image":
				_ = os.WriteFile(p.Source.Executable, []byte("substituted"), 0700)
			case "target-image":
				_ = os.WriteFile(p.Target.Executable, []byte("substituted"), 0700)
			case "receipt":
				r := p.Target
				r.Label = "dev.unrelated"
				_ = writeJSON(filepath.Join(r.Dir, "install.json"), r)
			case "definition":
				_ = writeAtomic(definitionPath(p.Source), []byte("unrelated user definition"), 0600)
			case "intent":
				_ = writeIntent(p.Source.Dir, p.Source, "start", "")
			case "journal":
				_ = os.WriteFile(filepath.Join(p.Source.Dir, upgradePublicationFile), []byte("{"), 0600)
			case "writer":
				lock, e := ipc.Lock(filepath.Join(p.Source.DataDir, "db.lock"))
				if e != nil {
					t.Fatal(e)
				}
				defer lock.Close()
			}
			before, e := os.ReadFile(filepath.Join(p.Source.Dir, "install.json"))
			if e != nil {
				t.Fatal(e)
			}
			if e = ReconcileUpgrade(ctx, p.Source.Dir); e == nil {
				t.Fatal("untrusted reconciliation accepted")
			}
			after, _ := os.ReadFile(filepath.Join(p.Source.Dir, "install.json"))
			if string(before) != string(after) {
				t.Fatal("receipt mutated on refusal")
			}
			if _, e = os.Lstat(filepath.Join(p.Source.Dir, upgradePublicationFile)); e != nil {
				t.Fatal("journal lost", e)
			}
		})
	}
}

func TestOversizedInstallInputsRefuseBeforeMutation(t *testing.T) {
	root := testRoot(t)
	dir := filepath.Join(root, "must-not-exist")
	_, e := Install(context.Background(), Config{Dir: dir, Home: root, Label: "dev.memory.fixture", SHA256: strings.Repeat("a", 64), Version: "1", DataDir: filepath.Join(root, strings.Repeat("a", 17000)), RunDir: filepath.Join(root, "run")})
	if e == nil {
		t.Fatal("oversized receipt accepted")
	}
	if _, e = os.Lstat(dir); !os.IsNotExist(e) {
		t.Fatal("oversized input mutated install", e)
	}
}

func TestUpgradeReconciliationLaunchWaitsForLifecyclePublication(t *testing.T) {
	p, ctx, _ := interruptedPublication(t, 3)
	lock, e := lockInstall(p.Source.Dir)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	done := make(chan error, 1)
	go func() { done <- ReconcileUpgrade(ctx, p.Source.Dir) }()
	select {
	case e := <-done:
		t.Fatal("startup did not wait for publisher", e)
	case <-time.After(30 * time.Millisecond):
	}
	if e = lock.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("startup recovery deadlocked")
	}
	// The reconciler cannot publish even a file when its caller has cancelled.
	p, ctx, _ = interruptedPublication(t, 1)
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	before, _ := os.ReadFile(filepath.Join(p.Source.Dir, "install.json"))
	if e = ReconcileUpgrade(cancelCtx, p.Source.Dir); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(filepath.Join(p.Source.Dir, "install.json"))
	if string(before) != string(after) {
		t.Fatal("cancelled reconciliation mutated receipt")
	}
}
