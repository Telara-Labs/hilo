//go:build darwin && cgo

package vault

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/mcp"
	"github.com/Telara-Labs/hilo/contract/internal/node/peer"
	"github.com/Telara-Labs/hilo/contract/internal/node/shim"
)

var liveInstalled = flag.Bool("live-installed-authority", false, "Exercise an isolated native keychain and temporary real service installation")

// The test executable doubles as a disposable installed process. The driver
// uses the actual installer, daemon, SQLite adapter, native vault and stdio shim.
// Its keychain selection exists only in this test binary, never in wire input.
func TestMain(m *testing.M) {
	// Simulates an older authenticated helper protocol while retaining native
	// custody/cleanup, so the regression also exercises historical staging items.
	if custodyBuild == "older-helper" && len(os.Args) == 2 && os.Args[1] == capabilityArg {
		_, _ = io.Copy(io.Discard, io.LimitReader(os.Stdin, 7))
		_, _ = os.Stdout.Write([]byte{'T', 'M', 'V', 'C', 0, 0, 7})
		return
	}
	if runCustodyUpgradeFixture(os.Args[1:]) {
		return
	}
	if RunHelper(os.Args[1:], os.Stdin, os.Stdout) {
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "managed-daemon" || os.Args[1] == "authority-test-shim") {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
		defer cancel()
		var err error
		if os.Args[1] == "authority-test-shim" {
			if len(os.Args) != 4 {
				os.Exit(2)
			}
			p, e := ipc.Resolve(os.Args[2], os.Args[3])
			err = e
			if err == nil {
				err = shim.Run(ctx, os.Stdin, os.Stdout, shim.Config{Paths: p})
			}
		} else {
			if len(os.Args) != 4 || os.Args[2] != "--install-dir" {
				os.Exit(2)
			}
			dir := os.Args[3]
			r, e := install.VerifyRunning(dir)
			err = e
			if err == nil {
				var v *Vault
				v, err = openIsolated(filepath.Join(r.DataDir, "authority-test.keychain"))
				if err == nil {
					defer v.closeIsolated()
					p, e := ipc.Resolve(r.DataDir, r.RunDir)
					err = e
					if err == nil {
						provider := mcp.InstalledRuntimeProvider{Provider: disclosure.InstalledProvider{Dir: r.DataDir, Vault: peer.GuardVault(v), Peers: peer.Authority{InstallDir: dir, DataDir: r.DataDir}}}
						if _, e := os.Lstat(filepath.Join(r.DataDir, "authority-test.pending")); !os.IsNotExist(e) {
							return
						}
						err = daemon.Run(ctx, daemon.Config{CustodyHandoff: func(ctx context.Context, raw json.RawMessage) error {
							var req struct {
								Digest string `json:"sha256"`
							}
							if ipc.DecodeStrict(raw, &req) != nil {
								return install.ErrUnverified
							}
							if e := peer.VerifyLifecycle(ctx, r); e != nil {
								return e
							}
							if e := v.PrepareUpgrade(ctx, r, req.Digest); e != nil {
								return e
							}
							return peer.VerifyLifecycle(ctx, r)
						}, BindConnection: peer.BindConnection, Paths: p, Verify: func() error {
							current, e := install.VerifyRunning(dir)
							if e != nil {
								return e
							}
							if current != r {
								return install.ErrUnverified
							}
							return nil
						}, Open: func(ctx context.Context) (daemon.Backend, error) {
							if e := v.RecoverUpgrade(ctx, r); e != nil {
								return nil, e
							}
							return mcp.Open(ctx, r.DataDir, provider)
						}})
					}
				}
			}
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	os.Exit(m.Run())
}

func TestInstalledNativeDaemonShimTaskRoundTrip(t *testing.T) {
	if !*liveInstalled {
		t.Skip("requires explicit -live-installed-authority for a temporary native service installation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	if err = os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	p, err := ipc.Resolve(filepath.Join(home, "data"), filepath.Join(home, "run"))
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Prepare(); err != nil {
		t.Fatal(err)
	}
	password := make([]byte, 32)
	if _, err = rand.Read(password); err != nil {
		t.Fatal(err)
	}
	v, err := createIsolated(filepath.Join(p.Data, "authority-test.keychain"), password)
	clear(password)
	if err != nil {
		t.Fatal("isolated native keychain prerequisite", err)
	}
	t.Cleanup(v.closeIsolated)
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Install refuses any symlinked path component; /var is one on macOS.
	if source, err = filepath.EvalSymlinks(source); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(b)
	dir := filepath.Join(home, "install")
	var manual *exec.Cmd
	// Register cleanup before the first install/manager mutation, including its
	// partial-failure paths. Keep the isolated keychain open through deletion.
	t.Cleanup(func() {
		if manual != nil {
			defer func() { _ = manual.Process.Signal(syscall.SIGTERM); _ = manual.Wait() }()
		}
		if _, e := os.Lstat(filepath.Join(dir, "install.json")); os.IsNotExist(e) {
			return
		}
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		err := install.Uninstall(c, dir, func(ctx context.Context) error {
			if _, err := os.Lstat(filepath.Join(p.Data, "authority-test.pending")); !os.IsNotExist(err) {
				lock, err := ipc.Lock(filepath.Join(p.Data, "db.lock"))
				if err != nil {
					return err
				}
				defer lock.Close()
				if _, err = os.Lstat(filepath.Join(p.Data, "installed-authority.json")); os.IsNotExist(err) {
					return nil
				}
				return disclosure.DeleteInstalledSecret(ctx, p.Data, v)
			}
			if err := daemon.Quiesce(ctx, p); err != nil {
				return err
			}
			lock, err := ipc.Lock(filepath.Join(p.Data, "db.lock"))
			if err != nil {
				return err
			}
			defer lock.Close()
			if _, err := os.Lstat(filepath.Join(p.Data, "installed-authority.json")); os.IsNotExist(err) {
				return nil
			}
			return disclosure.DeleteInstalledSecret(ctx, p.Data, v)
		})
		if err != nil {
			t.Error("temporary installation cleanup", err)
		}
	})
	admission, err := ipc.Lock(filepath.Join(p.Data, "db.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Close()
	if err = os.WriteFile(filepath.Join(p.Data, "authority-test.pending"), []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := install.Install(ctx, install.Config{Dir: dir, Home: home, Label: "dev.memory.authority." + hex.EncodeToString(hash[:8]) + fmt.Sprint(time.Now().UnixNano()), Executable: source, SHA256: hex.EncodeToString(hash[:]), Version: "test", DataDir: p.Data, RunDir: p.Run})
	if err != nil && !errors.Is(err, install.ErrUnavailable) {
		t.Fatal(err)
	}
	managerUnavailable := errors.Is(err, install.ErrUnavailable)
	if err = disclosure.BootstrapInstalled(ctx, p.Data, "Installed local clients", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S, disclosure.P, disclosure.E}}, disclosure.TaskWriteGrant{Repos: disclosure.AllLocalRepos(), AllowUnscoped: true, Actions: []disclosure.TaskMutation{disclosure.Create, disclosure.Checkpoint, disclosure.Pause, disclosure.Complete}}, v); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(p.Data, "authority-test.pending")); err != nil {
		t.Fatal(err)
	}
	if err = admission.Close(); err != nil {
		t.Fatal(err)
	}
	if managerUnavailable {
		t.Log("service manager unavailable; explicitly launch the verified managed entrypoint for transport acceptance")
		cmd := exec.Command(r.Record.Executable, "managed-daemon", "--install-dir", dir)
		cmd.Env = replaceHome(os.Environ(), home)
		cmd.Stderr = os.Stderr
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		manual = cmd
	} else if err = install.Start(ctx, dir); err != nil {
		t.Fatal(err)
	}
	for {
		probe, c := context.WithTimeout(ctx, 100*time.Millisecond)
		_, e := daemon.Probe(probe, p)
		c()
		if e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("readiness", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	call := func(exe, tool string, args map[string]any) []byte {
		cmd := exec.CommandContext(ctx, exe, "authority-test-shim", p.Data, p.Run)
		cmd.Env = replaceHome(os.Environ(), home)
		in, e := cmd.StdinPipe()
		if e != nil {
			t.Fatal(e)
		}
		out, e := cmd.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		cmd.Stderr = os.Stderr
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		params, _ := json.Marshal(map[string]any{"name": tool, "arguments": args, "_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": map[string]any{}}})
		if e = ipc.WriteFrame(in, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params}); e != nil {
			t.Fatal(e)
		}
		raw, e := ipc.ReadFrame(bufio.NewReader(out))
		in.Close()
		_, _ = io.Copy(io.Discard, out)
		wait := cmd.Wait()
		if e != nil || wait != nil {
			t.Fatal("shim", e, wait)
		}
		return raw
	}
	created := call(r.Record.Executable, "telara_task_create", map[string]any{"goal": "native installed authority round trip"})
	if !bytes.Contains(created, []byte("task_id")) || !bytes.Contains(created, []byte("native installed authority round trip")) {
		t.Fatalf("create %s", created)
	}
	listed := call(r.Record.Executable, "telara_task_list", map[string]any{"include_completed": true, "mode": "detail"})
	if !bytes.Contains(listed, []byte("native installed authority round trip")) {
		t.Fatalf("list %s", listed)
	}
	refused := call(source, "telara_task_create", map[string]any{"goal": "must never persist"})
	if !bytes.Contains(refused, []byte(`"isError":true`)) || bytes.Contains(refused, []byte("task_id")) {
		t.Fatalf("noninstalled image accepted %s", refused)
	}
	listed = call(r.Record.Executable, "telara_task_list", map[string]any{"include_completed": true, "mode": "detail"})
	if bytes.Contains(listed, []byte("must never persist")) {
		t.Fatal("refused task persisted")
	}
}

func replaceHome(environ []string, home string) []string {
	out := make([]string, 0, len(environ)+1)
	for _, s := range environ {
		if !strings.HasPrefix(s, "HOME=") {
			out = append(out, s)
		}
	}
	return append(out, "HOME="+home)
}
