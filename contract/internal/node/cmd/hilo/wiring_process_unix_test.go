//go:build darwin || linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

func awaitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("missing fixture receipt", path)
}
func TestProcessDrainSettlesAndExits(t *testing.T) {
	p := testPaths(t)
	pr := launch(t, driver, p.Data, p.Run)
	waitReady(t, p)
	idle, err := ipc.Dial(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	c, r := wire(t, p)
	ipc.WriteFrame(c, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage("41"), Method: "settle"})
	awaitFile(t, filepath.Join(p.Data, "entered"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- daemon.Quiesce(ctx, p) }()
	time.Sleep(80 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatal("unsettled drain returned", err)
	default:
	}
	if lock, err := ipc.Lock(filepath.Join(p.Data, "db.lock")); !errors.Is(err, ipc.ErrBusy) {
		if lock != nil {
			lock.Close()
		}
		t.Fatal("unsettled lock released", err)
	}
	if _, err := os.Stat(filepath.Join(p.Data, "premature-cancel")); !os.IsNotExist(err) {
		t.Fatal("drain cancelled admitted call")
	}
	os.WriteFile(filepath.Join(p.Data, "release"), []byte("release"), 0600)
	raw, err := ipc.ReadFrame(r)
	if err != nil || !bytes.Contains(raw, []byte(`"settled":true`)) {
		t.Fatalf("admitted response lost %s %v", raw, err)
	}
	if err := <-done; err != nil {
		t.Fatal("quiesce", err)
	}
	select {
	case err := <-pr.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("process remains")
	}
	if err := daemon.Quiesce(ctx, p); err != nil {
		t.Fatal("repeat clean quiesce", err)
	}
	for _, name := range []string{"settled", "checkpoint"} {
		awaitFile(t, filepath.Join(p.Data, name))
	}
	lock, err := ipc.Lock(filepath.Join(p.Data, "db.lock"))
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
	if _, err := os.Lstat(p.Endpoint); !os.IsNotExist(err) {
		t.Fatal("endpoint remains")
	}
}
func TestProcessDrainUnknownDoesNotHandoff(t *testing.T) {
	for _, kind := range []string{"inflight-timeout", "settled-without-exit", "crash", "missing"} {
		t.Run(kind, func(t *testing.T) {
			p := testPaths(t)
			if kind == "missing" {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if daemon.Quiesce(ctx, p) == nil {
					t.Fatal("unknown accepted")
				}
				return
			}
			argv := []string{p.Data, p.Run}
			if kind == "settled-without-exit" {
				argv = append(argv, "linger")
			}
			pr := launch(t, driver, argv...)
			waitReady(t, p)
			if kind == "crash" {
				pr.cmd.Process.Kill()
				<-pr.done
			}
			if kind == "inflight-timeout" {
				c, _ := wire(t, p)
				ipc.WriteFrame(c, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage("2"), Method: "settle"})
				awaitFile(t, filepath.Join(p.Data, "entered"))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
			defer cancel()
			if err := daemon.Quiesce(ctx, p); !errors.Is(err, daemon.ErrSettlement) {
				t.Fatal("unknown handoff", err)
			}
			if kind == "inflight-timeout" {
				if lock, err := ipc.Lock(filepath.Join(p.Data, "db.lock")); !errors.Is(err, ipc.ErrBusy) {
					if lock != nil {
						lock.Close()
					}
					t.Fatal("timed out writer unlocked", err)
				}
				os.WriteFile(filepath.Join(p.Data, "release"), []byte("release"), 0600)
				select {
				case <-pr.done:
				case <-time.After(3 * time.Second):
					t.Fatal("drain never settled")
				}
			}
		})
	}
}
func TestProcessDrainRejectsUnauthenticatedAndMCP(t *testing.T) {
	p := testPaths(t)
	launch(t, driver, p.Data, p.Run)
	waitReady(t, p)
	for _, kind := range []string{"no-hello", "wrong-pid", "mcp", "params", "forwarded"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, err := ipc.Dial(ctx, p)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		r := bufio.NewReader(c)
		request := daemon.Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "drain-and-exit"}
		if kind == "no-hello" {
			if kind == "forwarded" {
				ipc.WriteFrame(c, daemon.ForwardedRequest{Request: request, ClientRequestID: json.RawMessage("2")})
			} else {
				ipc.WriteFrame(c, request)
			}
		} else {
			h := ipc.Hello{T: "hello", V: 1, Kind: "control", PID: os.Getpid(), Client: "test"}
			if kind == "wrong-pid" {
				h.PID++
			}
			if kind == "mcp" {
				h.Kind = "mcp"
			}
			ipc.WriteFrame(c, h)
			raw, err := ipc.ReadFrame(r)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "wrong-pid" {
				if !bytes.Contains(raw, []byte("invalid_hello")) {
					t.Fatal(string(raw))
				}
				c.Close()
				continue
			}
			if kind == "params" {
				request.Params = json.RawMessage(`{"kill":true}`)
			}
			if kind == "forwarded" {
				ipc.WriteFrame(c, daemon.ForwardedRequest{Request: request, ClientRequestID: json.RawMessage("2")})
			} else {
				ipc.WriteFrame(c, request)
			}
		}
		raw, err := ipc.ReadFrame(r)
		c.Close()
		if err != nil || (!bytes.Contains(raw, []byte("unsupported_control")) && !bytes.Contains(raw, []byte("invalid_hello"))) {
			t.Fatalf("%s %s %v", kind, raw, err)
		}
		waitReady(t, p)
	}
}
func installedFixture(t *testing.T) (install.Record, ipc.Paths) {
	t.Helper()
	p := testPaths(t)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(home, 0700)
	dir := filepath.Join(home, "install")
	b, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	digest := hex.EncodeToString(sum[:])
	exe := filepath.Join(dir, "bin", digest, "telara-memory")
	if err := os.MkdirAll(filepath.Dir(exe), 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(exe, b, 0700)
	r := install.Record{Schema: 1, Dir: dir, Home: home, Label: "dev.memory.fixture", Platform: runtime.GOOS, UserID: strconv.Itoa(os.Geteuid()), Executable: exe, SHA256: digest, Version: "fixture", DataDir: p.Data, RunDir: p.Run}
	writeJSONFixture(t, filepath.Join(dir, "install.json"), r)
	writeJSONFixture(t, filepath.Join(dir, "intent.json"), map[string]string{"mode": "start", "sha256": digest, "version": r.Version, "session": ""})
	return r, p
}
func writeJSONFixture(t *testing.T, path string, value any) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestProcessManagedDaemonVerifiesBeforeOpen(t *testing.T) {
	for _, kind := range []string{"valid", "copied", "tampered", "stopped", "path-override"} {
		t.Run(kind, func(t *testing.T) {
			record, p := installedFixture(t)
			exe := record.Executable
			argv := []string{"managed-daemon", "--install-dir", record.Dir}
			switch kind {
			case "copied":
				exe = binary
			case "tampered":
				os.WriteFile(record.Executable, append(mustReadBytes(t, record.Executable), 0), 0700)
			case "stopped":
				writeJSONFixture(t, filepath.Join(record.Dir, "intent.json"), map[string]string{"mode": "stop", "sha256": record.SHA256, "version": record.Version, "session": ""})
			case "path-override":
				argv = append(argv, "--data-dir", p.Data)
			}
			pr := launch(t, exe, argv...)
			if kind == "valid" {
				live := waitReady(t, p)
				raw, _ := json.Marshal(live)
				if !bytes.Contains(raw, []byte(`"store_wired":false`)) {
					t.Fatal("overclaimed storage", string(raw))
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := daemon.Quiesce(ctx, p); err != nil {
					t.Fatal(err)
				}
			} else {
				select {
				case err := <-pr.done:
					if (kind == "stopped") != (err == nil) {
						t.Fatalf("%s %v %s", kind, err, pr.err.String())
					}
				case <-time.After(2 * time.Second):
					t.Fatal("verification did not refuse")
				}
				if _, err := os.Lstat(filepath.Join(p.Data, "db.lock")); !os.IsNotExist(err) {
					t.Fatal("storage opened before verification")
				}
			}
		})
	}
}

func TestProcessManagedStartupRechecksAfterStopBeforeLock(t *testing.T) {
	for _, change := range []string{"stop", "uninstall", "receipt-change"} {
		t.Run(change, func(t *testing.T) {
			record, p := installedFixture(t)
			first := launch(t, record.Executable, "managed-daemon", "--install-dir", record.Dir)
			waitReady(t, p)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := daemon.Quiesce(ctx, p); err != nil {
				t.Fatal("prior clean shutdown", err)
			}
			if err := <-first.done; err != nil {
				t.Fatal(err)
			}
			receiptPath := filepath.Join(p.Data, "shutdown.receipt")
			priorReceipt := mustReadBytes(t, receiptPath)
			if len(priorReceipt) == 0 {
				t.Fatal("missing prior clean-close receipt")
			}
			// Run creates its runtime directory only after the initial
			// VerifyRunning. Hold start.lock so that directory is an observable
			// barrier before db.lock acquisition, without test-only daemon flags.
			if err := os.Remove(p.Run); err != nil {
				t.Fatal(err)
			}
			start, err := ipc.Lock(filepath.Join(p.Data, "start.lock"))
			if err != nil {
				t.Fatal(err)
			}
			defer start.Close()
			next := launch(t, record.Executable, "managed-daemon", "--install-dir", record.Dir)
			awaitFile(t, p.Run)
			switch change {
			case "stop":
				writeJSONFixture(t, filepath.Join(record.Dir, "intent.json"), map[string]string{"mode": "stop", "sha256": record.SHA256, "version": record.Version, "session": ""})
			case "uninstall":
				if err := os.Remove(filepath.Join(record.Dir, "install.json")); err != nil {
					t.Fatal(err)
				}
			case "receipt-change":
				record.DataDir = filepath.Join(filepath.Dir(p.Data), "replacement-data")
				writeJSONFixture(t, filepath.Join(record.Dir, "install.json"), record)
			}
			if err := start.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-next.done:
				if (change == "stop") != (err == nil) {
					t.Fatalf("%s exit %v", change, err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("managed startup outlived revoked intent")
			}
			if !bytes.Equal(priorReceipt, mustReadBytes(t, receiptPath)) {
				t.Fatal("revoked startup invalidated prior settlement")
			}
			if _, err := os.Lstat(p.Endpoint); !os.IsNotExist(err) {
				t.Fatal("revoked startup opened listener", err)
			}
			lock, err := ipc.Lock(filepath.Join(p.Data, "db.lock"))
			if err != nil {
				t.Fatal("revoked startup retained writer lock", err)
			}
			lock.Close()
		})
	}
}

func mustReadBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestProcessHookEndToEnd(t *testing.T) {
	home := t.TempDir()
	os.Chmod(home, 0700)
	state := filepath.Join(home, "data")
	for _, form := range [][]string{{"hook", "claude"}, {"hook", "--client", "claude"}} {
		cmd := exec.Command(binary, append(form, "--home", home, "--state-dir", state)...)
		cmd.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":"SessionStart","session_id":"01234567-89ab-4cde-8fab-0123456789ab","cwd":%q,"prompt":"secret not retained"}`, home))
		raw, err := cmd.CombinedOutput()
		if err != nil || len(raw) != 0 {
			t.Fatalf("hook %q %v", raw, err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(state, "spool", "claude", "new", "*.json"))
	if len(files) != 2 {
		t.Fatal(len(files))
	}
	for _, path := range files {
		if bytes.Contains(mustReadBytes(t, path), []byte("secret")) {
			t.Fatal("content leaked")
		}
	}
	for _, payload := range []string{"invalid", `{"session_id":"a","session_id":"b"}`, strings.Repeat("x", (1<<20)+1)} {
		cmd := exec.Command(binary, "hook", "claude", "--home", home, "--state-dir", state)
		cmd.Stdin = strings.NewReader(payload)
		raw, err := cmd.CombinedOutput()
		if err != nil || len(raw) != 0 {
			t.Fatalf("hook failure not silent %q %v", raw, err)
		}
	}
}

var liveWiredAgent = flag.Bool("live-wired-launchagent", false, "Run actual managed-daemon LaunchAgent install and settled uninstall")

func TestLiveWiredLaunchAgent(t *testing.T) {
	if !*liveWiredAgent {
		t.Skip("lead must run with -live-wired-launchagent outside sandbox")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	// Preserve a failed live fixture for diagnosis rather than removing a live
	// writer's paths through t.TempDir cleanup.
	root, err := os.MkdirTemp("", "memory-live-wired-")
	if err != nil {
		t.Fatal(err)
	}
	home, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(home, 0700)
	p, err := ipc.Resolve(filepath.Join(home, "data"), filepath.Join(home, "run"))
	if err != nil {
		t.Fatal(err)
	}
	safeCleanup := false
	defer func() {
		if safeCleanup {
			os.RemoveAll(root)
			os.RemoveAll(p.Run)
		} else {
			t.Logf("preserved live fixture %s", home)
		}
	}()
	image, err := filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mustReadBytes(t, image))
	c := install.Config{Dir: filepath.Join(home, "install"), Home: home, Label: fmt.Sprintf("dev.memory.wired.%d", time.Now().UnixNano()), Executable: image, SHA256: hex.EncodeToString(sum[:]), Version: "fixture", DataDir: p.Data, RunDir: p.Run}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := install.Install(ctx, c)
	if err != nil {
		t.Fatalf("native manager install %v report %s. Lead must inspect partial registration %s", err, r.State, c.Label)
	}
	waitReady(t, p)
	if err := run(ctx, []string{"stop", "--install-dir", c.Dir}, strings.NewReader(""), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"uninstall", "--install-dir", c.Dir}, strings.NewReader(""), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "install.json")); !os.IsNotExist(err) {
		t.Fatal("receipt remains")
	}
	if _, err := os.Stat(r.Record.Executable); err != nil {
		t.Fatal("uninstall removed binary", err)
	}
	safeCleanup = true
}

func TestProcessFailedCloseNeverHandsOff(t *testing.T) {
	p := testPaths(t)
	os.WriteFile(filepath.Join(p.Data, "fail-close"), []byte("fixture"), 0600)
	pr := launch(t, driver, p.Data, p.Run)
	waitReady(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	if err := daemon.Quiesce(ctx, p); !errors.Is(err, daemon.ErrSettlement) {
		t.Fatal(err)
	}
	cancel()
	awaitFile(t, filepath.Join(p.Data, "closing"))
	if lock, err := ipc.Lock(filepath.Join(p.Data, "db.lock")); !errors.Is(err, ipc.ErrBusy) {
		if lock != nil {
			lock.Close()
		}
		t.Fatal("failed close released lock", err)
	}
	if raw := mustReadBytes(t, filepath.Join(p.Data, "shutdown.receipt")); len(raw) != 0 {
		t.Fatal("failed close wrote settlement")
	}
	os.WriteFile(filepath.Join(p.Data, "allow-close"), []byte("settled"), 0600)
	select {
	case err := <-pr.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("settled close stuck")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := daemon.Quiesce(ctx, p); err != nil {
		t.Fatal("clean retry rejected", err)
	}
}
func TestProcessNewWriterInvalidatesPriorSettlement(t *testing.T) {
	p := testPaths(t)
	first := launch(t, driver, p.Data, p.Run)
	waitReady(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := daemon.Quiesce(ctx, p); err != nil {
		t.Fatal(err)
	}
	<-first.done
	next := launch(t, driver, p.Data, p.Run)
	waitReady(t, p)
	if len(mustReadBytes(t, filepath.Join(p.Data, "shutdown.receipt"))) != 0 {
		t.Fatal("new writer retained old proof")
	}
	next.cmd.Process.Kill()
	<-next.done
	if err := daemon.Quiesce(ctx, p); !errors.Is(err, daemon.ErrSettlement) {
		t.Fatal("crash reused old proof", err)
	}
}
func TestProcessHookDoesNotWaitForInputEOF(t *testing.T) {
	home := t.TempDir()
	os.Chmod(home, 0700)
	cmd := exec.Command(binary, "hook", "claude", "--home", home, "--state-dir", filepath.Join(home, "data"))
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	started := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil || out.Len() != 0 {
			t.Fatalf("silent hook %v %q", err, out.String())
		}
	case <-time.After(3 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatal("hook blocked on input")
	}
	if time.Since(started) > 2500*time.Millisecond {
		t.Fatal("hook exceeded fail-open bound")
	}
}

func TestProcessInstallQuiesceCallbackUsesStoppedReceipt(t *testing.T) {
	record, p := installedFixture(t)
	pr := launch(t, record.Executable, "managed-daemon", "--install-dir", record.Dir)
	waitReady(t, p)
	// This is the intent state install.Stop writes before invoking the production
	// callback. No real service-manager mutation is performed by this fixture.
	writeJSONFixture(t, filepath.Join(record.Dir, "intent.json"), map[string]string{"mode": "stop", "sha256": record.SHA256, "version": record.Version, "session": ""})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := quiesceInstalled(ctx, record.Dir); err != nil {
		t.Fatal("production callback", err)
	}
	select {
	case err := <-pr.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("callback did not prove exit")
	}
	if err := quiesceInstalled(ctx, record.Dir); err != nil {
		t.Fatal("repeat production callback", err)
	}
	lock, err := ipc.Lock(filepath.Join(p.Data, "db.lock"))
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
}
