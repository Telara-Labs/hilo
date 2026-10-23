//go:build darwin || linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

var binary, driver string

func TestMain(m *testing.M) {
	dir, e := os.MkdirTemp("", "memory-process-binaries-")
	if e != nil {
		panic(e)
	}
	binary = filepath.Join(dir, "telara-memory")
	driver = filepath.Join(dir, "transport-driver")
	for _, spec := range [][2]string{{binary, "."}, {driver, "../../internal/node/daemon/testdata/process"}} {
		cmd := exec.Command("go", "build", "-p", "2", "-o", spec[0], spec[1])
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if out, e := cmd.CombinedOutput(); e != nil {
			fmt.Fprintf(os.Stderr, "build %v %s", e, out)
			os.RemoveAll(dir)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type process struct {
	cmd  *exec.Cmd
	done chan error
	err  bytes.Buffer
}

func launch(t *testing.T, exe string, args ...string) *process {
	t.Helper()
	p := &process{cmd: exec.Command(exe, args...), done: make(chan error, 1)}
	p.cmd.Stderr = &p.err
	if e := p.cmd.Start(); e != nil {
		t.Fatal(e)
	}
	go func() { p.done <- p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { p.cmd.Process.Kill(); <-p.done })
	return p
}
func testPaths(t *testing.T) ipc.Paths {
	t.Helper()
	base := t.TempDir()
	os.Chmod(base, 0700)
	p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Prepare(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(p.Run) })
	return p
}
func args(p ipc.Paths, cmd string) []string {
	return []string{cmd, "--data-dir", p.Data, "--run-dir", p.Run}
}
func waitReady(t *testing.T, p ipc.Paths) daemon.Response {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		out, e := daemon.Probe(ctx, p)
		cancel()
		if e == nil {
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("daemon not ready")
	return daemon.Response{}
}
func wire(t *testing.T, p ipc.Paths) (net.Conn, *bufio.Reader) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, e := ipc.Dial(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if e = ipc.WriteFrame(c, ipc.Hello{T: "hello", V: 1, Kind: "mcp", PID: os.Getpid(), Client: "test"}); e != nil {
		t.Fatal(e)
	}
	r := bufio.NewReader(c)
	b, e := ipc.ReadFrame(r)
	if e != nil || !bytes.Contains(b, []byte("connection_id")) {
		t.Fatalf("hello %s %v", b, e)
	}
	return c, r
}
func TestProcessConcurrentStarts(t *testing.T) {
	p := testPaths(t)
	var ps []*process
	for i := 0; i < 8; i++ {
		ps = append(ps, launch(t, binary, args(p, "daemon")...))
	}
	waitReady(t, p)
	time.Sleep(150 * time.Millisecond)
	alive := 0
	for _, pr := range ps {
		select {
		case e := <-pr.done:
			if e != nil {
				t.Fatalf("loser %v %s", e, pr.err.String())
			}
		default:
			alive++
		}
	}
	if alive != 1 {
		t.Fatalf("writers %d", alive)
	}
	if lock, e := ipc.Lock(filepath.Join(p.Data, "db.lock")); e == nil {
		lock.Close()
		t.Fatal("db not locked")
	}
}
func TestProcessLockContention(t *testing.T) {
	p := testPaths(t)
	lock, e := ipc.Lock(filepath.Join(p.Data, "db.lock"))
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	pr := launch(t, binary, args(p, "daemon")...)
	select {
	case e := <-pr.done:
		if e == nil {
			t.Fatal("writer admitted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lock wait unbounded")
	}
	if _, e = os.Lstat(p.Endpoint); !os.IsNotExist(e) {
		t.Fatal("listener opened before lock")
	}
}
func TestProcessStaleSocket(t *testing.T) {
	p := testPaths(t)
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: p.Endpoint, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	launch(t, binary, args(p, "daemon")...)
	waitReady(t, p)
}
func TestProcessAmbiguousOwner(t *testing.T) {
	p := testPaths(t)
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: p.Endpoint, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	os.WriteFile(filepath.Join(p.Run, "owner.pid"), []byte(fmt.Sprint(os.Getpid())), 0600)
	pr := launch(t, binary, args(p, "daemon")...)
	if e := <-pr.done; e == nil {
		t.Fatal("live owner stolen")
	}
	if _, e = os.Lstat(p.Endpoint); e != nil {
		t.Fatal("socket removed")
	}
}
func TestProcessUnsafeDirectories(t *testing.T) {
	for _, mode := range []string{"loose", "symlink", "wrong-owner"} {
		t.Run(mode, func(t *testing.T) {
			p := testPaths(t)
			runDir := p.Run
			switch mode {
			case "loose":
				os.Chmod(runDir, 0755)
			case "symlink":
				link := filepath.Join(p.Data, "run-link")
				os.Symlink(runDir, link)
				runDir = link
			case "wrong-owner":
				if os.Geteuid() == 0 {
					t.Skip("requires unprivileged test process")
				}
				runDir = "/private/tmp"
				if _, e := os.Stat(runDir); e != nil {
					runDir = "/tmp"
				}
			}
			pr := launch(t, binary, "daemon", "--data-dir", p.Data, "--run-dir", runDir)
			select {
			case e := <-pr.done:
				if e == nil {
					t.Fatal("unsafe run accepted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("unsafe run blocked")
			}
		})
	}
}
func TestProcessOversizeAndMalformed(t *testing.T) {
	p := testPaths(t)
	launch(t, binary, args(p, "daemon")...)
	waitReady(t, p)
	for _, payload := range []string{strings.Repeat("x", ipc.MaxFrame+1), "{secret}\n"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, e := ipc.Dial(ctx, p)
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		go func() { io.WriteString(c, payload) }()
		b, e := ipc.ReadFrame(bufio.NewReader(c))
		c.Close()
		if e != nil || string(b) != "{\"error\":\"invalid_frame\"}" {
			t.Fatalf("error %q %v", b, e)
		}
	}
	waitReady(t, p)
}
func TestProcessHandshakeTimeout(t *testing.T) {
	p := testPaths(t)
	launch(t, binary, args(p, "daemon")...)
	waitReady(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	c, e := ipc.Dial(ctx, p)
	cancel()
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(12 * time.Second))
	start := time.Now()
	_, e = c.Read(make([]byte, 100))
	elapsed := time.Since(start)
	if e == nil || elapsed < 9*time.Second || elapsed > 11500*time.Millisecond {
		t.Fatalf("timeout %v %s", e, elapsed)
	}
}
func TestProcessInflightCap(t *testing.T) {
	p := testPaths(t)
	launch(t, driver, p.Data, p.Run)
	waitReady(t, p)
	c, r := wire(t, p)
	for i := 1; i <= 17; i++ {
		if e := ipc.WriteFrame(c, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(fmt.Sprint(i)), Method: "hold"}); e != nil {
			t.Fatal(e)
		}
	}
	b, e := ipc.ReadFrame(r)
	if e != nil || !bytes.Contains(b, []byte("busy")) || !bytes.Contains(b, []byte(`"id":17`)) {
		t.Fatalf("cap %s %v", b, e)
	}
}
func TestProcessHelloIdentityAndVersion(t *testing.T) {
	p := testPaths(t)
	launch(t, binary, args(p, "daemon")...)
	waitReady(t, p)
	for _, h := range []ipc.Hello{{T: "hello", V: 99, Kind: "mcp", PID: os.Getpid(), Client: "test"}, {T: "hello", V: 1, Kind: "mcp", PID: os.Getpid() + 1, Client: "test"}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, e := ipc.Dial(ctx, p)
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		ipc.WriteFrame(c, h)
		b, e := ipc.ReadFrame(bufio.NewReader(c))
		c.Close()
		if e != nil || !bytes.Contains(b, []byte("invalid_hello")) {
			t.Fatalf("identity %s %v", b, e)
		}
	}
}
func TestProcessShimSetupAndForward(t *testing.T) {
	p := testPaths(t)
	launch(t, driver, p.Data, p.Run)
	waitReady(t, p)
	input := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\"}\n"
	cmd := exec.Command(binary, args(p, "shim")...)
	cmd.Stdin = strings.NewReader(input)
	out, e := cmd.CombinedOutput()
	if e != nil || !bytes.Contains(out, []byte(`"ok":true`)) || !bytes.Contains(out, []byte(`"tools":[]`)) {
		t.Fatalf("shim %s %v", out, e)
	}
}
func TestProcessNoReplayAfterCommit(t *testing.T) {
	p := testPaths(t)
	launch(t, driver, p.Data, p.Run)
	waitReady(t, p)
	cmd := exec.Command(binary, args(p, "shim")...)
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fixture_write","arguments":{"op_id":"unchanged-write"}}}` + "\n")
	out, e := cmd.CombinedOutput()
	if e != nil || !bytes.Contains(out, []byte("outcome_unknown")) || !bytes.Contains(out, []byte(`"isError":true`)) {
		t.Fatalf("loss %s %v", out, e)
	}
	b, e := os.ReadFile(filepath.Join(p.Data, "committed"))
	if e != nil || string(b) != "one\n" {
		t.Fatalf("replay %s %v", b, e)
	}
	time.Sleep(100 * time.Millisecond)
	if b, _ = os.ReadFile(filepath.Join(p.Data, "committed")); string(b) != "one\n" {
		t.Fatal("write replayed")
	}
}
func TestProcessShimWaitBound(t *testing.T) {
	p := testPaths(t)
	lock, e := ipc.Lock(filepath.Join(p.Data, "start.lock"))
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	cmd := exec.Command(binary, args(p, "shim")...)
	cmd.Stdin = strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}\n")
	start := time.Now()
	out, e := cmd.CombinedOutput()
	if e != nil || !bytes.Contains(out, []byte("autostart_unverified_install")) || !bytes.Contains(out, []byte("isError")) || time.Since(start) > 11500*time.Millisecond {
		t.Fatalf("wait %s %v %s", out, e, time.Since(start))
	}
}
func TestProcessGracefulShutdownReleasesLock(t *testing.T) {
	p := testPaths(t)
	pr := launch(t, binary, args(p, "daemon")...)
	waitReady(t, p)
	pr.cmd.Process.Signal(os.Interrupt)
	select {
	case e := <-pr.done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown stalled")
	}
	lock, e := ipc.Lock(filepath.Join(p.Data, "db.lock"))
	if e != nil {
		t.Fatal("lock retained", e)
	}
	lock.Close()
	if _, e = os.Lstat(p.Endpoint); !os.IsNotExist(e) {
		t.Fatal("socket not cleaned")
	}
}
func TestProcessUnverifiedAutostartRefused(t *testing.T) {
	p := testPaths(t)
	cmd := exec.Command(binary, append(args(p, "status"), "--start")...)
	out, e := cmd.CombinedOutput()
	if e == nil || !bytes.Contains(out, []byte("autostart_unverified_install")) {
		t.Fatalf("unverified launch %s %v", out, e)
	}
	if _, e = os.Lstat(p.Endpoint); !os.IsNotExist(e) {
		t.Fatal("refusal launched a daemon")
	}
}
func TestProcessSubstitutedExecutableRefused(t *testing.T) {
	p := testPaths(t)
	copyPath := filepath.Join(t.TempDir(), "shim")
	b, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(copyPath, b, 0700); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(copyPath, args(p, "shim")...)
	stdin, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	// Replace the exact executable pathname after the shim process is running.
	if e = os.Remove(copyPath); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(copyPath, []byte("substituted artifact"), 0700); e != nil {
		t.Fatal(e)
	}
	io.WriteString(stdin, `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`+"\n")
	stdin.Close()
	if e = cmd.Wait(); e != nil || !bytes.Contains(out.Bytes(), []byte("autostart_unverified_install")) {
		t.Fatalf("substitution %s %v", out.String(), e)
	}
}
func TestProcessCrashOwnerRestart(t *testing.T) {
	p := testPaths(t)
	first := launch(t, binary, args(p, "daemon")...)
	waitReady(t, p)
	first.cmd.Process.Kill()
	<-first.done
	launch(t, binary, args(p, "daemon")...)
	waitReady(t, p)
}

func TestProcessShimSIGTERM(t *testing.T) {
	for _, blocked := range []string{"stdin", "stdout"} {
		t.Run(blocked, func(t *testing.T) {
			p := testPaths(t)
			input, writer, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer input.Close()
			defer writer.Close() // Intentionally held open until after child exit.
			reader, output, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer reader.Close()
			defer output.Close()
			cmd := exec.Command(binary, args(p, "shim")...)
			cmd.Stdin, cmd.Stdout = input, output
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait(); close(done) }()
			defer func() { cmd.Process.Kill(); <-done }()
			request := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n"
			if _, e = io.WriteString(writer, request); e != nil {
				t.Fatal(e)
			}
			if e = reader.SetReadDeadline(time.Now().Add(2 * time.Second)); e != nil {
				t.Fatal(e)
			}
			if b, e := ipc.ReadFrame(bufio.NewReader(reader)); e != nil || !bytes.Contains(b, []byte("protocolVersion")) {
				t.Fatalf("shim not ready %s %v", b, e)
			}
			if blocked == "stdout" {
				// Fill the actual inherited stdout pipe while keeping its reader
				// open. A setup response now requires a blocked output write.
				raw, e := output.SyscallConn()
				if e != nil {
					t.Fatal(e)
				}
				var fillErr error
				e = raw.Control(func(handle uintptr) {
					fd := int(handle)
					flags, err := unix.FcntlInt(handle, unix.F_GETFL, 0)
					if err != nil {
						fillErr = err
						return
					}
					if fillErr = unix.SetNonblock(fd, true); fillErr != nil {
						return
					}
					defer func() {
						_, err := unix.FcntlInt(handle, unix.F_SETFL, flags)
						if fillErr == nil {
							fillErr = err
						}
					}()
					for {
						_, err = unix.Write(fd, make([]byte, 4096))
						if err == unix.EAGAIN {
							return
						}
						if err != nil {
							fillErr = err
							return
						}
					}
				})
				if e != nil || fillErr != nil {
					t.Fatalf("fill stdout %v %v", e, fillErr)
				}
				if _, e = io.WriteString(writer, request); e != nil {
					t.Fatal(e)
				}
			}
			time.Sleep(100 * time.Millisecond)
			select {
			case e := <-done:
				t.Fatalf("shim exited before signal %v %s", e, stderr.String())
			default:
			}
			if e = cmd.Process.Signal(syscall.SIGTERM); e != nil {
				t.Fatal(e)
			}
			select {
			case e := <-done:
				if e != nil {
					t.Fatalf("shutdown %v %s", e, stderr.String())
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("SIGTERM hung with blocked %s", blocked)
			}
		})
	}
}

func TestProcessDaemonDarwinAncestorACL(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS ACL regression")
	}
	for _, grant := range []string{"search", "add_subdirectory"} {
		t.Run(grant, func(t *testing.T) {
			p := testPaths(t)
			parent := filepath.Dir(p.Data)
			if out, e := exec.Command("/bin/chmod", "+a", "everyone allow "+grant, parent).CombinedOutput(); e != nil {
				t.Fatalf("ACL fixture %v %s", e, out)
			}
			t.Cleanup(func() {
				if out, e := exec.Command("/bin/chmod", "-N", parent).CombinedOutput(); e != nil {
					t.Errorf("ACL cleanup %v %s", e, out)
				}
			})
			pr := launch(t, binary, args(p, "daemon")...)
			if grant == "search" {
				waitReady(t, p)
				return
			}
			select {
			case e := <-pr.done:
				if e == nil || !strings.Contains(pr.err.String(), "unsafe_path") {
					t.Fatalf("mutable ancestor %v %s", e, pr.err.String())
				}
			case <-time.After(2 * time.Second):
				t.Fatal("daemon accepted mutable ancestor")
			}
		})
	}
}
