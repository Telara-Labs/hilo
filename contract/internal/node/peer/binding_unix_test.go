//go:build linux || (darwin && cgo)

package peer

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBindingProcessHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-1] != "binding-process-helper" {
		return
	}
	c, e := net.Dial("unix", os.Args[len(os.Args)-2])
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.Write([]byte("ready\n"))
	mode, _ := bufio.NewReader(c).ReadString('\n')
	if strings.TrimSpace(mode) == "exec" {
		raw, _ := c.(*net.UnixConn).SyscallConn()
		raw.Control(func(fd uintptr) { unix.FcntlInt(fd, unix.F_SETFD, 0) })
		// Keep the original socket inherited while the process changes image.
		if e = unix.Exec("/bin/cat", []string{"cat"}, os.Environ()); e != nil {
			t.Fatal(e)
		}
	}
}
func bindingFixture(t *testing.T) (processBinding, net.Conn, *exec.Cmd, string) {
	t.Helper()
	root, e := os.MkdirTemp("/tmp", "peer-bind-")
	if e == nil {
		t.Cleanup(func() { os.RemoveAll(root) })
		root, e = filepath.EvalSymlinks(root)
	}
	if e != nil {
		t.Fatal(e)
	}
	source, _ := os.Executable()
	b, e := os.ReadFile(source)
	if e != nil {
		t.Fatal(e)
	}
	image := filepath.Join(root, "helper")
	if e = os.WriteFile(image, b, 0700); e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(root, "s")
	l, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	cmd := exec.Command(image, "-test.run=^TestBindingProcessHelper$", "--", socket, "binding-process-helper")
	stdin, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stderr = os.Stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() })
	l.(*net.UnixListener).SetDeadline(time.Now().Add(5 * time.Second))
	c, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if line, e := bufio.NewReader(c).ReadString('\n'); line != "ready\n" || e != nil {
		t.Fatal(line, e)
	}
	bound, release, e := BindConnection(context.Background(), c)
	if e != nil {
		t.Fatal("kernel binding", runtime.GOOS, e)
	}
	t.Cleanup(release)
	return bound.Value(bindingKey{}).(processBinding), c, cmd, image
}
func TestKernelBindingRejectsExecAndProcessDeath(t *testing.T) {
	b, c, cmd, _ := bindingFixture(t)
	pid := cmd.Process.Pid
	if e := b.check(pid); e != nil {
		t.Fatal(e)
	}
	if e := b.check(pid + 1); e == nil {
		t.Fatal("PID substitution accepted")
	}
	if _, e := io.WriteString(c, "exec\n"); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for b.check(pid) == nil {
		if time.Now().After(deadline) {
			t.Fatal("exec accepted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cmd.Process.Kill()
	cmd.Process.Wait()
	if e := b.check(pid); e == nil {
		t.Fatal("dead process accepted")
	}
	// The pinned lifetime cannot be replaced by a live process with another PID.
	if e := b.check(os.Getpid()); e == nil {
		t.Fatal("reused identity accepted")
	}
}
func TestKernelBindingRejectsPathReplacement(t *testing.T) {
	b, _, cmd, image := bindingFixture(t)
	if e := os.Rename(image, image+".old"); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(image, []byte("replacement "+strconv.Itoa(cmd.Process.Pid)), 0700); e != nil {
		t.Fatal(e)
	}
	if e := b.check(cmd.Process.Pid); e == nil {
		t.Fatal("replacement pathname accepted")
	}
}
func TestBindingRejectsNonKernelConnection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, release, e := BindConnection(context.Background(), a); e == nil {
		release()
		t.Fatal("uncredentialed connection accepted")
	}
}

func TestLifecyclePeerRequiresRetainedReceiptImage(t *testing.T) {
	b, _, cmd, image := bindingFixture(t)
	raw, e := os.ReadFile(image)
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(raw)
	record := install.Record{Executable: image, SHA256: hex.EncodeToString(digest[:])}
	ctx := context.WithValue(context.Background(), bindingKey{}, b)
	if e = verifyLifecyclePeer(ctx, cmd.Process.Pid, record); e != nil {
		t.Fatal(e)
	}
	if e = VerifyLifecycle(ctx, record); e == nil {
		t.Fatal("missing daemon peer PID accepted")
	}
	if e = VerifyLifecycle(nil, record); e == nil {
		t.Fatal("nil context accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if e = verifyLifecyclePeer(canceled, cmd.Process.Pid, record); e == nil {
		t.Fatal("canceled control accepted")
	}
	record.SHA256 = hex.EncodeToString(make([]byte, 32))
	if e = verifyLifecyclePeer(ctx, cmd.Process.Pid, record); e == nil {
		t.Fatal("wrong receipt digest accepted")
	}
	record.SHA256 = hex.EncodeToString(digest[:])
	record.Executable += ".other"
	if e = verifyLifecyclePeer(ctx, cmd.Process.Pid, record); e == nil {
		t.Fatal("wrong receipt image accepted")
	}
}
