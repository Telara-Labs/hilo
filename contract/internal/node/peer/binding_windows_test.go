//go:build windows

package peer

import (
	"bufio"
	"context"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsBindingHelper(t *testing.T) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-1] != "windows-binding-helper" {
		return
	}
	p, e := ipc.Resolve(os.Args[len(os.Args)-3], os.Args[len(os.Args)-2])
	if e != nil {
		t.Fatal(e)
	}
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	conn, e := ipc.Dial(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.Write([]byte("ready\n"))
	bufio.NewReader(conn).ReadString('\n')
}
func TestWindowsBindingPinsClientProcessUntilExit(t *testing.T) {
	root := t.TempDir()
	p, e := ipc.Resolve(filepath.Join(root, "data"), filepath.Join(root, "run"))
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Prepare(); e != nil {
		t.Fatal(e)
	}
	listener, e := ipc.Listen(p)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "-test.run=^TestWindowsBindingHelper$", "--", p.Data, p.Run, "windows-binding-helper")
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := listener.Accept(); accepted <- c }()
	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("pipe accept timeout")
	}
	if conn == nil {
		t.Fatal("pipe refused")
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, e = bufio.NewReader(conn).ReadString('\n'); e != nil {
		t.Fatal(e)
	}
	b, e := bindProcess(conn)
	if e != nil {
		t.Fatal(e)
	}
	defer b.close()
	if e = b.check(cmd.Process.Pid); e != nil {
		t.Fatal(e)
	}
	if e = b.check(os.Getpid()); e == nil {
		t.Fatal("PID substitution accepted")
	}
	cmd.Process.Kill()
	cmd.Process.Wait()
	if e = b.check(cmd.Process.Pid); e == nil {
		t.Fatal("retained pipe authorized exited creator")
	}
}
