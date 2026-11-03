//go:build darwin || linux

package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

type settling struct{ entered, settle, closed chan struct{} }

func (b *settling) Handle(ctx context.Context, h ipc.Hello, r Request) Response {
	close(b.entered)
	<-b.settle
	return Error(r.ID, "settled")
}
func (b *settling) Close() error { close(b.closed); return nil }
func TestWriterLockHeldUntilSettlement(t *testing.T) {
	base := t.TempDir()
	os.Chmod(base, 0700)
	p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(p.Run)
	b := &settling{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Paths: p, Ready: func() { close(ready) }, Open: func(context.Context) (Backend, error) { return b, nil }})
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("not ready")
	}
	c, e := ipc.Dial(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(c)
	ipc.WriteFrame(c, ipc.Hello{T: "hello", V: 1, Kind: "mcp", PID: os.Getpid(), Client: "test"})
	if _, e = ipc.ReadFrame(r); e != nil {
		t.Fatal(e)
	}
	ipc.WriteFrame(c, Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "hold"})
	<-b.entered
	cancel()
	time.Sleep(10 * time.Millisecond)
	if lock, e := ipc.Lock(filepath.Join(p.Data, "db.lock")); !errors.Is(e, ipc.ErrBusy) {
		if lock != nil {
			lock.Close()
		}
		t.Fatal("released unsettled writer", e)
	}
	close(b.settle)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("settled shutdown blocked")
	}
	select {
	case <-b.closed:
	default:
		t.Fatal("backend not closed")
	}
	lock, e := ipc.Lock(filepath.Join(p.Data, "db.lock"))
	if e != nil {
		t.Fatal(e)
	}
	lock.Close()
}
func TestOpenFailureReleasesLocks(t *testing.T) {
	base := t.TempDir()
	os.Chmod(base, 0700)
	p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(p.Run)
	expected := errors.New("unsupported_schema")
	e = Run(context.Background(), Config{Paths: p, Open: func(context.Context) (Backend, error) { return nil, expected }})
	if !errors.Is(e, expected) {
		t.Fatal(e)
	}
	for _, name := range []string{"db.lock", "start.lock"} {
		lock, e := ipc.Lock(filepath.Join(p.Data, name))
		if e != nil {
			t.Fatal(e)
		}
		lock.Close()
	}
}

type failingClose struct {
	entered, allow chan struct{}
	calls          int
}

func (b *failingClose) Handle(context.Context, ipc.Hello, Request) Response { return Response{} }
func (b *failingClose) Close() error {
	b.calls++
	if b.calls == 1 {
		close(b.entered)
		return errors.New("unsettled_close")
	}
	<-b.allow
	return nil
}
func TestFailedCloseRetainsWriter(t *testing.T) {
	base := t.TempDir()
	os.Chmod(base, 0700)
	p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(p.Run)
	b := &failingClose{entered: make(chan struct{}), allow: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Paths: p, Ready: func() { close(ready) }, Open: func(context.Context) (Backend, error) { return b, nil }})
	}()
	<-ready
	cancel()
	<-b.entered
	if lock, e := ipc.Lock(filepath.Join(p.Data, "db.lock")); !errors.Is(e, ipc.ErrBusy) {
		if lock != nil {
			lock.Close()
		}
		t.Fatal("failed close released ownership", e)
	}
	close(b.allow)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close retry stalled")
	}
}

func TestFailedOwnerRecordIsPreserved(t *testing.T) {
	base := t.TempDir()
	os.Chmod(base, 0700)
	p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(p.Run)
	if e = p.Prepare(); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(p.Data, "untouched")
	os.WriteFile(target, []byte("sentinel"), 0600)
	link := filepath.Join(p.Run, "owner.pid")
	os.Symlink(target, link)
	if e = Run(context.Background(), Config{Paths: p}); e == nil {
		t.Fatal("unsafe owner accepted")
	}
	if fi, e := os.Lstat(link); e != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("unvalidated owner artifact removed", e)
	}
	if b, _ := os.ReadFile(target); string(b) != "sentinel" {
		t.Fatal("owner target modified")
	}
}

func TestContendedStartupRequiresReadyDaemon(t *testing.T) {
	base := t.TempDir()
	os.Chmod(base, 0700)
	p, e := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(p.Run)
	if e = p.Prepare(); e != nil {
		t.Fatal(e)
	}
	lock, e := ipc.Lock(filepath.Join(p.Data, "start.lock"))
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
	defer cancel()
	if e = Run(ctx, Config{Paths: p}); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("false duplicate success %v", e)
	}
}
