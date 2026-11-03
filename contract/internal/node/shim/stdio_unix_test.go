//go:build darwin || linux

package shim

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"golang.org/x/sys/unix"
)

func fileFlags(t *testing.T, f *os.File) int {
	t.Helper()
	raw, e := f.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	var flags int
	var flagErr error
	if e = raw.Control(func(fd uintptr) { flags, flagErr = unix.FcntlInt(fd, unix.F_GETFL, 0) }); e != nil || flagErr != nil {
		t.Fatalf("flags %v %v", e, flagErr)
	}
	return flags
}

func TestStdioFilePipeCancelAndRestore(t *testing.T) {
	for _, direction := range []string{"read", "write"} {
		t.Run(direction, func(t *testing.T) {
			r, w, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			defer w.Close()
			f := r
			if direction == "write" {
				f = w
			}
			// Reproduce inherited stdio rather than os.Pipe's pollable file.
			fd := int(f.Fd())
			if e := unix.SetNonblock(fd, false); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			adapted, cleanup, e := cancelableFile(ctx, f)
			if e != nil {
				t.Fatal(e)
			}
			defer cleanup()
			if fileFlags(t, f)&unix.O_NONBLOCK == 0 {
				t.Fatal("stdio still blocking")
			}
			if direction == "write" {
				for {
					_, e = unix.Write(fd, make([]byte, 4096))
					if e == unix.EAGAIN {
						break
					}
					if e != nil {
						t.Fatal(e)
					}
				}
			}
			done := make(chan error, 1)
			go func() {
				var e error
				if direction == "read" {
					_, e = adapted.Read(make([]byte, 1))
				} else {
					_, e = adapted.Write([]byte("blocked"))
				}
				done <- e
			}()
			select {
			case e := <-done:
				t.Fatalf("did not block %v", e)
			case <-time.After(75 * time.Millisecond):
			}
			cancel()
			select {
			case e := <-done:
				if !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
			case <-time.After(time.Second):
				t.Fatal("stdio cancellation stalled")
			}
		})
	}
}

func TestStdioFileTransferEOFAndFlags(t *testing.T) {
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	if e := unix.SetNonblock(int(r.Fd()), false); e != nil {
		t.Fatal(e)
	}
	before := fileFlags(t, r)
	adapted, cleanup, e := cancelableFile(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Write([]byte("hello")); e != nil {
		cleanup()
		t.Fatal(e)
	}
	w.Close()
	b, e := io.ReadAll(adapted)
	cleanup()
	if e != nil || string(b) != "hello" {
		t.Fatalf("transfer %q %v", b, e)
	}
	if got := fileFlags(t, r); got != before {
		t.Fatalf("flags changed %x -> %x", before, got)
	}
	if _, e := r.Stat(); e != nil {
		t.Fatal("original closed", e)
	}
}

func TestStdioFileRegularAndClosed(t *testing.T) {
	f, e := os.Create(filepath.Join(t.TempDir(), "stdio"))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	adapted, cleanup, e := cancelableFile(context.Background(), f)
	if e != nil {
		t.Fatal(e)
	}
	n, e := adapted.Write([]byte("regular"))
	cleanup()
	if e != nil || n != 7 {
		t.Fatalf("write %d %v", n, e)
	}
	f.Close()
	if _, _, e := cancelableFile(context.Background(), f); e == nil {
		t.Fatal("closed descriptor accepted")
	}
}

func TestStdioFileReadWaitAndHangup(t *testing.T) {
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	adapted, cleanup, e := cancelableFile(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	defer cleanup()
	done := make(chan error, 1)
	go func() {
		time.Sleep(25 * time.Millisecond)
		_, e := w.Write([]byte("ready"))
		w.Close()
		done <- e
	}()
	b, e := io.ReadAll(adapted)
	if writeErr := <-done; e != nil || writeErr != nil || string(b) != "ready" {
		t.Fatalf("read after readiness %q %v %v", b, e, writeErr)
	}
}

func TestStdioFilePartialWriteWaitAndBrokenPipe(t *testing.T) {
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	fd := int(w.Fd())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	adapted, cleanup, e := cancelableFile(ctx, w)
	if e != nil {
		t.Fatal(e)
	}
	defer cleanup()
	filled := 0
	for {
		n, e := unix.Write(fd, make([]byte, 4096))
		if n > 0 {
			filled += n
		}
		if e == unix.EAGAIN {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	payload := bytes.Repeat([]byte("partial-write"), 20000)
	done := make(chan error, 1)
	go func() { done <- ipc.WriteEncodedFrame(adapted, payload) }()
	select {
	case e := <-done:
		t.Fatalf("full pipe did not block %v", e)
	case <-time.After(25 * time.Millisecond):
	}
	if e = r.SetReadDeadline(time.Now().Add(2 * time.Second)); e != nil {
		t.Fatal(e)
	}
	all := make([]byte, filled+len(payload))
	_, readErr := io.ReadFull(r, all)
	if e := <-done; e != nil || readErr != nil || !bytes.Equal(all[filled:], payload) {
		t.Fatalf("partial write %v %v", e, readErr)
	}
	r.Close()
	if n, e := adapted.Write([]byte("closed")); n != 0 || !errors.Is(e, unix.EPIPE) {
		t.Fatalf("broken pipe %d %v", n, e)
	}
}

func TestRunRejectsClosedStdioAndCanceledBufferedInput(t *testing.T) {
	f, e := os.Create(filepath.Join(t.TempDir(), "stdio"))
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	if e := Run(context.Background(), f, io.Discard, Config{}); e == nil {
		t.Fatal("closed input accepted")
	}
	if e := Run(context.Background(), bytes.NewReader(nil), f, Config{}); e == nil {
		t.Fatal("closed output accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	e = Run(ctx, bytes.NewBufferString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n"), &out, Config{})
	if !errors.Is(e, context.Canceled) || out.Len() != 0 {
		t.Fatalf("canceled input processed %q %v", out.String(), e)
	}
}
