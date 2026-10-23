//go:build darwin || linux

package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func paths(t *testing.T) Paths {
	t.Helper()
	base := t.TempDir()
	os.Chmod(base, 0700)
	p, e := Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Prepare(); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestDirectoriesAndLocks(t *testing.T) {
	p := paths(t)
	if e := ValidateDir(p.Run, false); e != nil {
		t.Fatal(e)
	}
	os.Chmod(p.Run, 0755)
	if !errors.Is(ValidateDir(p.Run, false), ErrUnsafe) {
		t.Fatal("loose mode accepted")
	}
	os.Chmod(p.Run, 0700)
	link := filepath.Join(p.Data, "link")
	os.Symlink(p.Run, link)
	if ValidateDir(link, false) == nil {
		t.Fatal("symlink accepted")
	}
	lock, e := Lock(filepath.Join(p.Data, "db.lock"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Lock(filepath.Join(p.Data, "db.lock")); !errors.Is(e, ErrBusy) {
		t.Fatalf("lock %v", e)
	}
	lock.Close()
	os.Symlink(filepath.Join(p.Data, "db.lock"), filepath.Join(p.Data, "bad.lock"))
	if _, e = Lock(filepath.Join(p.Data, "bad.lock")); e == nil {
		t.Fatal("symlink lock")
	}
	os.Link(filepath.Join(p.Data, "db.lock"), filepath.Join(p.Data, "hard.lock"))
	if _, e = Lock(filepath.Join(p.Data, "hard.lock")); e == nil {
		t.Fatal("hardlink lock")
	}
	if ValidateDir("relative", true) == nil {
		t.Fatal("relative accepted")
	}
}
func TestConservativeStaleRecovery(t *testing.T) {
	p := paths(t)
	os.WriteFile(p.Endpoint, []byte("not a socket"), 0600)
	if _, e := Listen(p); e == nil {
		t.Fatal("file removed")
	}
	os.Remove(p.Endpoint)
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: p.Endpoint, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	os.WriteFile(filepath.Join(p.Run, "owner.pid"), []byte("1"), 0600)
	if _, e = Listen(p); e == nil {
		t.Fatal("live owner removed")
	}
	os.Remove(filepath.Join(p.Run, "owner.pid"))
	l2, e := Listen(p)
	if e != nil {
		t.Fatal(e)
	}
	defer l2.Close()
	defer Cleanup(p)
	if _, e = Listen(p); !errors.Is(e, ErrBusy) {
		t.Fatalf("live socket %v", e)
	}
}
func TestKernelPeerBothDirections(t *testing.T) {
	p := paths(t)
	l, e := Listen(p)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	defer Cleanup(p)
	done := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e == nil {
			defer c.Close()
			var pid int
			pid, e = Peer(c)
			if e == nil && pid != os.Getpid() {
				e = ErrPeer
			}
		}
		done <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, e := Dial(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if pid, e := Peer(c); e != nil || pid != os.Getpid() {
		t.Fatalf("peer %d %v", pid, e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
func TestLongPathFallback(t *testing.T) {
	p, e := Resolve(filepath.Join(t.TempDir(), "data"), filepath.Join(t.TempDir(), string(make([]byte, 120))))
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Endpoint) > 100 {
		t.Fatal("long socket")
	}
}

func TestUnsafeOwnerRecordAndNudge(t *testing.T) {
	p := paths(t)
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: p.Endpoint, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	target := filepath.Join(p.Data, "target")
	os.WriteFile(target, []byte("1"), 0600)
	os.Symlink(target, filepath.Join(p.Run, "owner.pid"))
	if _, e = Listen(p); e == nil {
		t.Fatal("owner symlink accepted")
	}
	if e = RecordOwner(p); e == nil {
		t.Fatal("owner symlink replaced")
	}
	os.Remove(filepath.Join(p.Run, "owner.pid"))
	os.Remove(p.Endpoint)
	live, e := Listen(p)
	if e != nil {
		t.Fatal(e)
	}
	defer live.Close()
	defer Cleanup(p)
	got := make(chan []byte, 1)
	go func() {
		c, e := live.Accept()
		if e != nil {
			got <- nil
			return
		}
		defer c.Close()
		b, _ := ReadFrame(bufio.NewReader(c))
		got <- b
	}()
	if e = Nudge(context.Background(), p, "test"); e != nil {
		t.Fatal(e)
	}
	if string(<-got) != `{"t":"nudge","v":1,"client":"test"}` {
		t.Fatal("nudge frame")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = Nudge(ctx, p, "test"); e == nil {
		t.Fatal("expired budget")
	}
}

func TestConcurrentLockCreation(t *testing.T) {
	p := paths(t)
	for round := 0; round < 30; round++ {
		path := filepath.Join(p.Data, fmt.Sprintf("contended-%d.lock", round))
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				lock, e := Lock(path)
				if e == nil {
					lock.Close()
				} else if !errors.Is(e, ErrBusy) {
					t.Errorf("concurrent create %v", e)
				}
			}()
		}
		wg.Wait()
	}
}

func TestUnsafeAncestorAndFallbackClient(t *testing.T) {
	base := t.TempDir()
	os.Chmod(base, 0700)
	unsafe := filepath.Join(base, "writable")
	os.Mkdir(unsafe, 0777)
	os.Chmod(unsafe, 0777)
	private := filepath.Join(unsafe, "private")
	os.Mkdir(private, 0700)
	if ValidateDir(private, false) == nil {
		t.Fatal("mutable ancestor accepted")
	}
	p := paths(t)
	link := filepath.Join(p.Data, "link")
	os.Symlink(p.Run, link)
	p.requestedRun = link
	if p.ValidateRuntime() == nil {
		t.Fatal("client fallback bypassed requested path")
	}
}

func TestOwnerAtomicPublicationAndStartIdentity(t *testing.T) {
	p := paths(t)
	// A killed pre-publication writer can leave only a temporary record, which
	// cannot become owner.pid or block recovery.
	os.WriteFile(filepath.Join(p.Run, ".owner-interrupted"), []byte(`{"pid":`), 0600)
	stop := make(chan struct{})
	observed := make(chan error, 1)
	go func() {
		for {
			select {
			case <-stop:
				observed <- nil
				return
			default:
			}
			b, e := os.ReadFile(filepath.Join(p.Run, "owner.pid"))
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				observed <- e
				return
			}
			var r ownerRecord
			if json.Unmarshal(b, &r) != nil || r.PID <= 0 || r.Start == "" {
				observed <- fmt.Errorf("partial published owner")
				return
			}
		}
	}()
	for i := 0; i < 50; i++ {
		if e := RecordOwner(p); e != nil {
			t.Fatal(e)
		}
		os.Remove(filepath.Join(p.Run, "owner.pid"))
	}
	close(stop)
	if e := <-observed; e != nil {
		t.Fatal(e)
	}
	if e := RecordOwner(p); e != nil {
		t.Fatal(e)
	}
	b, e := readOwner(p)
	if e != nil {
		t.Fatal(e)
	}
	if stale, e := ownerStale(b); e != nil || stale {
		t.Fatalf("live identity %v %v", stale, e)
	}
	var r ownerRecord
	json.Unmarshal(b, &r)
	r.Start = "different-process-incarnation"
	b, _ = json.Marshal(r)
	if stale, e := ownerStale(b); e != nil || !stale {
		t.Fatalf("reused PID %v %v", stale, e)
	}
	if e = os.WriteFile(filepath.Join(p.Run, "owner.pid"), b, 0600); e != nil {
		t.Fatal(e)
	}
	if e = RecordOwner(p); e != nil {
		t.Fatal("PID reuse blocked", e)
	}
	for _, bad := range []string{"", `{"pid":`, `1`} {
		if stale, _ := ownerStale([]byte(bad)); stale {
			t.Fatal("ambiguous owner treated as dead")
		}
	}
}
func TestDarwinACLGrantsRejected(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS ACL regression")
	}
	p := paths(t)
	lockPath := filepath.Join(p.Data, "acl.lock")
	f, e := Lock(lockPath)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	for _, target := range []string{p.Run, p.Data, lockPath} {
		grant := "everyone allow read,write,delete"
		if target != lockPath {
			grant = "everyone allow list,search,add_file,delete_child"
		}
		cmd := exec.Command("/bin/chmod", "+a", grant, target)
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("ACL fixture %v %s", e, out)
		}
		if target == lockPath {
			if f, e := Lock(lockPath); e == nil {
				f.Close()
				t.Error("ACL lock accepted")
			}
		} else {
			if e := ValidateDir(target, false); e == nil {
				t.Error("ACL directory accepted")
			}
		}
		// The ACL directory also fails as an ancestor of an owner-only child.
		if target == p.Data {
			child := filepath.Join(target, "child")
			if e := os.Mkdir(child, 0700); e != nil {
				t.Fatal(e)
			}
			if ValidateDir(child, false) == nil {
				t.Error("mutable ACL ancestor accepted")
			}
		}
		if out, e := exec.Command("/bin/chmod", "-N", target).CombinedOutput(); e != nil {
			t.Fatalf("ACL cleanup %v %s", e, out)
		}
	}
}

func TestDarwinAncestorACLSearchAndAddSubdirectory(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS ACL regression")
	}
	for _, grant := range []string{"search", "add_subdirectory"} {
		t.Run(grant, func(t *testing.T) {
			p := paths(t)
			parent := filepath.Dir(p.Data)
			if out, e := exec.Command("/bin/chmod", "+a", "everyone allow "+grant, parent).CombinedOutput(); e != nil {
				t.Fatalf("ACL fixture %v %s", e, out)
			}
			t.Cleanup(func() {
				if out, e := exec.Command("/bin/chmod", "-N", parent).CombinedOutput(); e != nil {
					t.Errorf("ACL cleanup %v %s", e, out)
				}
			})
			// Long test paths can move p.Run to the short socket fallback.
			// The requested run path remains below this ACL-bearing parent.
			for _, child := range []string{p.Data, p.requestedRun} {
				e := ValidateDir(child, false)
				if grant == "search" && e != nil {
					t.Fatalf("search-only ancestor rejected %v", e)
				}
				if grant == "add_subdirectory" && !errors.Is(e, ErrUnsafe) {
					t.Fatalf("mutable ancestor accepted %v", e)
				}
			}
			if e := p.Prepare(); (e == nil) != (grant == "search") {
				t.Fatalf("prepare with ancestor %s %v", grant, e)
			}
		})
	}
}
