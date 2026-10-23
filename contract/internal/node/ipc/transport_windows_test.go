package ipc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsVolumeRootCreationACL(t *testing.T) {
	current, e := currentSID()
	if e != nil {
		t.Fatal(e)
	}
	const creation = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	for _, tc := range []struct {
		name               string
		mask               uint32
		rootOK, ancestorOK bool
	}{
		{"read-search", windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE, true, true},
		{"add-file", windows.FILE_WRITE_DATA, true, false},
		{"add-subdirectory", windows.FILE_APPEND_DATA, true, false},
		{"create-both", creation, true, false},
		{"delete-child", creation | 0x40, false, false},
		{"delete-self", creation | windows.DELETE, false, false},
		{"write-dacl", creation | windows.WRITE_DAC, false, false},
		{"write-owner", creation | windows.WRITE_OWNER, false, false},
		{"write-ea", creation | windows.FILE_WRITE_EA, false, false},
		{"write-attributes", creation | windows.FILE_WRITE_ATTRIBUTES, false, false},
		{"generic-write", creation | windows.GENERIC_WRITE, false, false},
		{"generic-all", creation | windows.GENERIC_ALL, false, false},
		{"maximum-allowed", creation | windows.MAXIMUM_ALLOWED, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Build the real Windows ACL in-process. CI+AD is the standard
			// BUILTIN\Users volume-root pattern; never change the host root ACL.
			sd, e := windows.SecurityDescriptorFromString(fmt.Sprintf("O:SYD:P(A;;FA;;;SY)(A;CI;0x%x;;;BU)", tc.mask))
			if e != nil {
				t.Fatal(e)
			}
			for _, root := range []bool{true, false} {
				want := tc.ancestorOK
				if root {
					want = tc.rootOK
				}
				e = checkAncestorSecurity(sd, current, root)
				if (e == nil) != want || (e != nil && !errors.Is(e, ErrUnsafe)) {
					t.Fatalf("volume root %v, accepted %v, want %v, error %v", root, e == nil, want, e)
				}
			}
		})
	}
	for _, sddl := range []string{
		"O:BUD:P(A;CI;AD;;;BU)",   // creation exception cannot trust a new owner
		"D:P(A;CI;AD;;;BU)",       // missing owner
		"O:SYD:NO_ACCESS_CONTROL", // null DACL
	} {
		sd, e := windows.SecurityDescriptorFromString(sddl)
		if e != nil {
			t.Fatal(e)
		}
		if e = checkAncestorSecurity(sd, current, true); !errors.Is(e, ErrUnsafe) {
			t.Fatalf("unsafe root descriptor accepted %q: %v", sddl, e)
		}
	}
}

func TestWindowsCreationACLPrivateDescendant(t *testing.T) {
	current, e := currentSID()
	if e != nil {
		t.Fatal(e)
	}
	parent := t.TempDir()
	// Exercise the root's creation ACE on an owned disposable directory, not
	// the host volume root. Only the descriptor-policy test grants root status.
	setWindowsDACL(t, parent, "D:P(A;;FA;;;"+current.String()+")(A;CI;AD;;;BU)")
	u, e := windows.UTF16PtrFromString(parent)
	if e != nil {
		t.Fatal(e)
	}
	h, e := windows.CreateFile(u, windows.READ_CONTROL|windows.FILE_LIST_DIRECTORY, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(h)
	if e = checkAncestor(h, false); !errors.Is(e, ErrUnsafe) {
		t.Fatalf("creation exception leaked to descendant ancestor: %v", e)
	}
	sd, e := ownerSecurity()
	if e != nil {
		t.Fatal(e)
	}
	child, e := relativeOpen(h, "private", true, true, sd)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(child)
	if e = checkSecurity(child); e != nil {
		t.Fatal("private descendant inherited root creation ACE", e)
	}
	// Full path validation must still refuse this non-root creation grant.
	if e = ValidateDir(filepath.Join(parent, "private"), false); !errors.Is(e, ErrUnsafe) {
		t.Fatalf("non-root creation grant accepted: %v", e)
	}
}

func TestWindowsPipeIdentityAndFirstInstance(t *testing.T) {
	base := t.TempDir()
	p, e := Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Prepare(); e != nil {
		t.Fatal(e)
	}
	l, e := Listen(p)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if other, e := Listen(p); e == nil {
		other.Close()
		t.Fatal("first instance bypass")
	}
	got := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e == nil {
			pid, pe := Peer(c)
			if pe != nil || pid != os.Getpid() {
				e = ErrPeer
			}
			c.Close()
		}
		got <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, e := Dial(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	if pid, e := Peer(c); e != nil || pid != os.Getpid() {
		t.Fatal("server SID", e)
	}
	c.Close()
	if e = <-got; e != nil {
		t.Fatal("client SID", e)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, e = Peer(a); e == nil {
		t.Fatal("nonpipe identity")
	}
}
func TestWindowsPrivateDACLAndLock(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "private")
	if e := ValidateDir(path, true); e != nil {
		t.Fatal(e)
	}
	lock, e := Lock(filepath.Join(path, "db.lock"))
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	if other, e := Lock(filepath.Join(path, "db.lock")); e == nil {
		other.Close()
		t.Fatal("LockFileEx contention")
	}
	// Add an Everyone allow ACE. Existing state must be refused, never repaired.
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if e != nil {
		t.Fatal(e)
	}
	acl, _, e := sd.DACL()
	if e != nil {
		t.Fatal(e)
	}
	if e = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); e != nil {
		t.Fatal(e)
	}
	if e = ValidateDir(path, false); e == nil {
		t.Fatal("Everyone DACL accepted")
	}
}
func TestWindowsRejectRemoteClient(t *testing.T) {
	p, e := Resolve(filepath.Join(t.TempDir(), "data"), filepath.Join(t.TempDir(), "run"))
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Prepare(); e != nil {
		t.Fatal(e)
	}
	l, e := Listen(p)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	// The local-machine UNC route is still a remote pipe client.
	remote := `\\localhost\pipe\` + p.Endpoint[len(`\\.\pipe\`):]
	u, e := windows.UTF16PtrFromString(remote)
	if e != nil {
		t.Fatal(e)
	}
	h, e := windows.CreateFile(u, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if e == nil {
		windows.CloseHandle(h)
		t.Fatal("remote pipe client admitted")
	}
}

func windowsPaths(t *testing.T) Paths {
	t.Helper()
	base := t.TempDir()
	p, e := Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Prepare(); e != nil {
		t.Fatal(e)
	}
	return p
}
func acceptWithin(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	result := make(chan net.Conn, 1)
	errs := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			errs <- e
		} else {
			result <- c
		}
	}()
	select {
	case c := <-result:
		return c
	case e := <-errs:
		t.Fatal(e)
	case <-time.After(2 * time.Second):
		l.Close()
		t.Fatal("accept timed out")
	}
	return nil
}
func TestWindowsAuthenticatedPipeDeadlines(t *testing.T) {
	p := windowsPaths(t)
	l, e := Listen(p)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, e := Dial(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server := acceptWithin(t, l)
	defer server.Close()
	// Both identity branches must leave IOCP polling intact.
	for _, c := range []net.Conn{server, client} {
		if _, e = Peer(c); e != nil {
			t.Fatal(e)
		}
	}
	if e = server.SetDeadline(time.Now().Add(40 * time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	var b [1]byte
	_, e = server.Read(b[:])
	var ne net.Error
	if !errors.As(e, &ne) || !ne.Timeout() || time.Since(start) > time.Second {
		t.Fatalf("idle hello deadline %v %s", e, time.Since(start))
	}
	if e = server.SetDeadline(time.Time{}); e != nil {
		t.Fatal(e)
	}
	if e = client.SetWriteDeadline(time.Now().Add(40 * time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	start = time.Now()
	_, e = client.Write(bytes.Repeat([]byte("x"), 8<<20))
	if !errors.As(e, &ne) || !ne.Timeout() || time.Since(start) > time.Second {
		t.Fatalf("blocked nudge/write deadline %v %s", e, time.Since(start))
	}
}
func TestWindowsDisconnectBeforeAcceptRecycles(t *testing.T) {
	p := windowsPaths(t)
	l, e := Listen(p)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	probe, e := Dial(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	probe.Close()
	result := make(chan error, 1)
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				result <- e
				return
			}
			var b [1]byte
			_, e = io.ReadFull(c, b[:])
			c.Close()
			if e == nil && b[0] == 'x' {
				result <- nil
				return
			}
		}
	}()
	client, e := Dial(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	client.SetWriteDeadline(time.Now().Add(time.Second))
	if _, e = client.Write([]byte("x")); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-result:
		if e != nil {
			t.Fatal("probe killed listener", e)
		}
	case <-ctx.Done():
		t.Fatal("listener did not recover")
	}
}
func setWindowsDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		t.Fatal(e)
	}
	acl, _, e := sd.DACL()
	if e != nil {
		t.Fatal(e)
	}
	if e = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); e != nil {
		t.Fatal(e)
	}
}
func TestWindowsMutableAncestorAndJunctionRefused(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "hostile")
	child := filepath.Join(parent, "private")
	if e := ValidateDir(child, true); e != nil {
		t.Fatal(e)
	}
	sid, e := currentSID()
	if e != nil {
		t.Fatal(e)
	}
	// Everyone includes a different local user. That principal could rename or
	// replace children even though the leaf has an owner-only DACL.
	setWindowsDACL(t, parent, "D:P(A;;FA;;;"+sid.String()+")(A;;FA;;;WD)")
	if ValidateDir(child, false) == nil {
		t.Fatal("another-user mutation rights accepted")
	}
	if f, e := Lock(filepath.Join(child, "db.lock")); e == nil {
		f.Close()
		t.Fatal("mutable ancestor used")
	}
	setWindowsDACL(t, parent, "D:P(A;;FA;;;"+sid.String()+")")
	target := filepath.Join(base, "target")
	if e = ValidateDir(target, true); e != nil {
		t.Fatal(e)
	}
	junction := filepath.Join(parent, "junction")
	if out, e := exec.Command("cmd.exe", "/c", "mklink", "/J", junction, target).CombinedOutput(); e != nil {
		t.Fatalf("junction fixture %v %s", e, out)
	}
	defer os.Remove(junction)
	if ValidateDir(junction, false) == nil {
		t.Fatal("junction accepted")
	}
	if f, e := Lock(filepath.Join(junction, "db.lock")); e == nil {
		f.Close()
		t.Fatal("junction followed")
	}
}
func TestWindowsAncestorHandlesRetainedUntilLockClose(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	child := filepath.Join(parent, "private")
	if e := ValidateDir(child, true); e != nil {
		t.Fatal(e)
	}
	f, e := Lock(filepath.Join(child, "db.lock"))
	if e != nil {
		t.Fatal(e)
	}
	moved := filepath.Join(base, "renamed")
	if e = os.Rename(parent, moved); e == nil {
		f.Close()
		os.Rename(moved, parent)
		t.Fatal("verified ancestor renamed during lock lifetime")
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(parent, moved); e != nil {
		t.Fatal("ancestor handle leaked", e)
	}
}
