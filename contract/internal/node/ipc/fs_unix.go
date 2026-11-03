//go:build darwin || linux

package ipc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// The short-socket fallback retains the v1 locator namespace across upgrades.
func platformPaths(data, run string) (Paths, error) {
	endpoint := filepath.Join(run, "node.sock")
	if len(endpoint) > 100 {
		sum := fmt.Sprintf("%x", hashPath(data))
		run = filepath.Join("/tmp", fmt.Sprintf("telara-memory-%d", os.Geteuid()), sum)
		endpoint = filepath.Join(run, "node.sock")
	}
	return Paths{Data: data, Run: run, Endpoint: endpoint}, nil
}
func hashPath(s string) [8]byte { var h [8]byte; x := shaPath(s); copy(h[:], x[:8]); return h }

// ValidateDir walks with openat/O_NOFOLLOW. Every ancestor must be non-symlink;
// the final directory must be owned by this user and exactly owner-only.
func ValidateDir(path string, create bool) error {
	fd, e := openDir(path, create)
	if e != nil {
		return e
	}
	return unix.Close(fd)
}
func openDir(path string, create bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, unsafePath("openDir", path, "absolute clean path required", nil)
	}
	// macOS /var and /tmp are system symlinks. Resolve only these OS-owned aliases.
	path = systemPath(path)
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	if e := checkACL(fd, false); e != nil {
		unix.Close(fd)
		return -1, unsafePath("openDir", "/", "ancestor ACL validation required", e)
	}
	current := "/"
	parts := splitPath(path)
	for i, part := range parts {
		current = filepath.Join(current, part)
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(e, unix.ENOENT) && create {
			if e = unix.Mkdirat(fd, part, 0700); e == nil || errors.Is(e, unix.EEXIST) {
				next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		unix.Close(fd)
		if e != nil {
			return -1, unsafePath("openat directory", current, "no symlink; directory open/create required", e)
		}
		fd = next
		var st unix.Stat_t
		if e := unix.Fstat(fd, &st); e != nil {
			unix.Close(fd)
			return -1, unsafePath("fstat directory", current, "metadata required", e)
		}
		if e := checkACL(fd, i == len(parts)-1); e != nil {
			unix.Close(fd)
			return -1, unsafePath("openDir", current, "directory ACL validation required", e)
		}
		owned := st.Uid == uint32(os.Geteuid())
		if i == len(parts)-1 {
			if !owned {
				unix.Close(fd)
				return -1, unsafePath("validate directory", current, fmt.Sprintf("owner must be current uid=%d; got uid=%d", os.Geteuid(), st.Uid), nil)
			}
			if st.Mode&0777 != 0700 {
				unix.Close(fd)
				return -1, unsafePath("validate directory", current, fmt.Sprintf("mode must be 0700; got %#o", st.Mode), nil)
			}
		} else {
			// A mutable ancestor owned by another uid can swap an otherwise
			// private final directory between validation and pathname binding.
			trusted := owned || st.Uid == 0
			sticky := st.Mode&unix.S_ISVTX != 0
			if !trusted {
				unix.Close(fd)
				return -1, unsafePath("validate ancestor", current, fmt.Sprintf("owner must be root or current uid=%d; got uid=%d", os.Geteuid(), st.Uid), nil)
			}
			if st.Mode&0022 != 0 && !sticky {
				unix.Close(fd)
				return -1, unsafePath("validate ancestor", current, fmt.Sprintf("mode forbids group/other writes without sticky protection; got %#o", st.Mode), nil)
			}
		}
	}
	if len(parts) == 0 {
		unix.Close(fd)
		return -1, unsafePath("openDir", path, "non-root private directory required", nil)
	}
	return fd, nil
}
func Lock(path string) (*os.File, error) {
	fd, e := openDir(filepath.Dir(path), false)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	// Darwin can return transient ENOENT when concurrent openat(O_CREAT)
	// calls create the same pathname. Retry only that lookup on the pinned
	// directory descriptor, preserving every no-follow/type/owner check.
	var n int
	for attempt := 0; attempt < 16; attempt++ {
		n, e = unix.Openat(fd, filepath.Base(path), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
		if !errors.Is(e, unix.ENOENT) && !errors.Is(e, unix.EINTR) {
			break
		}
	}
	if e != nil {
		return nil, unsafePath("openat lock", path, "no symlink; lock file open required", e)
	}
	f := os.NewFile(uintptr(n), path)
	var st unix.Stat_t
	if e := privateFile(n, path, &st); e != nil {
		f.Close()
		return nil, e
	}
	if e = unix.Flock(n, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		if errors.Is(e, unix.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, e
	}
	return f, nil
}
func Dial(ctx context.Context, p Paths) (net.Conn, error) {
	if e := p.ValidateRuntime(); e != nil {
		return nil, e
	}
	c, e := (&net.Dialer{}).DialContext(ctx, "unix", p.Endpoint)
	if e != nil {
		return nil, e
	}
	if _, e = Peer(c); e != nil {
		c.Close()
		return nil, e
	}
	return c, nil
}

// Listen may remove only an owned socket with a refused connect and no recorded
// live/ambiguous owner. Caller must hold both startup and database locks.
func Listen(p Paths) (net.Listener, error) {
	fi, e := os.Lstat(p.Endpoint)
	if e == nil {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uint32(os.Geteuid()) || fi.Mode()&os.ModeSocket == 0 {
			return nil, unsafePath("Listen", p.Endpoint, "socket must have current owner and socket type", nil)
		}
		c, de := net.DialTimeout("unix", p.Endpoint, HandshakeTimeout)
		if de == nil {
			c.Close()
			return nil, ErrBusy
		}
		if !errors.Is(de, syscall.ECONNREFUSED) {
			return nil, ErrBusy
		}
		b, re := readOwner(p)
		if re == nil {
			stale, se := ownerStale(b)
			if se != nil || !stale {
				return nil, ErrBusy
			}
		} else if !errors.Is(re, os.ErrNotExist) {
			return nil, unsafePath("Listen", filepath.Join(p.Run, "owner.pid"), "stale-owner record validation required", re)
		}
		again, se := os.Lstat(p.Endpoint)
		if se != nil || !os.SameFile(fi, again) {
			return nil, unsafePath("Listen", p.Endpoint, "socket identity must be unchanged before removal", se)
		}
		if e = os.Remove(p.Endpoint); e != nil {
			return nil, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: p.Endpoint, Net: "unix"})
	if e != nil {
		return nil, e
	}
	l.SetUnlinkOnClose(false)
	if e = os.Chmod(p.Endpoint, 0600); e != nil {
		l.Close()
		return nil, e
	}
	return l, nil
}
func readOwner(p Paths) ([]byte, error) {
	fd, e := openDir(p.Run, false)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	n, e := unix.Openat(fd, "owner.pid", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(n), "owner.pid")
	defer f.Close()
	var st unix.Stat_t
	if e := privateFile(n, filepath.Join(p.Run, "owner.pid"), &st); e != nil {
		return nil, e
	}
	return io.ReadAll(io.LimitReader(f, 513))
}

type ownerRecord struct {
	PID   int    `json:"pid"`
	Start string `json:"start"`
}

func ownerStale(b []byte) (bool, error) {
	var r ownerRecord
	if len(b) > 512 || json.Unmarshal(b, &r) != nil || r.PID <= 0 || r.Start == "" {
		return false, ErrBusy
	}
	identity, e := processIdentity(r.PID)
	if errors.Is(e, unix.ESRCH) {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	return identity != r.Start, nil
}
func RecordOwner(p Paths) error {
	fd, e := openDir(p.Run, false)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	if b, re := readOwner(p); re == nil {
		stale, se := ownerStale(b)
		if se != nil || !stale {
			return ErrBusy
		}
	} else if !errors.Is(re, os.ErrNotExist) {
		return re
	}
	identity, e := processIdentity(os.Getpid())
	if e != nil {
		return e
	}
	b, e := json.Marshal(ownerRecord{os.Getpid(), identity})
	if e != nil {
		return e
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	name := ".owner-" + hex.EncodeToString(nonce[:])
	n, e := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	defer unix.Unlinkat(fd, name, 0)
	f := os.NewFile(uintptr(n), name)
	defer f.Close()
	if e := checkACL(n, true); e != nil {
		return unsafePath("RecordOwner", filepath.Join(p.Run, name), "private ACL validation required", e)
	}
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	// Atomic publication under the caller-held startup/db locks. A crash leaves
	// either the prior complete record or this complete record, never a prefix.
	if e = unix.Renameat(fd, name, fd, "owner.pid"); e != nil {
		return e
	}
	return unix.Fsync(fd)
}
func Cleanup(p Paths) { os.Remove(filepath.Join(p.Run, "owner.pid")); os.Remove(p.Endpoint) }

func privateFile(fd int, path string, st *unix.Stat_t) error {
	if e := unix.Fstat(fd, st); e != nil {
		return unsafePath("fstat", path, "metadata required", e)
	}
	fail := func(rule string) error {
		return unsafePath("validate private file", path, fmt.Sprintf("%s (uid=%d mode=%#o nlink=%d)", rule, st.Uid, st.Mode, st.Nlink), nil)
	}
	if st.Uid != uint32(os.Geteuid()) {
		return fail("owner must be current user")
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fail("type must be regular file")
	}
	if st.Mode&0777 != 0600 {
		return fail("mode must be 0600")
	}
	if st.Nlink != 1 {
		return fail("link count must be one")
	}
	if e := checkACL(fd, true); e != nil {
		return unsafePath("validate private file", path, "private ACL required", e)
	}
	return nil
}
