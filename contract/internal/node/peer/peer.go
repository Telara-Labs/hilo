// Package peer authorizes only the installed image behind a kernel-authenticated
// IPC peer. Hello metadata never selects an executable or grants authority.
package peer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

var ErrAuthority = errors.New("peer_authority_unavailable")

type Authority struct {
	InstallDir string
	DataDir    string
	// Drain must synchronously apply all available capture signals before return.
	// The opener may bind its live collector through the daemon context seam.
	// Without either collector, a nonempty spool explicitly denies access.
	Drain func(context.Context, string) error
}

func (a Authority) VerifyAndDrain(ctx context.Context, h ipc.Hello, credential string) error {
	if ctx == nil || ctx.Err() != nil || h.PID <= 0 || daemon.AuthenticatedPeerPID(ctx) != h.PID || credential == "" {
		return ErrAuthority
	}
	b, ok := ctx.Value(bindingKey{}).(processBinding)
	if !ok || b.check(h.PID) != nil {
		return ErrAuthority
	}
	if err := a.verify(h.PID); err != nil {
		return err
	}
	if err := a.drain(ctx, credential); err != nil {
		return ErrAuthority
	}

	// Capture draining cannot turn a dead/reused peer into authority.
	if ctx.Err() != nil {
		return ErrAuthority
	}
	if b.check(h.PID) != nil {
		return ErrAuthority
	}
	return a.verify(h.PID)
}

func (a Authority) verify(pid int) error {
	v, err := install.VerifiedExecutable(a.InstallDir)
	if err != nil {
		return ErrAuthority
	}
	defer v.Close()
	return verifyImage(pid, v.Path, v.SHA256)
}

func verifyImage(pid int, expectedPath, expectedDigest string) error {
	path, identity, err := executable(pid)
	if err != nil || identity == "" || path != expectedPath {
		return ErrAuthority
	}
	image, err := openImage(pid, path)
	if err != nil {
		return ErrAuthority
	}
	defer image.Close()
	actual, err := image.Stat()
	if err != nil || !actual.Mode().IsRegular() {
		return ErrAuthority
	}
	expected, err := os.Stat(expectedPath)
	if err != nil || !os.SameFile(actual, expected) {
		return ErrAuthority
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(image, (512<<20)+1))
	if err != nil || n > 512<<20 || hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return ErrAuthority
	}
	nextPath, nextIdentity, err := executable(pid)
	if err != nil || nextPath != path || nextIdentity != identity {
		return ErrAuthority
	}
	return nil
}

func emptySpool(data string) error {
	if !filepath.IsAbs(data) || ipc.ValidateDir(data, false) != nil {
		return ErrAuthority
	}
	spool := filepath.Join(data, "spool")
	if _, err := os.Lstat(spool); os.IsNotExist(err) {
		return nil
	}
	if ipc.ValidateDir(spool, false) != nil {
		return ErrAuthority
	}
	clients, err := os.ReadDir(spool)
	if err != nil || len(clients) > 16 {
		return ErrAuthority
	}
	for _, client := range clients {
		base := filepath.Join(spool, client.Name())
		if ipc.ValidateDir(base, false) != nil {
			return ErrAuthority
		}
		for _, sub := range []string{"new", "tmp"} {
			path := filepath.Join(base, sub)
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				continue
			}
			if ipc.ValidateDir(path, false) != nil {
				return ErrAuthority
			}
			f, err := os.Open(path)
			if err != nil {
				return ErrAuthority
			}
			names, e := f.Readdirnames(1)
			f.Close()
			if len(names) != 0 || e != io.EOF {
				return ErrAuthority
			}
		}
	}
	return nil
}

// BindConnection pins kernel credentials and process lifetime before the hello
// frame is read. The returned context is usable only while its release is held.
// Same-uid injection and IPC-handle transfer remain outside containment.
func BindConnection(ctx context.Context, c net.Conn) (context.Context, func(), error) {
	if ctx == nil || ctx.Err() != nil {
		return ctx, func() {}, ErrAuthority
	}
	b, err := bindProcess(c)
	if err != nil {
		return ctx, func() {}, ErrAuthority
	}
	if b == nil {
		// Only the explicit Darwin static implementation returns no binding.
		// Proof and lifecycle verification still refuse a missing binding.
		return ctx, func() {}, nil
	}
	return context.WithValue(ctx, bindingKey{}, b), func() { b.close() }, nil
}

type bindingKey struct{}
type processBinding interface {
	check(int) error
	close()
}

// VerifyLifecycle checks the retained connection against the receipt captured at
// managed startup. Upgrade has already set stop intent, so the ordinary live
// request verifier (which requires start intent) cannot authorize this control.
func VerifyLifecycle(ctx context.Context, record install.Record) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrAuthority
	}
	return verifyLifecyclePeer(ctx, daemon.AuthenticatedPeerPID(ctx), record)
}
func verifyLifecyclePeer(ctx context.Context, pid int, record install.Record) error {
	b, ok := ctx.Value(bindingKey{}).(processBinding)
	if !ok || pid <= 0 || b.check(pid) != nil || verifyImage(pid, record.Executable, record.SHA256) != nil || ctx.Err() != nil || b.check(pid) != nil {
		return ErrAuthority
	}
	return nil
}
