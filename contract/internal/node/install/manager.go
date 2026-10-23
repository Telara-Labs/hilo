package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

func lockInstall(dir string) (io.Closer, error) {
	if e := ensureDir(dir, true); e != nil {
		return nil, e
	}
	return ipc.Lock(filepath.Join(dir, "install.lock"))
}
func verifyDefinition(r Record) error {
	expected, e := Definition(r.Platform, r)
	if e != nil {
		return e
	}
	f, release, e := openTrusted(definitionPath(r), true)
	// Service parents may be 0755, but the definition itself is owner-only.
	if e != nil {
		return e
	}
	defer release()
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || !bytes.Equal(b, expected) {
		return ErrUnverified
	}
	return nil
}

// Commands are fixed native tools. No shell, PATH search, elevation, lingering,
// or caller-controlled flags. Output is bounded and never included in errors.
type boundedOutput struct{ bytes.Buffer }

// A context-local command adapter keeps manager argument unit tests isolated
// from the user's actual manager. Production callers cannot construct this key.
type commandKey struct{}
type commandAdapter func(context.Context, string, ...string) ([]byte, error)

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 65536 {
		keep := 65536 - b.Len()
		if len(p) > keep {
			p = p[:keep]
		}
		b.Buffer.Write(p)
	}
	return n, nil
}
func nativeCommand(ctx context.Context, platform string, args ...string) ([]byte, error) {
	if adapter, ok := ctx.Value(commandKey{}).(commandAdapter); ok {
		return adapter(ctx, platform, args...)
	}
	path := managerTool(platform)
	if path == "" {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	var out boundedOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	if e := cmd.Run(); e != nil {
		return out.Bytes(), ErrUnavailable
	}
	return out.Bytes(), nil
}

func domain(r Record) string { return "gui/" + r.UserID }
func service(r Record) string {
	if r.Platform == "darwin" {
		return domain(r) + "/" + r.Label
	}
	return r.Label + ".service"
}
func managerAvailable(ctx context.Context, r Record) error {
	var e error
	switch r.Platform {
	case "darwin":
		_, e = nativeCommand(ctx, r.Platform, "print", domain(r))
	case "linux":
		_, e = nativeCommand(ctx, r.Platform, "--user", "show", "--property=Version", "--value")
	case "windows":
		_, e = nativeCommand(ctx, r.Platform, "/Query", "/FO", "CSV", "/NH")
	default:
		e = ErrUnavailable
	}
	return e
}
func managerInstall(ctx context.Context, r Record) error {
	var e error
	switch r.Platform {
	case "darwin":
		_, e = nativeCommand(ctx, r.Platform, "bootstrap", domain(r), definitionPath(r))
	case "linux":
		if _, e = nativeCommand(ctx, r.Platform, "--user", "daemon-reload"); e == nil {
			if e = registered(ctx, r); e == nil {
				_, e = nativeCommand(ctx, r.Platform, "--user", "enable", "--now", service(r))
			}
		}
	case "windows":
		if _, e = nativeCommand(ctx, r.Platform, "/Create", "/TN", r.Label, "/XML", definitionPath(r)); e == nil {
			e = managerStart(ctx, r)
		}
	default:
		e = ErrUnavailable
	}
	return e
}

// errAbsent is returned only after a successful inventory or an exact native
// not-found diagnostic. Permission failures and manager outages are not absence.
var errAbsent = errors.New("registration absent")

func managerStatus(ctx context.Context, r Record) error {
	if e := registered(ctx, r); e != nil {
		return e
	}
	if r.Platform == "linux" {
		b, e := nativeCommand(ctx, r.Platform, "--user", "is-enabled", service(r))
		if e != nil || strings.TrimSpace(string(b)) != "enabled" {
			return ErrUnavailable
		}
	}
	return nil
}
func managerStart(ctx context.Context, r Record) error {
	if r.Platform != "darwin" {
		if e := registered(ctx, r); e != nil {
			return e
		}
	}
	var e error
	switch r.Platform {
	case "darwin":
		if e := managerStatus(ctx, r); errors.Is(e, errAbsent) {
			return managerInstall(ctx, r)
		} else if e != nil {
			return e
		}
		_, e = nativeCommand(ctx, r.Platform, "kickstart", service(r)) // never -k
	case "linux":
		_, e = nativeCommand(ctx, r.Platform, "--user", "start", service(r))
	case "windows":
		_, e = nativeCommand(ctx, r.Platform, "/Run", "/TN", r.Label)
	default:
		e = ErrUnavailable
	}
	return e
}
func managerStop(ctx context.Context, r Record) error {
	if e := registered(ctx, r); e != nil {
		if errors.Is(e, errAbsent) {
			return nil
		}
		return e
	}
	var e error
	switch r.Platform {
	case "darwin":
		_, e = nativeCommand(ctx, r.Platform, "bootout", service(r))
		if e != nil && errors.Is(registered(ctx, r), errAbsent) {
			return nil
		}
	case "linux":
		_, e = nativeCommand(ctx, r.Platform, "--user", "stop", service(r))
	case "windows":
		// Quiesce already proved a successful process exit. Leave the logon
		// trigger enabled for the next login, never /End an unsettled writer.
		// Any failure retry in this login meets the owner-only stop intent.
		return nil
	default:
		e = ErrUnavailable
	}
	return e
}
func managerReplace(ctx context.Context, r Record, old Record) error {
	if e := registered(ctx, old); e != nil && !(old.Platform == "darwin" && errors.Is(e, errAbsent)) {
		return e
	}
	if r.Platform == "windows" {
		if _, e := nativeCommand(ctx, r.Platform, "/Create", "/TN", r.Label, "/XML", definitionPath(r), "/F"); e != nil {
			return e
		}
		return managerStart(ctx, r)
	}
	if r.Platform == "linux" {
		if _, e := nativeCommand(ctx, r.Platform, "--user", "daemon-reload"); e != nil {
			return e
		}
	}
	return managerStart(ctx, r)
}
func managerUninstall(ctx context.Context, r Record) error {
	if e := registered(ctx, r); e != nil {
		if errors.Is(e, errAbsent) {
			return nil
		}
		return e
	}
	switch r.Platform {
	case "darwin":
		return nil // already booted out after quiescence
	case "linux":
		_, e := nativeCommand(ctx, r.Platform, "--user", "disable", service(r))
		return e
	case "windows":
		_, e := nativeCommand(ctx, r.Platform, "/Delete", "/TN", r.Label, "/F")
		return e
	}
	return ErrUnavailable
}

func unixSession(ctx context.Context, platform string) (string, error) {
	var b []byte
	var e error
	if platform == "darwin" {
		b, e = nativeCommand(ctx, platform, "print", "gui/"+strconv.Itoa(os.Geteuid()))
		if e != nil {
			return "", e
		}
		// The audit session belongs to the GUI bootstrap domain and changes
		// on logout/login. Do not use the requesting terminal's getsid.
		for _, line := range strings.Split(string(b), "\n") {
			p := strings.SplitN(strings.TrimSpace(line), "=", 2)
			if len(p) == 2 && strings.TrimSpace(p[0]) == "asid" {
				id := strings.TrimSpace(p[1])
				if _, e = strconv.ParseUint(id, 10, 64); e == nil {
					return id, nil
				}
			}
		}
		return "", ErrUnavailable
	}
	b, e = nativeCommand(ctx, platform, "--user", "show", "init.scope", "--property=InvocationID", "--value")
	if e != nil {
		return "", e
	}
	id := strings.TrimSpace(string(b))
	if len(id) != 32 {
		return "", ErrUnavailable
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return "", ErrUnavailable
		}
	}
	if id == strings.Repeat("0", 32) {
		return "", ErrUnavailable
	}
	return id, nil
}

// No manager operation may be claimed successful from an exit code alone.
// Live readiness is deliberately left to daemon.Probe by the command adapter.
