// Command telara-memory provides local daemon, stdio shim and status entrypoints.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/shim"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/syncnode"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/vault"
)

func run(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("invalid_arguments")
	}
	switch args[0] {
	case "hook":
		return runHook(ctx, args[1:], in)
	case "clients":
		return runClients(ctx, args[1:], out)
	case "sync":
		return runSync(ctx, args[1:], in, out)
	case "login":
		return runLogin(ctx, args[1:], in, out)
	case "logout":
		return runLogout(ctx, args[1:], out)
	case "erase":
		return runErase(ctx, args[1:], in, out)
	case "bundle":
		return runBundle(ctx, args[1:], in, out)
	case "doctor":
		return runDoctor(ctx, args[1:], out)
	case "verify-release":
		return runVerifyRelease(args[1:], out)
	case "daemon", "managed-daemon", "shim", "install", "uninstall", "status", "register", "start", "stop", "upgrade":
		return runService(ctx, args, out, in)
	default:
		return errors.New("invalid_command")
	}
}

func main() {
	if vault.RunHelper(os.Args[1:], os.Stdin, os.Stdout) {
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), stopSignals()...)
	defer cancel()
	if e := run(ctx, os.Args[1:], os.Stdin, os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, publicCode(e))
		os.Exit(1)
	}
}
func publicCode(e error) string {
	var refused *shim.AutostartError
	if errors.As(e, &refused) {
		return refused.Error()
	}
	var fixed publicError
	if errors.As(e, &fixed) {
		return fixed.Error()
	}
	for _, code := range []error{install.ErrUnavailable, install.ErrStopped, install.ErrUnverified, install.ErrUnsafe, install.ErrUpgrade, daemon.ErrSettlement,
		clients.ErrOptions, clients.ErrUnsafe, clients.ErrConflict, clients.ErrMalformed, clients.ErrBusy, vault.ErrKeychainUnavailable, vault.ErrUnavailable,
		syncnode.ErrProfile, syncnode.ErrNotEnrolled, syncnode.ErrIdentity, syncnode.ErrCredential, syncnode.ErrEnrollment, syncnode.ErrUnsupported, syncnode.ErrRule,
		syncnode.ErrTenantConflict, syncnode.ErrLogin, syncnode.ErrPolicyState, syncnode.ErrPolicyNotCurrent} {
		if errors.Is(e, code) {
			return code.Error()
		}
	}
	switch {
	case errors.Is(e, ipc.ErrUnsafe):
		return "unsafe_path"
	case errors.Is(e, ipc.ErrBusy):
		return "busy"
	case errors.Is(e, ipc.ErrPeer):
		return "peer_identity"
	case errors.Is(e, ipc.ErrFrame):
		return "invalid_frame"
	}
	switch e.Error() {
	case "invalid_arguments", "invalid_command", "invalid_paths", "daemon_unavailable", "settlement_unknown", "release_inputs_required", "runtime_authority_unavailable":
		return e.Error()
	}
	return "daemon_error"
}
