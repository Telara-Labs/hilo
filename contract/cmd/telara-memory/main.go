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
	case "daemon", "managed-daemon", "shim", "install", "uninstall", "status", "register", "start", "stop", "upgrade":
		return runService(ctx, args, out, in)
	default:
		return errors.New("invalid_command")
	}
}

func main() {
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
	for _, code := range []error{install.ErrUnavailable, install.ErrStopped, install.ErrUnverified, install.ErrUnsafe, install.ErrUpgrade, daemon.ErrSettlement,
		clients.ErrOptions, clients.ErrUnsafe, clients.ErrConflict, clients.ErrMalformed, clients.ErrBusy} {
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
	case "invalid_arguments", "invalid_command", "invalid_paths", "daemon_unavailable", "settlement_unknown", "release_inputs_required":
		return e.Error()
	}
	return "daemon_error"
}
