// Command telara-memory provides local daemon, stdio shim and status entrypoints.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/shim"
)

func run(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage daemon|shim|status")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	data := fs.String("data-dir", "", "Owner-only data directory")
	dir := fs.String("run-dir", "", "Owner-only runtime directory")
	start := fs.Bool("start", false, "Start unmanaged daemon for status")
	if e := fs.Parse(args[1:]); e != nil || fs.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	if args[0] != "daemon" && args[0] != "shim" && args[0] != "status" {
		return errors.New("invalid_command")
	}
	p, e := ipc.Resolve(*data, *dir)
	if e != nil {
		return errors.New("invalid_paths")
	}
	switch args[0] {
	case "daemon":
		e = daemon.Run(ctx, daemon.Config{Paths: p, Open: func(context.Context) (daemon.Backend, error) { return mcp.New(nil, nil), nil }})
		if errors.Is(e, context.Canceled) {
			return nil
		}
		return e
	case "shim":
		e = shim.Run(ctx, in, out, shim.Config{Paths: p, Start: func() error { return shim.Spawn(p) }})
		if errors.Is(e, context.Canceled) {
			return nil
		}
		return e
	case "status":
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if *start {
			if e = shim.Ensure(ctx, p, func() error { return shim.Spawn(p) }); e != nil {
				return e
			}
		}
		status, e := daemon.Probe(ctx, p)
		if e != nil {
			return errors.New("daemon_unavailable")
		}
		return ipc.WriteFrame(out, status)
	}
	return nil
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
	case "invalid_arguments", "invalid_command", "invalid_paths", "daemon_unavailable", "usage daemon|shim|status":
		return e.Error()
	}
	return "daemon_error"
}
