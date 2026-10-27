package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

func clientFlags(name string) (*flag.FlagSet, *clients.Options, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := &clients.Options{}
	client := fs.String("client", "", "claude, codex, cursor or pi")
	fs.StringVar(&o.Home, "home", "", "Client home")
	fs.StringVar(&o.ConfigRoot, "config-root", "", "Existing vendor configuration root")
	fs.StringVar(&o.Executable, "executable", "", "Node executable")
	fs.StringVar(&o.StateDir, "state-dir", "", "Node data directory")
	fs.StringVar(&o.StateDir, "data-dir", "", "Node data directory")
	fs.BoolVar(&o.Print, "print", false, "Preview installation changes")
	return fs, o, client
}
func finishClientOptions(o *clients.Options) error {
	if o.Executable == "" {
		var err error
		o.Executable, err = os.Executable()
		if err != nil {
			return err
		}
	}
	p, err := ipc.Resolve(o.StateDir, "")
	if err != nil {
		return clients.ErrOptions
	}
	o.StateDir = p.Data
	return nil
}
func runClients(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("invalid_arguments")
	}
	var action func(context.Context, clients.Options) (clients.Report, error)
	switch args[0] {
	case "install":
		action = clients.Install
	case "uninstall":
		action = clients.Uninstall
	case "status":
		action = clients.Status
	default:
		return errors.New("invalid_command")
	}
	fs, o, client := clientFlags("clients " + args[0])
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	if !validClientFlags(fs, false) {
		return errors.New("invalid_arguments")
	}
	if err := finishClientOptions(o); err != nil {
		return err
	}
	selected := []clients.Client{clients.Claude, clients.Codex, clients.Cursor, clients.Pi}
	if *client != "" {
		selected = []clients.Client{clients.Client(*client)}
	}
	var first error
	for _, c := range selected {
		o.Client = c
		r, err := action(ctx, *o)
		if r.Client != "" {
			if err := ipc.WriteFrame(out, r); err != nil {
				return err
			}
		}
		if first == nil {
			first = err
		}
	}
	return first
}
func runHook(ctx context.Context, args []string, in io.Reader) error {
	// Generated clients use --client; the public positional form is equivalent.
	// All malformed invocations are silent success, just like RunHook failures.
	fs, o, client := clientFlags("hook")
	positional := ""
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		positional = args[0]
		args = args[1:]
	}
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return nil
	}
	if positional != "" {
		if *client != "" {
			return nil
		}
		*client = positional
	}
	if !validClientFlags(fs, true) {
		return nil
	}
	o.Client = clients.Client(*client)
	if finishClientOptions(o) != nil {
		return nil
	}
	clients.RunHook(ctx, *o, in)
	return nil
}

func validClientFlags(fs *flag.FlagSet, hook bool) bool {
	seen := map[string]bool{}
	valid := true
	fs.Visit(func(f *flag.Flag) {
		seen[f.Name] = true
		if hook && (f.Name == "print" || f.Name == "executable") {
			valid = false
		}
	})
	return valid && !(seen["state-dir"] && seen["data-dir"])
}
