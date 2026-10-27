package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// runRepository exposes owner enrollment on the direct owner control channel.
// A selector is public metadata. Credential secrets never leave the native vault.
func runRepository(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("invalid_arguments")
	}
	fs := flag.NewFlagSet("repository", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	data := fs.String("data-dir", "", "Owner-only data directory")
	run := fs.String("run-dir", "", "Owner-only runtime directory")
	install := fs.String("install-dir", "", "Owner-only installation directory")
	observation := fs.String("observation", "", "Exact current signed native session record selected by the owner")
	root := fs.String("project-root", "", "Exact existing project root selected by the owner")
	remote := fs.String("remote", "", "Exact canonical repository remote selected by the owner")
	binding := fs.String("binding", "", "Exact owner binding to retire")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	method := "repository_" + args[0]
	var params any = struct{}{}
	switch args[0] {
	case "inspect":
		if *observation != "" || *root != "" || *remote != "" || *binding != "" {
			return errors.New("invalid_arguments")
		}
	case "enroll":
		if !record.IsHex64(*observation) || *root == "" || *remote == "" || *binding != "" {
			return errors.New("invalid_arguments")
		}
		params = map[string]string{"observation": *observation, "project_root": *root, "remote": *remote}
	case "revoke":
		if !record.IsHex64(*binding) || *observation != "" || *root != "" || *remote != "" {
			return errors.New("invalid_arguments")
		}
		params = map[string]string{"binding": *binding}
	default:
		return errors.New("invalid_arguments")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	p, err := profilePaths(ctx, *data, *run, *install)
	if err != nil {
		return err
	}
	res, err := daemon.Call(ctx, p, "repository", method, params)
	if err != nil {
		return publicError("daemon_unavailable")
	}
	if res.Error != nil {
		return publicError(res.Error.Message)
	}
	raw, ok := res.Result.(json.RawMessage)
	if !ok || !json.Valid(raw) {
		return ipc.ErrFrame
	}
	_, err = out.Write(append(raw, '\n'))
	return err
}
