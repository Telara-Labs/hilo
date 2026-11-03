package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/doctor"
	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

// runDoctor prints a read-only report. It never starts the daemon, changes
// the installation or reads record content.
func runDoctor(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	asJSON := fs.Bool("json", false, "Print the report as JSON")
	data := fs.String("data-dir", "", "Owner-only data directory")
	run := fs.String("run-dir", "", "Owner-only runtime directory")
	installDir := fs.String("install-dir", "", "Owner-only installation directory")
	home := fs.String("home", "", "Client home for hook status")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dir := *installDir
	if dir == "" {
		var err error
		if dir, err = install.DefaultDir(); err != nil {
			return err
		}
	}
	r, err := doctor.Run(ctx, doctor.Config{InstallDir: dir, DataDir: *data, RunDir: *run, Home: *home})
	if err != nil {
		return errors.New("invalid_paths")
	}
	if *asJSON {
		return ipc.WriteFrame(out, r)
	}
	return doctor.WriteText(out, r)
}
