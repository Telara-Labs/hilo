package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/peer"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/shim"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/vault"
)

// Installed key custody and per-client proofs come from the native vault and
// verified peer image. Missing authority leaves only diagnostics available.
// Client and transport hints never fill an authority gap.
func existingOpener(data string, provider mcp.RuntimeProvider) daemon.Opener {
	dir, _ := install.DefaultDir()
	return installedOpener(data, dir, provider)
}

func installedOpener(data, dir string, provider mcp.RuntimeProvider) daemon.Opener {
	return func(ctx context.Context) (daemon.Backend, error) {
		pending, pendingErr := readPending(data)
		if pendingErr == nil {
			if pending.Phase == "provisioning" {
				return nil, errors.New("runtime_authority_unavailable")
			}
			if pending.Phase == "complete" {
				// daemon.Run holds db.lock before invoking this opener. A failed
				// open remains conservatively admitted and requires settlement.
				pending.Phase = "admitted"
				if err := writePending(data, pending); err != nil {
					return nil, err
				}
			}
		} else if pendingErr != nil && !os.IsNotExist(pendingErr) {
			return nil, pendingErr
		}
		installed := provider
		if installed == nil {
			installed = mcp.InstalledRuntimeProvider{Provider: disclosure.InstalledProvider{Dir: data, Vault: peer.GuardVault(vault.New()), Peers: peer.Authority{InstallDir: dir, DataDir: data}}}
		}
		backend, err := mcp.Open(ctx, data, installed)
		if err != nil && err.Error() == "runtime_authority_unavailable" {
			// Keep doctor/lifecycle reachable with the explicit unavailable diagnostic.
			// No vault or peer-verifier fallback may manufacture installed authority.
			return mcp.Open(ctx, data, nil)
		}
		return backend, err
	}
}

func runService(ctx context.Context, args []string, out io.Writer, in io.Reader) error {
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	data := fs.String("data-dir", "", "Owner-only data directory")
	runtimeDir := fs.String("run-dir", "", "Owner-only runtime directory")
	installDir := fs.String("install-dir", "", "Owner-only installation directory")
	start := fs.Bool("start", false, "Explicitly start the installed service")
	source := fs.String("source", "", "Release executable authenticated by the caller")
	digest := fs.String("sha256", "", "SHA256 from an independently authenticated release manifest")
	version := fs.String("version", "", "Version from the authenticated release manifest")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	allowed := map[string]bool{}
	switch args[0] {
	case "daemon", "shim":
		allowed["data-dir"], allowed["run-dir"] = true, true
	case "managed-daemon":
		allowed["install-dir"] = true
	case "install":
		for _, key := range []string{"data-dir", "run-dir", "install-dir", "source", "sha256", "version"} {
			allowed[key] = true
		}
	case "upgrade":
		for _, key := range []string{"install-dir", "source", "sha256", "version"} {
			allowed[key] = true
		}
	case "status":
		for _, key := range []string{"install-dir", "start", "data-dir", "run-dir"} {
			allowed[key] = true
		}
	default:
		allowed["install-dir"] = true
	}
	valid := true
	fs.Visit(func(f *flag.Flag) {
		if !allowed[f.Name] {
			valid = false
		}
	})
	if !valid {
		return errors.New("invalid_arguments")
	}
	if args[0] == "managed-daemon" {
		if !filepath.IsAbs(*installDir) || filepath.Clean(*installDir) != *installDir {
			return errors.New("invalid_arguments")
		}
		record, err := install.VerifyRunning(*installDir)
		if errors.Is(err, install.ErrStopped) {
			return nil
		}
		if err != nil {
			return err
		}
		p, err := ipc.Resolve(record.DataDir, record.RunDir)
		if err != nil {
			return err
		}
		err = daemon.Run(ctx, daemon.Config{CustodyHandoff: installedCustodyHandoff(record), BindConnection: peer.BindConnection, Paths: p, Open: func(ctx context.Context) (daemon.Backend, error) {
			if e := vault.New().RecoverUpgrade(ctx, record); e != nil {
				return nil, e
			}
			return installedOpener(p.Data, *installDir, nil)(ctx)
		}, Verify: func() error {
			current, err := install.VerifyRunning(*installDir)
			if err != nil {
				return err
			}
			// Never open cached paths after a receipt or installation change.
			if current != record {
				return install.ErrUnverified
			}
			return nil
		}})
		if errors.Is(err, install.ErrStopped) || errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	if args[0] == "daemon" || args[0] == "shim" {
		p, err := ipc.Resolve(*data, *runtimeDir)
		if err != nil {
			return errors.New("invalid_paths")
		}
		if args[0] == "daemon" {
			err = daemon.Run(ctx, daemon.Config{BindConnection: peer.BindConnection, Paths: p, Open: existingOpener(p.Data, nil)})
		} else {
			err = shim.Run(ctx, in, out, shim.Config{Paths: p, Start: func() error { return shim.Spawn(p) }})
		}
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	// Lifecycle commands bound waiting, but a deadline never turns unknown
	// settlement into permission to hand off storage or mutate the service.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dir := *installDir
	var err error
	if dir == "" {
		dir, err = install.DefaultDir()
		if err != nil {
			return err
		}
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("invalid_arguments")
	}
	report := func(r install.Report, err error) error {
		if r.State != "" {
			if writeErr := ipc.WriteFrame(out, r); writeErr != nil {
				return writeErr
			}
		}
		return err
	}
	readiness := func(r install.Report) error {
		p, err := ipc.Resolve(r.Record.DataDir, r.Record.RunDir)
		if err != nil {
			return err
		}
		return waitReadiness(ctx, p, out)
	}
	switch args[0] {
	case "install":
		if !releaseInputs(*source, *digest, *version) {
			return errors.New("release_inputs_required")
		}
		p, err := ipc.Resolve(*data, *runtimeDir)
		if err != nil {
			return errors.New("invalid_paths")
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		var r install.Report
		var installErr error
		if err = ipc.WriteFrame(out, map[string]string{"credential_store": vault.Location()}); err != nil {
			return err
		}
		err = provisionAuthority(ctx, p.Data, vault.New(), func() error {
			r, installErr = install.Install(ctx, install.Config{Dir: dir, Home: home, Executable: *source, SHA256: *digest, Version: *version, DataDir: p.Data, RunDir: p.Run})
			if errors.Is(installErr, install.ErrUpgrade) {
				// Explicit retry of a never-opened setup may reuse only the exact
				// authenticated image/profile supplied by this owner invocation.
				prior, statusErr := install.Status(ctx, dir)
				if statusErr == nil || errors.Is(statusErr, install.ErrUnavailable) {
					if prior.Record.Dir == dir && prior.Record.SHA256 == *digest && prior.Record.Version == *version && prior.Record.DataDir == p.Data && prior.Record.RunDir == p.Run {
						if prior.State == "autostart_stopped" {
							// This explicit owner install retry authorizes resuming
							// the exact receipt. Pending startup still cannot open
							// a backend while writer admission is held here.
							if err := install.Start(ctx, dir); err != nil {
								return err
							}
						}
						r, installErr = install.Register(ctx, dir)
					}
				}
			}
			if installErr != nil && !errors.Is(installErr, install.ErrUnavailable) {
				return installErr
			}
			if r.Record.Dir != dir || r.Record.DataDir != p.Data || r.Record.RunDir != p.Run {
				return install.ErrUnverified
			}
			verified, err := install.VerifiedExecutable(dir)
			if err != nil {
				return err
			}
			return verified.Close()
		})
		if err != nil {
			return report(r, err)
		}
		if err = report(r, installErr); err != nil {
			return err
		}
		// A manager launch attempted while bootstrap held writer admission may
		// have refused the lock. Explicitly start the now-complete installation.
		if err = install.Start(ctx, dir); err != nil {
			return err
		}
		return readiness(r)
	case "register":
		r, err := install.Register(ctx, dir)
		if err = report(r, err); err != nil {
			return err
		}
		return readiness(r)
	case "start":
		if err = install.Start(ctx, dir); err != nil {
			return err
		}
		r, err := install.Status(ctx, dir)
		if err = report(r, err); err != nil {
			return err
		}
		return readiness(r)
	case "status":
		if *start && (*data != "" || *runtimeDir != "") {
			r, err := install.Status(ctx, dir)
			if err != nil {
				return err
			}
			p, err := ipc.Resolve(*data, *runtimeDir)
			if err != nil || p.Data != r.Record.DataDir || p.Run != r.Record.RunDir {
				return install.ErrUnsafe
			}
		}
		if *start {
			if err = install.Start(ctx, dir); err != nil {
				return err
			}
		}
		r, err := install.Status(ctx, dir)
		if err = report(r, err); err != nil {
			return err
		}
		// Custom status paths must match the installation; they never redirect its
		// readiness check or upgrade/stop control to a different writer.
		if *data != "" || *runtimeDir != "" {
			p, err := ipc.Resolve(*data, *runtimeDir)
			if err != nil || p.Data != r.Record.DataDir || p.Run != r.Record.RunDir {
				return install.ErrUnsafe
			}
		}
		if *start {
			return readiness(r)
		}
		p, err := ipc.Resolve(r.Record.DataDir, r.Record.RunDir)
		if err != nil {
			return err
		}
		live, err := daemon.Probe(ctx, p)
		if err != nil {
			return errors.New("daemon_unavailable")
		}
		return ipc.WriteFrame(out, live)
	case "stop", "uninstall", "upgrade":
		// The install package holds its lifecycle lock while this callback runs.
		// Read the current record there, so a concurrent reinstall cannot redirect
		// the manager mutation away from the daemon actually being quiesced.
		q := func(ctx context.Context) error { return quiesceInstalled(ctx, dir) }
		var r install.Report

		switch args[0] {
		case "stop":
			return install.Stop(ctx, dir, q)
		case "uninstall":
			return install.Uninstall(ctx, dir, func(ctx context.Context) error {
				r, err := install.Status(ctx, dir)
				if err != nil && !errors.Is(err, install.ErrUnavailable) {
					return err
				}
				if r.Record.Dir != dir {
					return install.ErrUnverified
				}
				if pending, pendingErr := readPending(r.Record.DataDir); pendingErr == nil && pending.Phase != "admitted" {
					// A validated pending record plus exclusive writer admission
					// proves no store was eligible to open, even if no daemon ever
					// existed to write a clean-close receipt.
					if err := deleteNeverAdmittedAuthority(ctx, r.Record.DataDir, vault.New()); err == nil {
						return nil
					} else if !errors.Is(err, ipc.ErrBusy) && !errors.Is(err, errAuthorityAdmitted) {
						return err
					}
				} else if pendingErr != nil && !os.IsNotExist(pendingErr) {
					return pendingErr
				}
				if err := q(ctx); err != nil {
					return err
				}
				return deleteAuthority(ctx, r.Record.DataDir, installedDeletionVault{vault.New(), r.Record})
			})
		default:
			if !releaseInputs(*source, *digest, *version) {
				return errors.New("release_inputs_required")
			}
			r, err = install.Upgrade(ctx, dir, *source, *digest, *version, func(ctx context.Context) error {
				prior, e := install.Status(ctx, dir)
				if e != nil && !errors.Is(e, install.ErrUnavailable) {
					return e
				}
				p, e := ipc.Resolve(prior.Record.DataDir, prior.Record.RunDir)
				if e != nil {
					return e
				}
				if vault.UpgradeHandoffRequired() {
					if e = requestCustodyHandoff(ctx, p, *digest); e != nil {
						// A crash may leave no live daemon. Only the retained,
						// receipt-verified old image can resume its custody work.
						if e = vault.New().ResumeUpgrade(ctx, prior.Record, *digest); e != nil {
							return e
						}
					}
				}
				return q(ctx)
			})
			if err = report(r, err); err != nil {
				return err
			}
			return readiness(r)
		}
	}
	return errors.New("invalid_command")
}
func releaseInputs(source, digest, version string) bool {
	return filepath.IsAbs(source) && filepath.Clean(source) == source && digest != "" && version != ""
}
func waitReadiness(ctx context.Context, p ipc.Paths, out io.Writer) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		probe, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		live, err := daemon.Probe(probe, p)
		cancel()
		if err == nil {
			return ipc.WriteFrame(out, live)
		}
		select {
		case <-ctx.Done():
			return errors.New("daemon_unavailable")
		case <-ticker.C:
		}
	}
}

func quiesceInstalled(ctx context.Context, dir string) error {
	r, err := install.Status(ctx, dir)
	if err != nil && !errors.Is(err, install.ErrUnavailable) {
		return err
	}
	if r.Record.Dir != dir {
		return install.ErrUnverified
	}
	p, err := ipc.Resolve(r.Record.DataDir, r.Record.RunDir)
	if err != nil {
		return err
	}
	return daemon.Quiesce(ctx, p)
}
