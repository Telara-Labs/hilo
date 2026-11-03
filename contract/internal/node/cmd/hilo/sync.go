package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/syncnode"
	"github.com/Telara-Labs/hilo/contract/internal/node/vault"
)

type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

// syncVault is replaced only by in-process tests that cannot reach a native
// keychain. Production always uses the profile-bound native vault.
var syncVault = func(data string) syncnode.SecretVault { return vault.ForProfile(data) }

// runSync manages hosted metadata sync for one data directory. Enrollment input
// is read from standard input so the refresh credential never appears in argv.
func runSync(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("invalid_arguments")
	}
	sub := args[0]
	fs := flag.NewFlagSet("sync "+sub, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	data := fs.String("data-dir", "", "Owner-only data directory")
	installDir := fs.String("install-dir", "", "Owner-only installation directory")
	id := fs.String("id", "", "Selection rule id")
	kinds := fs.String("kinds", "session,task", "Comma-separated record kinds")
	var repos repeated
	fs.Var(&repos, "repo", "Repository id to select (repeatable)")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	allowed := map[string]bool{"data-dir": true, "install-dir": true}
	switch sub {
	case "select":
		allowed["id"], allowed["kinds"], allowed["repo"] = true, true, true
	case "unselect":
		allowed["id"] = true
	case "key", "enroll", "status", "enable", "disable", "logout":
	default:
		return errors.New("invalid_command")
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
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dir, err := syncDataDir(ctx, *data, *installDir)
	if err != nil {
		return err
	}
	switch sub {
	case "key":
		jkt, err := syncnode.CreateKey(ctx, dir, syncVault(dir))
		if err != nil {
			return err
		}
		return ipc.WriteFrame(out, map[string]string{"jkt": jkt})
	case "enroll":
		e, err := syncnode.ParseEnrollment(in)
		if err != nil {
			return err
		}
		if err = syncnode.Enroll(ctx, dir, syncVault(dir), e); err != nil {
			return err
		}
		return ipc.WriteFrame(out, map[string]string{"state": "enrolled"})
	case "status":
		r, err := syncnode.Status(ctx, dir)
		if err != nil {
			return err
		}
		return ipc.WriteFrame(out, r)
	case "enable", "disable":
		if err = syncnode.SetEnabled(dir, sub == "enable"); err != nil {
			return err
		}
		return ipc.WriteFrame(out, map[string]string{"state": sub + "d"})
	case "logout":
		if err = syncnode.Logout(ctx, dir, syncVault(dir)); err != nil {
			return err
		}
		return ipc.WriteFrame(out, map[string]string{"state": "logged_out"})
	}
	st, err := syncnode.OpenState(ctx, dir)
	if err != nil {
		return err
	}
	defer st.Close()
	if sub == "unselect" {
		if err = st.RemoveRule(ctx, *id); err != nil {
			return err
		}
		return ipc.WriteFrame(out, map[string]string{"state": "removed"})
	}
	rule, err := st.PutRule(ctx, *id, repos, strings.Split(*kinds, ","), true)
	if err != nil {
		return err
	}
	return ipc.WriteFrame(out, rule)
}

// syncDataDir uses an explicit data directory, else the installed profile's.
func syncDataDir(ctx context.Context, data, installDir string) (string, error) {
	if data != "" {
		p, err := ipc.Resolve(data, "")
		if err != nil {
			return "", errors.New("invalid_paths")
		}
		return p.Data, nil
	}
	dir := installDir
	if dir == "" {
		var err error
		if dir, err = install.DefaultDir(); err != nil {
			return "", err
		}
	}
	r, err := install.Status(ctx, dir)
	if err != nil && !errors.Is(err, install.ErrUnavailable) {
		return "", err
	}
	if r.Record.DataDir == "" {
		return "", errors.New("invalid_paths")
	}
	return r.Record.DataDir, nil
}
