package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/syncnode"
)

// loginTimeout bounds one login or logout, including the store's bounded
// physical scrub of purged policy configuration.
const loginTimeout = 2 * time.Minute

// loginError reports store refusals verbatim; fixed sync codes are mapped by
// publicCode.
func loginError(err error) error {
	var s *store.Error
	if errors.As(err, &s) {
		return publicError(s.Code)
	}
	return err
}

// runLogin binds one tenant login to this device. With --key it provisions
// the device's DPoP key and prints the thumbprint the hosted login must bind.
// Otherwise it reads the login document from standard input, so the refresh
// credential never appears in argv, pins that tenant's policy root, admits its
// policy and enables sync. A second tenant is refused until logout.
func runLogin(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	data := fs.String("data-dir", "", "Owner-only data directory")
	installDir := fs.String("install-dir", "", "Owner-only installation directory")
	key := fs.Bool("key", false, "Provision the device key and print its thumbprint")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()
	dir, err := syncDataDir(ctx, *data, *installDir)
	if err != nil {
		return err
	}
	if *key {
		jkt, err := syncnode.CreateKey(ctx, dir, syncVault(dir))
		if err != nil {
			return err
		}
		return ipc.WriteFrame(out, map[string]string{"jkt": jkt})
	}
	doc, err := syncnode.ParseLogin(in)
	if err != nil {
		return loginError(err)
	}
	r, err := syncnode.Login(ctx, dir, syncVault(dir), doc)
	if err != nil {
		return loginError(err)
	}
	return ipc.WriteFrame(out, r)
}

// runLogout ends the active tenant login on this device. Records captured
// under that tenant's policy stay local, non-pushable and non-bundleable;
// hosted history is not deleted.
func runLogout(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	data := fs.String("data-dir", "", "Owner-only data directory")
	installDir := fs.String("install-dir", "", "Owner-only installation directory")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()
	dir, err := syncDataDir(ctx, *data, *installDir)
	if err != nil {
		return err
	}
	r, err := syncnode.LogoutDetailed(ctx, dir, syncVault(dir))
	if err != nil {
		return loginError(err)
	}
	return ipc.WriteFrame(out, r)
}
