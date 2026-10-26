package main

import (
	"context"
	"crypto/x509"
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

// loginTLSRoots validates the hosted login origin's certificate. Nil is the
// system pool; only in-process tests that serve a private origin replace it.
var loginTLSRoots *x509.CertPool

// loginError reports store refusals verbatim, and the login's own fixed
// refusals by their codes; other fixed sync codes are mapped by publicCode.
func loginError(err error) error {
	var s *store.Error
	if errors.As(err, &s) {
		return publicError(s.Code)
	}
	for _, code := range []error{syncnode.ErrLoginUnverified, syncnode.ErrProfileChanged, syncnode.ErrProfileBusy} {
		if errors.Is(err, code) {
			return publicError(code.Error())
		}
	}
	return err
}

// runLogin binds one tenant login to this device. With --key it provisions
// the device's DPoP key and prints the thumbprint the hosted login must bind.
// Otherwise it reads the login document from standard input, so the refresh
// credential never appears in argv, confirms that tenant's policy root through
// the origin's authenticated TLS login response, pins it, admits its policy
// and enables sync. A second tenant is refused until logout.
func runLogin(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	data := fs.String("data-dir", "", "Owner-only data directory")
	installDir := fs.String("install-dir", "", "Owner-only installation directory")
	hosted := fs.Bool("hosted", false, "Enroll over TLS using explicit human consent from stdin")
	key := fs.Bool("key", false, "Provision the device key and print its thumbprint")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *hosted && *key {
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
	if *hosted {
		input, err := syncnode.ParseHostedEnrollment(in)
		if err != nil {
			return loginError(err)
		}
		report, err := syncnode.EnrollHosted(ctx, dir, syncVault(dir), loginTLSRoots, input)
		if err != nil {
			return loginError(err)
		}
		return ipc.WriteFrame(out, report)
	}
	doc, err := syncnode.ParseLogin(in)
	if err != nil {
		return loginError(err)
	}
	r, err := syncnode.LoginTLS(ctx, dir, syncVault(dir), loginTLSRoots, doc)
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
