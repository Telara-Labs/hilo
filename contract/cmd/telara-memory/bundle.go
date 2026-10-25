package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/bundle"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/vault"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// noSurvivingDeviceLimit is printed by install, export, backup, join and
// restore. Recovery after losing every device is not offered in this version.
const noSurvivingDeviceLimit = "Loss of every device means a new identity. A bundle or backup can be restored only on a device that a surviving device of the same identity has added, so if every device is lost, old bundles and backups cannot be imported. This is not full disaster recovery."

// rollbackWarning is printed by every restore and backup.
const rollbackWarning = "Restoring is a rollback to the bundle's contents. A bundle cannot contain erasures issued after it was made. Erasures already on this device stay in force; erasures from your other devices apply only when this device receives them. Erasures not yet checked."

// unmanagedCopyNotice is printed by export and backup.
const unmanagedCopyNotice = "The written file is an unmanaged copy. A later erasure cannot remove records from it; keep it private and delete it when it is no longer needed."

// bundleVault is replaced only by in-process tests that cannot reach a native
// keychain. Production always uses the profile-bound native vault.
var bundleVault = func(data string) bundle.Vault { return vault.ForProfile(data) }

func bundleError(err error) error {
	var b bundle.Error
	if errors.As(err, &b) {
		return publicError(string(b))
	}
	var s *store.Error
	if errors.As(err, &s) {
		return publicError(s.Code)
	}
	return err
}

// runBundle manages encrypted same-identity bundles. Every payload that moves
// between machines is read from standard input and written to standard output;
// passphrases are read only from standard input, never from arguments.
func runBundle(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("invalid_arguments")
	}
	sub := args[0]
	fs := flag.NewFlagSet("bundle "+sub, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	data := fs.String("data-dir", "", "Owner-only data directory")
	installDir := fs.String("install-dir", "", "Owner-only installation directory")
	var ids, to repeated
	fs.Var(&ids, "id", "Exact record id to select (repeatable)")
	fs.Var(&to, "to", "Device key id of a trusted transfer recipient (repeatable)")
	outPath := fs.String("out", "", "New bundle file to write")
	inPath := fs.String("in", "", "Bundle file to restore")
	code := fs.String("code", "", "Six-word code shown by the other device")
	backup := fs.Bool("backup", false, "Restore a passphrase backup read from standard input")
	asJSON := fs.Bool("json", false, "Print the report as JSON")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	allowed := map[string]bool{"data-dir": true, "install-dir": true}
	switch sub {
	case "key", "invite":
	case "join", "enroll":
		delete(allowed, "install-dir")
	case "trust", "add-device":
		allowed["code"] = true
	case "export":
		allowed["id"], allowed["to"], allowed["out"], allowed["json"] = true, true, true, true
	case "backup":
		allowed["id"], allowed["out"], allowed["json"] = true, true, true
	case "restore":
		allowed["in"], allowed["backup"], allowed["json"] = true, true, true
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
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if sub == "join" || sub == "enroll" {
		if *data == "" {
			return errors.New("invalid_arguments")
		}
		p, err := ipc.Resolve(*data, "")
		if err != nil {
			return errors.New("invalid_paths")
		}
		if sub == "join" {
			return bundleError(bundleJoin(ctx, p.Data, in, out))
		}
		return bundleError(bundleEnroll(ctx, p.Data, in, out))
	}
	dir, err := syncDataDir(ctx, *data, *installDir)
	if err != nil {
		return err
	}
	switch sub {
	case "key":
		err = bundleKey(ctx, dir, out)
	case "trust":
		err = bundleTrust(ctx, dir, *code, in, out)
	case "invite":
		err = bundleInvite(ctx, dir, out)
	case "add-device":
		err = bundleAddDevice(ctx, dir, *code, in, out)
	case "export", "backup":
		if len(ids) == 0 || *outPath == "" || (sub == "export") != (len(to) > 0) {
			return errors.New("invalid_arguments")
		}
		mode := bundle.ModeTransfer
		if sub == "backup" {
			mode = bundle.ModeBackup
		}
		err = bundleExport(ctx, dir, mode, ids, to, *outPath, *asJSON, in, out)
	case "restore":
		if *inPath == "" {
			return errors.New("invalid_arguments")
		}
		err = bundleRestore(ctx, dir, *inPath, *backup, *asJSON, in, out)
	}
	return bundleError(err)
}

// openProfile opens the profile's store under its installed pins.
func openProfile(ctx context.Context, dir string) (bundle.Identity, *store.Store, error) {
	id, err := bundle.ProfileIdentity(dir)
	if err != nil {
		return id, nil, err
	}
	st, err := store.Open(ctx, store.Options{Dir: dir, PinnedGenesisID: id.Genesis, LocalMachineID: id.Machine})
	if err != nil {
		return id, nil, err
	}
	return id, st, nil
}

// deviceKey returns a copy of the profile's device signing key, which the
// caller clears. It never leaves this process.
func deviceKey(ctx context.Context, dir string, id bundle.Identity) (ed25519.PrivateKey, error) {
	genesis, machine, key, err := disclosure.InstalledDeviceKey(ctx, dir, bundleVault(dir))
	if err != nil {
		return nil, bundle.ErrProfile
	}
	if genesis != id.Genesis || machine != id.Machine || sig.KeyID(key.Public().(ed25519.PublicKey)) != id.Device {
		clear(key)
		return nil, bundle.ErrProfile
	}
	return key, nil
}

func bundleKey(ctx context.Context, dir string, out io.Writer) error {
	id, err := bundle.ProfileIdentity(dir)
	if err != nil {
		return err
	}
	o, err := bundle.EnsureExportKey(ctx, dir, bundleVault(dir), id)
	if err != nil {
		return err
	}
	return ipc.WriteFrame(out, o)
}

func bundleTrust(ctx context.Context, dir, code string, in io.Reader, out io.Writer) error {
	if code == "" {
		return publicError("confirmation_required")
	}
	o, err := bundle.ParseOffer(in)
	if err != nil {
		return err
	}
	id, st, err := openProfile(ctx, dir)
	if err != nil {
		return err
	}
	defer st.Close()
	keyring, err := st.Keyring(ctx)
	if err != nil {
		return err
	}
	if err = bundle.TrustRecipient(dir, id, keyring, o, code); err != nil {
		return err
	}
	return ipc.WriteFrame(out, map[string]string{"state": "trusted", "device": o.Device})
}

func bundleInvite(ctx context.Context, dir string, out io.Writer) error {
	id, st, err := openProfile(ctx, dir)
	if err != nil {
		return err
	}
	defer st.Close()
	keyring, err := st.Keyring(ctx)
	if err != nil {
		return err
	}
	key, err := deviceKey(ctx, dir, id)
	if err != nil {
		return err
	}
	defer clear(key)
	inv, err := bundle.NewInvite(id, keyring, key)
	if err != nil {
		return err
	}
	return ipc.WriteFrame(out, inv)
}

func bundleJoin(ctx context.Context, dir string, in io.Reader, out io.Writer) error {
	inv, err := bundle.ParseInvite(in)
	if err != nil {
		return err
	}
	q, err := bundle.Join(ctx, dir, bundleVault(dir), inv, disclosure.NewMachineID)
	if err != nil {
		return err
	}
	if err = ipc.WriteFrame(out, q); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Verification code %s\nType it on the surviving device with bundle add-device --code to add this device.\n%s\n", q.Code, noSurvivingDeviceLimit)
	return err
}

func bundleAddDevice(ctx context.Context, dir, code string, in io.Reader, out io.Writer) error {
	if code == "" {
		return publicError("confirmation_required")
	}
	q, err := bundle.ParseJoinRequest(in)
	if err != nil {
		return err
	}
	id, st, err := openProfile(ctx, dir)
	if err != nil {
		return err
	}
	defer st.Close()
	keyring, err := st.Keyring(ctx)
	if err != nil {
		return err
	}
	key, err := deviceKey(ctx, dir, id)
	if err != nil {
		return err
	}
	completed, offer, err := bundle.Authorize(id, keyring, key, q, code)
	clear(key)
	if err != nil {
		return err
	}
	if _, err = st.Append(ctx, completed); err != nil {
		return err
	}
	if keyring, err = st.Keyring(ctx); err != nil {
		return err
	}
	if err = bundle.TrustRecipient(dir, id, keyring, offer, offer.Code); err != nil {
		return err
	}
	return ipc.WriteFrame(out, bundle.NewEnrollment(id.Genesis, keyring))
}

func bundleEnroll(ctx context.Context, dir string, in io.Reader, out io.Writer) error {
	e, err := bundle.ParseEnrollment(in)
	if err != nil {
		return err
	}
	lock, err := ipc.Lock(filepath.Join(dir, "db.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	v := bundleVault(dir)
	id, err := bundle.Enroll(ctx, dir, v, e, func(ctx context.Context, key ed25519.PrivateKey, machine, genesis, add string, keyring []store.SignedRecord) error {
		return disclosure.BootstrapJoined(ctx, dir, "Installed local clients",
			disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S, disclosure.P, disclosure.E}},
			disclosure.TaskWriteGrant{Repos: disclosure.AllLocalRepos(), AllowUnscoped: true,
				Actions: []disclosure.TaskMutation{disclosure.Create, disclosure.Checkpoint, disclosure.Pause, disclosure.Complete}}, v, key, machine, genesis, add, keyring)
	})
	if err != nil {
		return err
	}
	return ipc.WriteFrame(out, map[string]string{"state": "enrolled", "genesis": id.Genesis, "device": id.Device, "machine": id.Machine})
}

// readSecretLine reads one passphrase line from standard input.
func readSecretLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", bundle.ErrPassphrase
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" || len(line) > 1024 {
		return "", bundle.ErrPassphrase
	}
	return line, nil
}

// bundleReport is the content-free outcome of an export, backup or restore.
type bundleReport struct {
	Mode     string                  `json:"mode"`
	Path     string                  `json:"path"`
	Keyring  int                     `json:"keyring"`
	Facts    int                     `json:"exposure_facts"`
	Controls int                     `json:"controls"`
	Data     int                     `json:"data"`
	Excluded []store.BundleExclusion `json:"excluded"`
	Fenced   bool                    `json:"held_until_erasures_checked,omitempty"`
	Limits   []string                `json:"limits"`
}

func writeBundleReport(out io.Writer, title string, r bundleReport, asJSON bool) error {
	if r.Excluded == nil {
		r.Excluded = []store.BundleExclusion{}
	}
	if asJSON {
		return ipc.WriteFrame(out, r)
	}
	var b strings.Builder
	line := func(key, value string) { fmt.Fprintf(&b, "  %-22s %s\n", key, value) }
	b.WriteString(title + "\n")
	line("mode", r.Mode)
	line("file", r.Path)
	line("keyring operations", fmt.Sprint(r.Keyring))
	line("exposure facts", fmt.Sprint(r.Facts))
	line("controls", fmt.Sprint(r.Controls))
	line("records", fmt.Sprint(r.Data))
	if r.Fenced {
		line("restored records", "held until erasures from hosted sync are checked")
	}
	if len(r.Excluded) > 0 {
		b.WriteString("\nNot included\n")
		for _, e := range r.Excluded {
			line(e.ID, e.Reason)
		}
	}
	b.WriteString("\n")
	for _, s := range r.Limits {
		b.WriteString(s + "\n")
	}
	_, err := io.WriteString(out, b.String())
	return err
}

// writeNewFile creates path exclusively with owner-only permissions.
func writeNewFile(path string, b []byte) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("invalid_paths")
	}
	f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", publicError("output_exists_or_unwritable")
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(abs)
		return "", publicError("output_write_failed")
	}
	return abs, nil
}

func bundleExport(ctx context.Context, dir, mode string, ids, to []string, outPath string, asJSON bool, in io.Reader, out io.Writer) error {
	var passphrase string
	if mode == bundle.ModeBackup {
		r := bufio.NewReader(io.LimitReader(in, 4096))
		first, err := readSecretLine(r)
		if err != nil {
			return err
		}
		second, err := readSecretLine(r)
		if err != nil || second != first {
			return bundle.ErrPassphrase
		}
		if len(first) < bundle.MinPassphrase {
			return bundle.ErrPassphrase
		}
		passphrase = first
	}
	id, st, err := openProfile(ctx, dir)
	if err != nil {
		return err
	}
	defer st.Close()
	keyring, err := st.Keyring(ctx)
	if err != nil {
		return err
	}
	var recipients []string
	if mode == bundle.ModeTransfer {
		if recipients, err = bundle.Recipients(dir, id, keyring, to); err != nil {
			return err
		}
	}
	// Selection and its policy recheck happen under the store writer
	// immediately before the bundle is framed and encrypted.
	sel, err := st.SelectBundle(ctx, ids)
	if err != nil {
		return err
	}
	key, err := deviceKey(ctx, dir, id)
	if err != nil {
		return err
	}
	plaintext, _, err := bundle.Encode(sel, id.Genesis, key, time.Now().UnixMilli())
	clear(key)
	if err != nil {
		return err
	}
	var sealed []byte
	if mode == bundle.ModeTransfer {
		sealed, err = bundle.SealTransfer(plaintext, recipients)
	} else {
		sealed, err = bundle.SealBackup(plaintext, passphrase)
	}
	clear(plaintext)
	if err != nil {
		return err
	}
	path, err := writeNewFile(outPath, sealed)
	if err != nil {
		return err
	}
	limits := []string{noSurvivingDeviceLimit, unmanagedCopyNotice}
	if mode == bundle.ModeBackup {
		limits = append(limits, rollbackWarning)
	}
	title := "Transfer bundle written"
	if mode == bundle.ModeBackup {
		title = "Backup written"
	}
	return writeBundleReport(out, title, bundleReport{Mode: mode, Path: path, Keyring: len(sel.Keyring), Facts: len(sel.Facts), Controls: len(sel.Controls), Data: len(sel.Data), Excluded: sel.Excluded, Limits: limits}, asJSON)
}

func bundleRestore(ctx context.Context, dir, inPath string, backup, asJSON bool, in io.Reader, out io.Writer) error {
	id, err := bundle.ProfileIdentity(dir)
	if err != nil {
		return err
	}
	f, err := os.Open(inPath)
	if err != nil {
		return publicError("input_unreadable")
	}
	raw, err := io.ReadAll(io.LimitReader(f, bundle.MaxCiphertext+1))
	f.Close()
	if err != nil {
		return publicError("input_unreadable")
	}
	mode := bundle.ModeTransfer
	var plaintext []byte
	var kinds []string
	if backup {
		mode = bundle.ModeBackup
		passphrase, err := readSecretLine(bufio.NewReader(io.LimitReader(in, 4096)))
		if err != nil {
			return err
		}
		plaintext, kinds, err = bundle.OpenBackup(raw, passphrase)
		if err != nil {
			return err
		}
	} else {
		identity, err := bundle.LoadExportIdentity(ctx, dir, bundleVault(dir), id)
		if err != nil {
			return err
		}
		if plaintext, kinds, err = bundle.OpenTransfer(raw, identity); err != nil {
			return err
		}
	}
	defer clear(plaintext)
	c, err := bundle.Decode(plaintext, id.Genesis)
	if err != nil {
		return err
	}
	if transport.ValidateBundleMode(id.Genesis, c.Manifest.Genesis, mode, kinds) != nil {
		return bundle.ErrUnsupportedMode
	}
	st, err := store.Open(ctx, store.Options{Dir: dir, PinnedGenesisID: id.Genesis, LocalMachineID: id.Machine})
	if err != nil {
		return err
	}
	defer st.Close()
	local, err := st.Keyring(ctx)
	if err != nil {
		return err
	}
	if err = bundle.Verify(c, local); err != nil {
		return err
	}
	r, err := st.ImportBundle(ctx, store.BundleImport{LocalKeyID: id.Device, Keyring: c.Keyring, Facts: c.FactLines, Controls: c.Controls, Data: c.Data})
	if err != nil {
		return err
	}
	abs, _ := filepath.Abs(inPath)
	return writeBundleReport(out, "Restore complete", bundleReport{Mode: mode, Path: abs, Keyring: r.Keyring, Facts: r.Facts, Controls: r.Controls, Data: r.Data, Excluded: r.Excluded, Fenced: r.Fenced, Limits: []string{rollbackWarning, noSurvivingDeviceLimit}}, asJSON)
}
