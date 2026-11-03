package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/bundle"
	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	"github.com/Telara-Labs/hilo/contract/internal/node/syncnode"
	"github.com/Telara-Labs/hilo/contract/internal/node/vault"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
	"github.com/Telara-Labs/hilo/contract/transport"
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
	yes := fs.Bool("yes", false, "Confirm carried controls with unbounded effect without the interactive review prompt")
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
		allowed["in"], allowed["backup"], allowed["json"], allowed["yes"] = true, true, true, true
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
		err = bundleRestore(ctx, dir, *inPath, *backup, *asJSON, *yes, in, out)
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

// bundleExportStaged runs after an export's sealed staging copy is written
// and before its publication. Only in-process tests replace it, to pause an
// export between selection and publication.
var bundleExportStaged = func() {}

// bundleSigner signs governed metadata variants with the device key. The
// key never leaves this process.
type bundleSigner struct{ key ed25519.PrivateKey }

func (b bundleSigner) KeyID() string { return sig.KeyID(b.key.Public().(ed25519.PublicKey)) }
func (b bundleSigner) SignRecordID(id string) (record.Signature, error) {
	return sig.SignRecord(b.key, id)
}

// writeStaging creates the export's staging copy exclusively, owner-only,
// next to the final path so publication is a link within one directory.
func writeStaging(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return publicError("output_exists_or_unwritable")
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return publicError("output_write_failed")
	}
	return nil
}

// publishStaging makes the complete staging copy visible at the final path
// without replacing anything there, then removes the staging name.
func publishStaging(staging, final string) error {
	if err := os.Link(staging, final); err != nil {
		if errors.Is(err, os.ErrExist) {
			return publicError("output_exists_or_unwritable")
		}
		if _, statErr := os.Lstat(final); !errors.Is(statErr, os.ErrNotExist) {
			return publicError("output_exists_or_unwritable")
		}
		if err = os.Rename(staging, final); err != nil {
			return publicError("output_write_failed")
		}
		return nil
	}
	if err := os.Remove(staging); err != nil {
		os.Remove(final)
		return publicError("output_write_failed")
	}
	return nil
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
	path, err := filepath.Abs(outPath)
	if err != nil {
		return errors.New("invalid_paths")
	}
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return publicError("output_exists_or_unwritable")
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
	key, err := deviceKey(ctx, dir, id)
	if err != nil {
		return err
	}
	defer clear(key)
	// The export is registered with the erasure lifecycle under this lock
	// from selection until its staging copy is published or destroyed.
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return publicError("entropy_unavailable")
	}
	token := hex.EncodeToString(nonce[:])
	lockPath := store.BundleExportLock(dir, token)
	lock, err := ipc.Lock(lockPath)
	if err != nil {
		return err
	}
	defer func() {
		lock.Close()
		os.Remove(lockPath)
	}()
	staging := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+token+".partial")
	// Selection and its policy recheck happen under the store writer, which
	// registers the in-flight export in the same transaction.
	sel, err := st.RegisterBundleExport(ctx, token, staging, ids, bundleSigner{key})
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			st.AbandonBundleExport(context.Background(), token)
		}
	}()
	plaintext, _, err := bundle.Encode(sel, id.Genesis, key, time.Now().UnixMilli())
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
	if err = writeStaging(staging, sealed); err != nil {
		return err
	}
	bundleExportStaged()
	// Publication rechecks the current tombs, policy and keys under the
	// writer; anything that invalidates the selection destroys the staging
	// copy instead.
	linked := false
	err = st.PublishBundleExport(ctx, token, ids, func() error {
		if err := publishStaging(staging, path); err != nil {
			return err
		}
		linked = true
		return nil
	})
	if err != nil {
		if linked {
			os.Remove(path)
		}
		return err
	}
	published = true
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

// receiptIssuer is this device's existing receipt authority: the tenant and
// service keys pinned from the authenticated TLS login response of an enrolled
// sync profile. Keys an enrollment document named are not pinned and give no
// authority. Nothing in a bundle can supply or extend it.
func receiptIssuer(dir string) *store.ReceiptIssuer {
	p, err := syncnode.LoadProfile(dir)
	if err != nil || !p.ServiceKeysPinned() {
		return nil
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range p.ServiceKeys {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(k.Public)
		if err != nil || len(raw) != ed25519.PublicKeySize || sig.KeyID(raw) != k.KeyID {
			return nil
		}
		keys[k.KeyID] = ed25519.PublicKey(raw)
	}
	return &store.ReceiptIssuer{Tenant: p.Tenant, Keys: keys}
}

// confirmControls shows the content-free review of carried controls with
// unbounded effect and requires the owner to type the confirmation word. A
// closed or non-interactive input without --yes is a refusal, never consent.
func confirmControls(r *bufio.Reader, out io.Writer, review []store.ControlReview, asJSON bool) error {
	if asJSON {
		if err := ipc.WriteFrame(out, map[string]any{"controls_requiring_confirmation": review}); err != nil {
			return err
		}
	} else {
		var b strings.Builder
		fmt.Fprintf(&b, "This bundle carries %d erasure control(s) whose effect is unbounded: they also remove matching records that arrive later, even if nothing matches now.\n", len(review))
		for _, c := range review {
			fmt.Fprintf(&b, "  %s  ids %d, events %d, tasks %d, sessions %d, lids %d, sources %d\n", c.ID, c.IDs, c.Events, c.Tasks, c.Sessions, c.LIDs, c.Sources)
		}
		b.WriteString("Type confirm to apply them with this restore. ")
		if _, err := io.WriteString(out, b.String()); err != nil {
			return err
		}
	}
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return publicError("confirmation_required")
	}
	if strings.TrimSpace(line) != "confirm" {
		return publicError("confirmation_required")
	}
	return nil
}

func bundleRestore(ctx context.Context, dir, inPath string, backup, asJSON, yes bool, in io.Reader, out io.Writer) error {
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
	// One reader serves the passphrase line and the confirmation line.
	stdin := bufio.NewReader(io.LimitReader(in, 4096))
	mode := bundle.ModeTransfer
	var plaintext []byte
	var kinds []string
	if backup {
		mode = bundle.ModeBackup
		passphrase, err := readSecretLine(stdin)
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
	// Carried controls with unbounded effect need this owner's local review
	// and confirmation before anything is admitted.
	review, err := st.ReviewBundleControls(ctx, c.Controls)
	if err != nil {
		return err
	}
	var confirmed []string
	if len(review) > 0 {
		if !yes {
			if err = confirmControls(stdin, out, review, asJSON); err != nil {
				return err
			}
		}
		for _, r := range review {
			confirmed = append(confirmed, r.ID)
		}
	}
	r, err := st.ImportBundle(ctx, store.BundleImport{LocalKeyID: id.Device, Keyring: c.Keyring, Facts: c.FactLines, Controls: c.Controls, Data: c.Data, Receipts: c.Receipts, ReceiptIssuer: receiptIssuer(dir), ConfirmedControls: confirmed})
	if err != nil {
		return err
	}
	abs, _ := filepath.Abs(inPath)
	return writeBundleReport(out, "Restore complete", bundleReport{Mode: mode, Path: abs, Keyring: r.Keyring, Facts: r.Facts, Controls: r.Controls, Data: r.Data, Excluded: r.Excluded, Fenced: r.Fenced, Limits: []string{rollbackWarning, noSurvivingDeviceLimit}}, asJSON)
}
