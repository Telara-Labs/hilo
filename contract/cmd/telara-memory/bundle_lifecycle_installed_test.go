//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/bundle"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/syncnode"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// dirFiles lists every name in dir, including hidden staging names.
func dirFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// TestBundleExportPausedAfterSelectionCannotPublishErasedData pauses a real
// export command after selection, with its sealed staging copy written, and
// erases the selected checkpoint through the running daemon. The erasure is
// reported pending while the export runs; the export then refuses to
// publish, destroys its staging copy and leaves no file. Only then does a
// retried scrub complete. A later export of the same ids carries no erased
// text.
func TestBundleExportPausedAfterSelectionCannotPublishErasedData(t *testing.T) {
	useBundleVaults(t)
	a := newGenesisDevice(t)
	an := a.start()
	canary := "pausedexportheronlanterncanary"
	plantTask(t, an, canary)
	records := dataRecords(t, a.paths.Data)
	b := joinDevice(t, a)
	bID := b.identity()
	var checkpoint string
	for _, r := range records {
		if r.kind == "checkpoint" {
			checkpoint = r.id
		}
	}
	outDir := t.TempDir()
	out := filepath.Join(outDir, "paused.age")
	var eraseOut bytes.Buffer
	var eraseErr error
	var stagedNames []string
	old := bundleExportStaged
	bundleExportStaged = func() {
		stagedNames = dirFiles(t, outDir)
		eraseErr = run(context.Background(), []string{"erase", "--data-dir", a.paths.Data, "--run-dir", a.paths.Run, "--yes", "--json", "--id", checkpoint}, strings.NewReader(""), &eraseOut)
	}
	t.Cleanup(func() { bundleExportStaged = old })

	_, err := a.cli("", withIDs([]string{"bundle", "export", "--to", bID.Device, "--out", out}, idsOf(records))...)
	bundleExportStaged = old
	if len(stagedNames) != 1 || !strings.HasSuffix(stagedNames[0], ".partial") {
		t.Fatal("no staging copy while paused", stagedNames)
	}
	if eraseErr == nil || publicCode(eraseErr) != "scrub_pending" {
		t.Fatal("erasure reported complete while the export held the erased body", eraseErr, eraseOut.String())
	}
	if err == nil || publicCode(err) != "bundle_invalidated" {
		t.Fatal("export published after the erasure", err)
	}
	if names := dirFiles(t, outDir); len(names) != 0 {
		t.Fatal("invalidated export left files", names)
	}
	var scrub bytes.Buffer
	if err = run(context.Background(), []string{"erase", "--data-dir", a.paths.Data, "--run-dir", a.paths.Run, "--scrub-pending", "--json"}, strings.NewReader(""), &scrub); err != nil {
		t.Fatal("scrub after the export ended", publicCode(err), scrub.String())
	}
	if hits := an.filesContaining("checkpoint " + canary); len(hits) != 0 {
		t.Fatal("erased checkpoint bytes remain in", hits)
	}
	// The same selection now exports without the erased records.
	rep := restoreReport(t, a.mustCLI("", withIDs([]string{"bundle", "export", "--to", bID.Device, "--out", out, "--json"}, idsOf(records))...))
	sealed, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err := bundle.OpenTransfer(sealed, mustIdentity(t, b))
	if err != nil || bytes.Contains(plain, []byte("checkpoint "+canary)) || rep.Data >= len(records) {
		t.Fatal("later export carries erased data", rep.Data, err)
	}
}

// eventErasure signs an erasure whose only selector is one event, as the
// device of key and machine.
func eventErasure(t *testing.T, key ed25519.PrivateKey, machine, genesis, nonce, eventID string) store.SignedRecord {
	t.Helper()
	keyID := sig.KeyID(key.Public().(ed25519.PublicKey))
	sk, err := record.SessionKey("claude-code", "local", record.NativeGlobal, "33333333-3333-4333-8333-333333333333", "")
	if err != nil {
		t.Fatal(err)
	}
	h := record.Header{Type: record.KindErasure, Prov: record.ProvUser, At: 1761150000999, Author: record.Author{MachineID: machine, KeyID: keyID}, Red: record.Redact{Profile: record.ProfileLocal}}
	if h.LID, err = record.ControlLID(record.KindErasure, keyID, record.H("nonce", nonce)[:32]); err != nil {
		t.Fatal(err)
	}
	r, err := record.Build(h, &record.ErasureBody{EventCoverage: "complete", Reason: "user_request", Selectors: record.Selectors{Events: []record.EventSelector{{Owner: genesis, SessionKey: sk, EventID: eventID}}}})
	if err != nil {
		t.Fatal(err)
	}
	sg, err := sig.SignRecord(key, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return store.SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: []record.Signature{sg}, AdvisoryID: r.ID}
}

// TestBundleRestoreReviewsEventSelectorControls restores a valid same-genesis
// bundle that carries an event-selector erasure matching nothing here. The
// restore shows a content-free review and applies nothing without the typed
// confirmation; a wrong word or closed input refuses; the confirmation word
// or --yes applies it.
func TestBundleRestoreReviewsEventSelectorControls(t *testing.T) {
	useBundleVaults(t)
	a := newGenesisDevice(t)
	a.start()
	a.stop()
	b := joinDevice(t, a)
	offer := trustOffer(t, b, a)
	aID := a.identity()
	key := a.deviceKey()
	defer clear(key)
	keyring := envelopeLines(t, selectionOf(t, a, []string{strings.Repeat("0", 64)}).Keyring)
	memory := filepath.Join(b.paths.Data, "memory.sqlite")
	stored := func(id string) int { return countIn(t, memory, "SELECT count(*) FROM record WHERE id=?", id) }

	ban := eventErasure(t, key, aID.Machine, aID.Genesis, "restore-review-one", "ev1:"+strings.Repeat("e", 64))
	file := writeTemp(t, "event-ban.age", sealedFor(t, key, aID.Genesis, keyring, nil, envelopeLines(t, []store.SignedRecord{ban}), nil, offer.Recipient, nil))
	for _, stdin := range []string{"", "no\n", "erase\n"} {
		out, err := b.cli(stdin, "bundle", "restore", "--in", file)
		if err == nil || publicCode(err) != "confirmation_required" {
			t.Fatalf("restore with %q: %v\n%s", stdin, publicCode(err), out)
		}
		if !strings.Contains(out, ban.AdvisoryID) || !strings.Contains(out, "events 1") || !strings.Contains(out, "Type confirm") {
			t.Fatal("restore did not show the control review", out)
		}
		if stored(ban.AdvisoryID) != 0 {
			t.Fatal("unconfirmed event selector applied")
		}
	}
	out := b.mustCLI("confirm\n", "bundle", "restore", "--in", file)
	checkLimits(t, out, "Restore complete")
	if stored(ban.AdvisoryID) != 1 {
		t.Fatal("confirmed control not applied")
	}
	// Restoring it again needs no review: it is already admitted.
	b.mustCLI("", "bundle", "restore", "--in", file)

	// --yes is the explicit non-interactive confirmation; JSON output keeps
	// the review as its own frame when the prompt is used.
	second := eventErasure(t, key, aID.Machine, aID.Genesis, "restore-review-two", "ev1:"+strings.Repeat("d", 64))
	file = writeTemp(t, "event-ban-2.age", sealedFor(t, key, aID.Genesis, keyring, nil, envelopeLines(t, []store.SignedRecord{second}), nil, offer.Recipient, nil))
	out, err := b.cli("", "bundle", "restore", "--in", file, "--json")
	if err == nil || publicCode(err) != "confirmation_required" || !strings.Contains(out, `"controls_requiring_confirmation"`) {
		t.Fatal("json restore without confirmation", publicCode(err), out)
	}
	b.mustCLI("", "bundle", "restore", "--in", file, "--yes", "--json")
	if stored(second.AdvisoryID) != 1 {
		t.Fatal("--yes did not apply the control")
	}
}

// TestBundleReceiptIssuerIsTheExistingLoginPin derives the receipt authority
// a restore uses only from the device's own enrolled sync profile: none
// before login, exactly the tenant and service key pinned by login after.
func TestBundleReceiptIssuerIsTheExistingLoginPin(t *testing.T) {
	useBundleVaults(t)
	old := syncVault
	syncVault = func(dir string) syncnode.SecretVault {
		bundleVaults.Lock()
		defer bundleVaults.Unlock()
		return bundleVaults.m[dir]
	}
	t.Cleanup(func() { syncVault = old })
	d := newGenesisDevice(t)
	d.start()
	if receiptIssuer(d.paths.Data) != nil {
		t.Fatal("receipt authority without any login")
	}
	login := func(stdin string, args ...string) {
		t.Helper()
		var out bytes.Buffer
		if err := run(context.Background(), append(args, "--data-dir", d.paths.Data), strings.NewReader(stdin), &out); err != nil {
			t.Fatalf("%v: %s\n%s", args, publicCode(err), out.String())
		}
	}
	tenant := newLoginTenant(t, 83, "tenant-receipt-pin", "receipt-user")
	_, policyEnv := tenant.policy(1, "receiptpinrulecanary")
	login("", "login", "--key")
	login(tenant.document(d, policyEnv, "telara_mcp_receipt_pin"), "login")
	issuer := receiptIssuer(d.paths.Data)
	if issuer == nil || issuer.Tenant != "tenant-receipt-pin" || len(issuer.Keys) != 1 || !bytes.Equal(issuer.Keys[sig.KeyID(tenant.service)], tenant.service) {
		raw, _ := json.Marshal(issuer)
		t.Fatal("receipt authority is not the login pin", string(raw))
	}
}
