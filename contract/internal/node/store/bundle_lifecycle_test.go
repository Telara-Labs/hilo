package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

// inflight registers one export the way the export command does: the lock
// is held before registration, the sealed staging copy is written next to
// the final path.
type inflight struct {
	token, staging, final string
	lock                  interface{ Close() error }
}

func registerExport(t *testing.T, s *Store, o Options, n byte, ids []string, signer ControlSigner, content []byte) (inflight, BundleSelection) {
	t.Helper()
	token := strings.Repeat(string("0123456789abcdef"[n%16]), 32)
	lock, err := ipc.Lock(BundleExportLock(o.Dir, token))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	e := inflight{token: token, staging: filepath.Join(dir, ".out.age."+token+".partial"), final: filepath.Join(dir, "out.age"), lock: lock}
	sel, err := s.RegisterBundleExport(context.Background(), token, e.staging, ids, signer)
	if err != nil {
		lock.Close()
		t.Fatal(err)
	}
	if err = os.WriteFile(e.staging, content, 0600); err != nil {
		t.Fatal(err)
	}
	return e, sel
}

func (e inflight) publish(s *Store, ids []string) error {
	return s.PublishBundleExport(context.Background(), e.token, ids, func() error { return os.Rename(e.staging, e.final) })
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// TestBundleExportPausedAfterSelectionLosesToErasure pauses an export after
// selection, with its sealed staging copy on disk, and erases the selected
// record. The erasure stays pending while the exporter runs; publication then
// finds the selection invalidated, destroys staging and writes nothing; only
// afterwards does the scrub complete. A crashed exporter's staging copy is
// destroyed by the next scrub. Unchanged selections still publish.
func TestBundleExportPausedAfterSelectionLosesToErasure(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	signer := worldSigner{w.key}
	task := w.task(31, "paused export 9c1e")
	w.append(task)
	ids := []string{task.AdvisoryID}

	// Negative control: nothing changes between selection and publication.
	ok, sel := registerExport(t, w.s, w.o, 1, ids, signer, task.BodyJCS)
	if len(sel.Data) != 1 {
		t.Fatal("selection", sel.Excluded)
	}
	if err := ok.publish(w.s, ids); err != nil || !exists(t, ok.final) || exists(t, ok.staging) {
		t.Fatal("unchanged selection did not publish", err)
	}
	ok.lock.Close()

	// The race: paused after selection, erased, then publication attempted.
	paused, sel := registerExport(t, w.s, w.o, 2, ids, signer, task.BodyJCS)
	if len(sel.Data) != 1 {
		t.Fatal("selection", sel.Excluded)
	}
	receipt, err := w.s.EraseExact(ctx, EraseRequest{IDs: ids}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := w.s.Scrub(ctx, receipt.Control); err != nil || res.State != "pending" {
		t.Fatal("erasure reported complete while an export holding the erased body runs", res, err)
	}
	if !exists(t, paused.staging) {
		t.Fatal("staging vanished under a live exporter")
	}
	if err = paused.publish(w.s, ids); Code(err) != "bundle_invalidated" {
		t.Fatal("publication after erasure", err)
	}
	if exists(t, paused.final) || exists(t, paused.staging) {
		t.Fatal("invalidated export left a copy")
	}
	paused.lock.Close()
	if res, err := w.s.Scrub(ctx, receipt.Control); err != nil || res.State != "complete" {
		t.Fatal("scrub after the export ended", res, err)
	}

	// A crashed exporter: lock released, staging left behind, registration
	// still present. The next scrub destroys staging before completing.
	other := w.task(32, "crashed export 2b77")
	w.append(other)
	crashed, _ := registerExport(t, w.s, w.o, 3, []string{other.AdvisoryID}, signer, other.BodyJCS)
	crashed.lock.Close()
	receipt, err = w.s.EraseExact(ctx, EraseRequest{IDs: []string{other.AdvisoryID}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := w.s.Scrub(ctx, receipt.Control); err != nil || res.State != "complete" {
		t.Fatal(res, err)
	}
	if exists(t, crashed.staging) || countRows(t, w.s, "SELECT count(*) FROM bundle_export") != 0 {
		t.Fatal("crashed export staging survived a clean scrub")
	}

	// A key change between selection and publication also invalidates it.
	third := w.task(33, "rekeyed export 7f0a")
	w.append(third)
	rekeyed, _ := registerExport(t, w.s, w.o, 4, []string{third.AdvisoryID}, signer, third.BodyJCS)
	joinDevice(t, w)
	if err = rekeyed.publish(w.s, []string{third.AdvisoryID}); Code(err) != "bundle_invalidated" || exists(t, rekeyed.final) || exists(t, rekeyed.staging) {
		t.Fatal("publication after a keyring change", err)
	}
	rekeyed.lock.Close()
}

// governedSession is a session with one chunk and a repository remote,
// sealed under the given policy id.
func governedSession(w *world, pol, text string) (SignedRecord, SignedRecord) {
	w.t.Helper()
	repo, err := record.RepoID("github.com/acme/widgets")
	if err != nil {
		w.t.Fatal(err)
	}
	e := w.event(text)
	sk := w.sessionKey()
	chunk := w.signed(record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk, RepoID: repo}, LID: record.ChunkLID(sk, testMachine, e.ID), Pol: pol}, &record.ChunkBody{Events: []record.Event{e}})
	session := w.signed(record.Header{Type: record.KindSession, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk, RepoID: repo}, LID: record.SessionLID(sk, testMachine, 0), Pol: pol}, &record.SessionBody{NativeID: "22222222-2222-4222-8222-222222222222", NativeIDKind: record.NativeGlobal, MachineOS: "darwin", Chunks: []string{chunk.AdvisoryID}, Repo: &record.RepoRef{ID: repo, Remote: "github.com/acme/widgets"}})
	return chunk, session
}

func pushPolicy(mutate func(*record.PolicyBody)) record.PolicyBody {
	b := record.PolicyBody{NotAfter: time.Now().Add(time.Hour).UnixMilli(), Push: record.PolicyPush{MaxProfile: record.ProfilePushMetadata, AllowRepos: []string{"github.com/acme/*"}}}
	if mutate != nil {
		mutate(&b)
	}
	return b
}

// TestBundleGovernedMetadataVariantExportAndImport builds the complete
// current authorization under the store writer. A governed session travels
// as a fresh signed push-metadata variant, never its full body, and a
// receiver logged in to the same tenant admits it. Refusals sit alongside:
// a preview requirement and a local ceiling deny export, and a receiver whose
// ceiling is local, or which has no tenant, denies import.
func TestBundleGovernedMetadataVariantExportAndImport(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	receiver := joinDevice(t, w)
	sign := installTenant(t, w, "tenant-variant")
	head := sign(1, pushPolicy(nil))
	w.append(head)
	const canary = "governed_variant_body_canary_51c3"
	chunk, session := governedSession(w, head.AdvisoryID, canary)
	w.append(chunk)
	w.append(session)
	ids := []string{session.AdvisoryID, chunk.AdvisoryID}

	// Existing records only: every governed full body is denied.
	plain, err := w.s.SelectBundle(ctx, ids)
	if err != nil || len(plain.Data) != 0 || excludedReason(plain, session.AdvisoryID) != ExcludedPolicy {
		t.Fatal("governed full body selected", plain.Excluded, err)
	}
	e, sel := registerExport(t, w.s, w.o, 5, ids, worldSigner{w.key}, []byte("sealed"))
	if len(sel.Data) != 1 || excludedReason(sel, chunk.AdvisoryID) != ExcludedPolicy || excludedReason(sel, session.AdvisoryID) != "" {
		t.Fatal("governed metadata export", len(sel.Data), sel.Excluded)
	}
	if err = e.publish(w.s, ids); err != nil {
		t.Fatal("governed metadata publication", err)
	}
	e.lock.Close()
	v, err := record.Parse(sel.Data[0].HeaderJCS, sel.Data[0].BodyJCS, sel.Data[0].AdvisoryID)
	if err != nil {
		t.Fatal(err)
	}
	if v.Header.Red.Profile != record.ProfilePushMetadata || v.Header.Links.Origin != session.AdvisoryID || v.Header.Pol != head.AdvisoryID {
		t.Fatalf("variant header %+v", v.Header)
	}
	if _, ok := v.Body.(*record.SessionMetaBody); !ok || bytes.Contains(sel.Data[0].BodyJCS, []byte(canary)) || bytes.Contains(sel.Data[0].BodyJCS, chunk.BodyJCS) {
		t.Fatal("variant carries the full body")
	}
	if res := sig.VerifyRecord(v, sel.Data[0].Sigs, mustKeyState(t, w.s), sig.Context{Route: record.RouteBundleImport}); res.Status != sig.StatusVerified {
		t.Fatal("variant signature", res.Reason)
	}

	// Import refusals alongside the permitted path.
	in := BundleImport{LocalKeyID: receiver.KeyID(), Keyring: sel.Keyring, Data: sel.Data}
	if r, err := receiver.s.ImportBundle(ctx, in); err != nil || r.Data != 0 || len(r.Excluded) != 1 || r.Excluded[0].Reason != ExcludedPolicy {
		t.Fatal("receiver without a tenant admitted governed metadata", r, err)
	}
	rsign := installTenant(t, &world{t: t, s: receiver.s, o: receiver.o}, "tenant-variant")
	local := rsign(1, pushPolicy(func(b *record.PolicyBody) { b.Push.MaxProfile = record.ProfileLocal }))
	if _, err = receiver.s.Append(ctx, local); err != nil {
		t.Fatal(err)
	}
	if r, err := receiver.s.ImportBundle(ctx, in); err != nil || r.Data != 0 || len(r.Excluded) != 1 || r.Excluded[0].Reason != ExcludedPolicy {
		t.Fatal("receiver with a local ceiling admitted governed metadata", r, err)
	}

	// The permitted import: the same tenant head on the receiver.
	o := testOptions(t)
	o.PinnedGenesisID, o.LocalMachineID = receiver.o.PinnedGenesisID, receiver.o.LocalMachineID
	fresh, err := Open(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	for _, r := range []SignedRecord{w.genesis, receiver.add} {
		if _, err = fresh.Append(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	installTenant(t, &world{t: t, s: fresh, o: o}, "tenant-variant")
	if _, err = fresh.Append(ctx, head); err != nil {
		t.Fatal(err)
	}
	r, err := fresh.ImportBundle(ctx, in)
	if err != nil || r.Data != 1 || len(r.Excluded) != 0 {
		t.Fatal("governed metadata import", r, err)
	}
	snap, err := fresh.Snapshot(ctx, ReadRequest{IDs: []string{v.ID}})
	if err != nil || find(snap, v.ID).State != "live" || len(find(snap, v.ID).BodyJCS) == 0 {
		t.Fatal("imported variant not live", find(snap, v.ID).State, err)
	}

	// Export refusals: a preview requirement, then a local ceiling.
	for i, mutate := range []func(*record.PolicyBody){
		func(b *record.PolicyBody) { b.Push.RequirePreview = true },
		func(b *record.PolicyBody) { b.Push.MaxProfile = record.ProfileLocal },
	} {
		ww := newWorld(t)
		s := installTenant(t, ww, "tenant-variant")
		h := s(1, pushPolicy(mutate))
		ww.append(h)
		c, sess := governedSession(ww, h.AdvisoryID, canary)
		ww.append(c)
		ww.append(sess)
		x, sel := registerExport(t, ww.s, ww.o, byte(6+i), []string{sess.AdvisoryID}, worldSigner{ww.key}, []byte("sealed"))
		x.lock.Close()
		if len(sel.Data) != 0 || excludedReason(sel, sess.AdvisoryID) != ExcludedPolicy {
			t.Fatal(i, "governed metadata exported without its authorization", sel.Excluded)
		}
	}
}

func mustKeyState(t *testing.T, s *Store) *sig.State {
	t.Helper()
	var st *sig.State
	if err := s.write(context.Background(), func() error {
		d, err := s.load(context.Background())
		if err != nil {
			return err
		}
		st = d.keyState()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

// tenantService is a hosted service key that signs acceptance receipts.
type tenantService struct {
	tenant string
	key    ed25519.PrivateKey
}

func (s tenantService) issuer() *ReceiptIssuer {
	pub := s.key.Public().(ed25519.PublicKey)
	return &ReceiptIssuer{Tenant: s.tenant, Keys: map[string]ed25519.PublicKey{sig.KeyID(pub): pub}}
}

func (s tenantService) receipt(t *testing.T, id, device string, at, hseq int64) record.Receipt {
	t.Helper()
	pub := s.key.Public().(ed25519.PublicKey)
	rc := record.Receipt{ID: id, Tenant: s.tenant, DeviceID: device, AcceptedAt: at, HSeq: hseq, Policy: strings.Repeat("d", 64)}
	msg, err := sig.ReceiptMessage(rc)
	if err != nil {
		t.Fatal(err)
	}
	sg := sig.Sign(s.key, sig.CtxReceipt, msg)
	if sg.KeyID != sig.KeyID(pub) {
		t.Fatal("receipt signer")
	}
	rc.Sig = &sg
	return rc
}

// TestBundleReceiptRestorePinnedAndUnpinned restores a record whose signing
// device was revoked after hosted accepted it. Its receipt is carried apart
// from any grant. A receiver without the issuer's existing pin keeps it out
// and resumable; the same bundle restored with that pin admits it, and it
// stays verified across a restart. A receipt after the revocation cutoff, a
// pin of another tenant and a forged receipt never grandfather it.
func TestBundleReceiptRestorePinnedAndUnpinned(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	author := joinDevice(t, w)
	recv := joinThird(t, w)
	tsk := tenantService{tenant: "tenant-receipts", key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{55}, 32))}

	// The joined device authors a task that hosted accepts.
	w.at++
	task := "4b444444-4444-4444-8444-444444444444"
	h := record.Header{Type: record.KindTask, LID: record.TaskLID(w.o.PinnedGenesisID, task), Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: record.H("op", "receipt"), At: w.at, Author: record.Author{MachineID: joinedMachine, KeyID: author.KeyID()}, Red: record.Redact{Profile: record.ProfileLocal}}
	built, err := record.Build(h, &record.TaskBody{Name: "task", Goal: "receipt restore 3d90", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	sg, err := sig.SignRecord(author.key, built.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec := wire(built, []record.Signature{sg})
	// Then the genesis device revokes it; hosted accepts the revocation later.
	heads := []string{author.add.AdvisoryID, recv.add.AdvisoryID}
	sort.Strings(heads)
	revoke := w.op(record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: sig.KeyRefOf(author.key.Public().(ed25519.PublicKey), record.RoleDevice, joinedMachine), Reason: "lost", Genesis: w.o.PinnedGenesisID, Parents: heads}, w.key, w.key)
	w.append(revoke)
	keyring, err := w.s.Keyring(ctx)
	if err != nil {
		t.Fatal(err)
	}
	accepted := tsk.receipt(t, rec.AdvisoryID, joinedMachine, 1000, 1)
	revoked := tsk.receipt(t, revoke.AdvisoryID, testMachine, 2000, 2)
	in := BundleImport{LocalKeyID: recv.KeyID(), Keyring: keyring, Data: []SignedRecord{rec}, Receipts: map[string]record.Receipt{rec.AdvisoryID: accepted, revoke.AdvisoryID: revoked}}

	stored := func() int {
		return countRows(t, recv.s, "SELECT count(*) FROM record WHERE id=?", rec.AdvisoryID)
	}
	// Unpinned: blocked and resumable, nothing stored.
	r, err := recv.s.ImportBundle(ctx, in)
	if err != nil || r.Data != 0 || len(r.Excluded) != 1 || r.Excluded[0].Reason != ExcludedReceiptPending || stored() != 0 {
		t.Fatal("unpinned receipt-dependent restore", r, err)
	}
	// A pin of another tenant is not this issuer's pin.
	otherTenant := tenantService{tenant: "tenant-other", key: tsk.key}
	in.ReceiptIssuer = otherTenant.issuer()
	if r, err = recv.s.ImportBundle(ctx, in); err != nil || r.Data != 0 || r.Excluded[0].Reason != ExcludedReceiptPending || stored() != 0 {
		t.Fatal("other tenant pin", r, err)
	}
	// A receipt accepted after the revocation cutoff never grandfathers.
	late := in
	late.ReceiptIssuer = tsk.issuer()
	late.Receipts = map[string]record.Receipt{rec.AdvisoryID: tsk.receipt(t, rec.AdvisoryID, joinedMachine, 3000, 3), revoke.AdvisoryID: revoked}
	if r, err = recv.s.ImportBundle(ctx, late); err != nil || r.Data != 0 || r.Excluded[0].Reason != ExcludedUnavailable || stored() != 0 {
		t.Fatal("late receipt", r, err)
	}
	// A forged receipt signed by another key is unverifiable under the pin.
	forger := tenantService{tenant: tsk.tenant, key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{56}, 32))}
	forged := in
	forged.ReceiptIssuer = tsk.issuer()
	forged.Receipts = map[string]record.Receipt{rec.AdvisoryID: forger.receipt(t, rec.AdvisoryID, joinedMachine, 1000, 1), revoke.AdvisoryID: revoked}
	if r, err = recv.s.ImportBundle(ctx, forged); err != nil || r.Data != 0 || r.Excluded[0].Reason != ExcludedUnavailable || stored() != 0 {
		t.Fatal("forged receipt", r, err)
	}

	// Pinned: the same bundle resumes and admits the record.
	in.ReceiptIssuer = tsk.issuer()
	if r, err = recv.s.ImportBundle(ctx, in); err != nil || r.Data != 1 || len(r.Excluded) != 0 {
		t.Fatal("pinned receipt-dependent restore", r, err)
	}
	live := func(stage string) {
		t.Helper()
		snap, err := recv.s.Snapshot(ctx, ReadRequest{IDs: []string{rec.AdvisoryID}})
		if e := find(snap, rec.AdvisoryID); err != nil || e.State != "live" || e.SignatureStatus != string(sig.StatusVerified) || len(e.BodyJCS) == 0 {
			t.Fatal(stage, "receipt-verified record not live", e.State, e.SignatureStatus, err)
		}
	}
	live("after import")
	reopenStore(t, &recv.s, recv.o)
	live("after restart")
	// The receipt is kept and travels on in a later bundle, never as a grant.
	sel, err := recv.s.SelectBundle(ctx, []string{strings.Repeat("0", 64)})
	if err != nil || sel.Receipts[revoke.AdvisoryID].ID != revoke.AdvisoryID {
		t.Fatal("retained key operation receipt not carried", err)
	}
}

// TestBundleEventSelectorControlNeedsLocalConfirmation carries a valid
// same-genesis erasure whose only selector is an event. Without the
// receiving owner's local confirmation the whole bundle is refused and the
// matching record survives; a zero-match event selector needs confirmation
// too. Review lists both; once confirmed they apply and purge the match.
func TestBundleEventSelectorControlNeedsLocalConfirmation(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	recv := joinDevice(t, w)
	const canary = "event_selector_bundle_canary_80aa"
	e := w.event(canary)
	chunk := w.chunk(e)
	w.append(chunk)
	sel, err := w.s.SelectBundle(ctx, []string{chunk.AdvisoryID})
	if err != nil || len(sel.Data) != 1 {
		t.Fatal(sel.Excluded, err)
	}
	if _, err = recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Keyring: sel.Keyring, Data: sel.Data}); err != nil {
		t.Fatal(err)
	}
	ban := deviceControl(t, w.key, testMachine, "bundle-event-ban", w.at+10, record.Selectors{Events: []record.EventSelector{{Owner: w.o.PinnedGenesisID, SessionKey: w.sessionKey(), EventID: e.ID}}})
	zero := deviceControl(t, w.key, testMachine, "bundle-zero-match", w.at+11, record.Selectors{Events: []record.EventSelector{{Owner: w.o.PinnedGenesisID, SessionKey: w.sessionKey(), EventID: "ev1:" + strings.Repeat("f", 64)}}})
	body := func() int {
		return countRows(t, recv.s, "SELECT count(*) FROM record_body WHERE id=?", chunk.AdvisoryID)
	}
	controls := []SignedRecord{ban, zero}
	for _, c := range [][]SignedRecord{{ban}, {zero}, controls} {
		if _, err = recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Keyring: sel.Keyring, Controls: c}); Code(err) != "bulk_confirmation_required" {
			t.Fatal("unconfirmed event selector applied", err)
		}
		if body() != 1 || countRows(t, recv.s, "SELECT count(*) FROM record WHERE id IN(?,?)", ban.AdvisoryID, zero.AdvisoryID) != 0 {
			t.Fatal("refused control changed the receiver")
		}
	}
	// Confirming one control does not confirm another.
	if _, err = recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Keyring: sel.Keyring, Controls: controls, ConfirmedControls: []string{ban.AdvisoryID}}); Code(err) != "bulk_confirmation_required" || body() != 1 {
		t.Fatal("partial confirmation applied an unconfirmed control", err)
	}
	review, err := recv.s.ReviewBundleControls(ctx, controls)
	if err != nil || len(review) != 2 || review[0].Events != 1 || review[1].Events != 1 {
		t.Fatal("review", review, err)
	}
	r, err := recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Keyring: sel.Keyring, Controls: controls, ConfirmedControls: []string{ban.AdvisoryID, zero.AdvisoryID}})
	if err != nil || r.Controls != 2 || body() != 0 {
		t.Fatal("confirmed event selectors", r, err)
	}
	// Admitted controls need no further review.
	if review, err = recv.s.ReviewBundleControls(ctx, controls); err != nil || len(review) != 0 {
		t.Fatal("admitted controls still reviewed", review, err)
	}
}
