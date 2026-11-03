package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

const joinedMachine = "33333333-3333-4333-8333-333333333333"

type joinedDevice struct {
	s   *Store
	o   Options
	key ed25519.PrivateKey
	add SignedRecord
}

func (j joinedDevice) KeyID() string { return sig.KeyID(j.key.Public().(ed25519.PublicKey)) }
func (j joinedDevice) SignRecordID(id string) (record.Signature, error) {
	return sig.SignRecord(j.key, id)
}

// joinDevice enrolls a second device of the sender's genesis with a device_add
// co-signed by the sender, the way a fresh machine joins before a restore.
func joinDevice(t *testing.T, sender *world) joinedDevice {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	pub := key.Public().(ed25519.PublicKey)
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(pub, record.RoleDevice, joinedMachine), Genesis: sender.o.PinnedGenesisID, Parents: []string{sender.genesis.AdvisoryID}}, sender.key.Public().(ed25519.PublicKey), testMachine, sender.at+1, key, sender.key)
	if err != nil {
		t.Fatal(err)
	}
	add := wire(op.Rec, op.Sigs)
	sender.append(add)
	o := testOptions(t)
	o.PinnedGenesisID, o.LocalMachineID = sender.o.PinnedGenesisID, joinedMachine
	st, err := Open(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for _, r := range []SignedRecord{sender.genesis, add} {
		if _, err = st.Append(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	return joinedDevice{s: st, o: o, key: key, add: add}
}

// checkpointAndCall builds an explicit no-event checkpoint P and call C whose
// signed commitment dependency is P.
func checkpointAndCall(t *testing.T, w *world, text string) (SignedRecord, SignedRecord) {
	t.Helper()
	task := "4a333333-3333-4333-8333-333333333333"
	op := record.H("bundle-transfer-op", text)
	p := w.signed(record.Header{Type: record.KindCheckpoint, LID: record.CheckpointLID(w.o.PinnedGenesisID, task, testMachine, op), Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: op}, &record.CheckpointBody{Milestone: text})
	ref, err := record.NewCallRef()
	if err != nil {
		t.Fatal(err)
	}
	w.at++
	call, err := record.BuildCall(record.Header{Type: record.KindCall, LID: record.CallLID(ref), At: w.at, Author: record.Author{MachineID: testMachine, KeyID: w.o.PinnedGenesisID}, Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: op, Red: record.Redact{Profile: record.ProfileLocal}, Links: record.Links{DerivedFrom: []string{p.AdvisoryID}}}, record.CallBody{CallRef: ref, ScopeID: "sc1:" + testMachine + ":" + strings.Repeat("1", 32), Tool: "telara_task_checkpoint", TaskID: task, Outcome: "ok", CommitmentDeps: []string{p.AdvisoryID}}, json.RawMessage(`{"milestone":"`+text+`"}`), json.RawMessage(`{"status":"checkpointed"}`))
	if err != nil {
		t.Fatal(err)
	}
	sg, err := sig.SignRecord(w.key, call.ID)
	if err != nil {
		t.Fatal(err)
	}
	return p, wire(call, []record.Signature{sg})
}

func excludedReason(s BundleSelection, id string) string {
	for _, e := range s.Excluded {
		if e.ID == id {
			return e.Reason
		}
	}
	return ""
}

func TestBundleSelectionNeverAutoSelectsRootsAndCarriesControls(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	p, c := checkpointAndCall(t, w, "selection checkpoint 6d1f")
	w.append(p)
	w.append(c)
	gone := w.task(7, "erased before export")
	w.append(gone)
	erase := w.control(70001, record.KindErasure, gone.AdvisoryID)
	w.append(erase)

	sel, err := w.s.SelectBundle(ctx, []string{c.AdvisoryID})
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Data) != 0 || excludedReason(sel, c.AdvisoryID) != ExcludedLineageIncomplete {
		t.Fatalf("call exported without its selected root %+v", sel.Excluded)
	}
	sel, err = w.s.SelectBundle(ctx, []string{c.AdvisoryID, p.AdvisoryID, gone.AdvisoryID, erase.AdvisoryID, strings.Repeat("e", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Data) != 2 || len(sel.Keyring) != 1 || len(sel.Controls) != 1 || sel.Controls[0].AdvisoryID != erase.AdvisoryID {
		t.Fatalf("selection %d data %d keyring %d controls", len(sel.Data), len(sel.Keyring), len(sel.Controls))
	}
	for id, want := range map[string]string{gone.AdvisoryID: ExcludedUnavailable, erase.AdvisoryID: ExcludedNotData, strings.Repeat("e", 64): ExcludedNotPresent} {
		if got := excludedReason(sel, id); got != want {
			t.Fatalf("%s excluded as %q, want %q", id[:8], got, want)
		}
	}
}

func TestBundleImportOtherDeviceThenExactRootErasure(t *testing.T) {
	ctx := context.Background()
	sender := newWorld(t)
	receiver := joinDevice(t, sender)
	p, c := checkpointAndCall(t, sender, "restored checkpoint 41ab77")
	sender.append(p)
	sender.append(c)
	sel, err := sender.s.SelectBundle(ctx, []string{p.AdvisoryID, c.AdvisoryID})
	if err != nil || len(sel.Data) != 2 {
		t.Fatal(sel.Excluded, err)
	}

	// A profile whose own device key is not enrolled is refused whole.
	if _, err = receiver.s.ImportBundle(ctx, BundleImport{LocalKeyID: strings.Repeat("ab", 16), Keyring: sel.Keyring, Controls: sel.Controls, Data: sel.Data}); Code(err) != "device_not_enrolled" {
		t.Fatal("unenrolled receiver imported", err)
	}
	// Data order does not matter: the call arrives before its root.
	in := BundleImport{LocalKeyID: receiver.KeyID(), Keyring: sel.Keyring, Controls: sel.Controls, Data: []SignedRecord{sel.Data[1], sel.Data[0]}}
	report, err := receiver.s.ImportBundle(ctx, in)
	if err != nil || report.Data != 2 || len(report.Excluded) != 0 || report.Fenced {
		t.Fatal(report, err)
	}
	snap, err := receiver.s.Snapshot(ctx, ReadRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{p.AdvisoryID, c.AdvisoryID} {
		if e := find(snap, id); e.State != "live" || len(e.BodyJCS) == 0 {
			t.Fatalf("restored %s state %q", id[:8], e.State)
		}
	}
	// The local route still refuses another device's record outside an import.
	other := sender.task(8, "not via a bundle")
	sender.append(other)
	if _, err = receiver.s.Append(ctx, other); Code(err) != "unauthorized_record" {
		t.Fatal("foreign record admitted on the local route", err)
	}
	// A restore that carries only the call cannot use the comparator.
	if r, err := receiver.s.ImportBundle(ctx, BundleImport{LocalKeyID: receiver.KeyID(), Keyring: sel.Keyring, Data: []SignedRecord{c}}); err != nil || r.Data != 0 || r.Excluded[0].Reason != ExcludedLineageIncomplete {
		t.Fatal("call without its carried root", r, err)
	}

	receipt, err := receiver.s.EraseExact(ctx, EraseRequest{IDs: []string{p.AdvisoryID}}, receiver)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := receiver.s.Scrub(ctx, receipt.Control); err != nil || res.State != "complete" {
		t.Fatal(res, err)
	}
	var n int
	receiver.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_body WHERE id IN(?,?)", p.AdvisoryID, c.AdvisoryID).Scan(&n)
	if n != 0 {
		t.Fatal("restored root or call body survived exact root erasure")
	}
	// Restoring the same older bundle again cannot resurrect either body.
	if _, err = receiver.s.ImportBundle(ctx, in); err != nil {
		t.Fatal(err)
	}
	receiver.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_body WHERE id IN(?,?)", p.AdvisoryID, c.AdvisoryID).Scan(&n)
	if n != 0 {
		t.Fatal("rollback restore resurrected erased data")
	}
}

func TestBundleRestoreFenceHoldsOtherDeviceDataUntilReconciled(t *testing.T) {
	ctx := context.Background()
	sender := newWorld(t)
	receiver := joinDevice(t, sender)
	task := sender.task(9, "fenced restore 0c55")
	sender.append(task)
	sel, err := sender.s.SelectBundle(ctx, []string{task.AdvisoryID})
	if err != nil || len(sel.Data) != 1 {
		t.Fatal(sel, err)
	}
	if err = os.WriteFile(filepath.Join(receiver.o.Dir, SyncProfileName), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := receiver.s.ImportBundle(ctx, BundleImport{LocalKeyID: receiver.KeyID(), Keyring: sel.Keyring, Data: sel.Data})
	if err != nil || !report.Fenced {
		t.Fatal(report, err)
	}
	reopen := func() {
		receiver.s.Close()
		st, err := Open(ctx, receiver.o)
		if err != nil {
			t.Fatal(err)
		}
		receiver.s = st
		t.Cleanup(func() { st.Close() })
	}
	reopen()
	snap, err := receiver.s.Snapshot(ctx, ReadRequest{IDs: []string{task.AdvisoryID}})
	if err != nil || find(snap, task.AdvisoryID).State != "privacy-hold" || len(find(snap, task.AdvisoryID).BodyJCS) != 0 {
		t.Fatal("restored data served before control reconciliation", find(snap, task.AdvisoryID).State, err)
	}
	if err = receiver.s.CompleteRestoreReconciliation(ctx); err != nil {
		t.Fatal(err)
	}
	snap, err = receiver.s.Snapshot(ctx, ReadRequest{IDs: []string{task.AdvisoryID}})
	if err != nil || find(snap, task.AdvisoryID).State != "live" {
		t.Fatal("reconciled restore still held", err)
	}
}
