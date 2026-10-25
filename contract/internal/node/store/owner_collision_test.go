package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// newOwnerWorld is newWorld for a second, unrelated identity: its own genesis
// key, its own store, the same machine id.
func newOwnerWorld(t *testing.T, seed byte) *world {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	o := testOptions(t)
	o.PinnedGenesisID = sig.KeyID(key.Public().(ed25519.PublicKey))
	s, err := Open(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, s: s, o: o, key: key, at: 1761150000000}
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(key.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: o.PinnedGenesisID}, key.Public().(ed25519.PublicKey), testMachine, w.at, key)
	if err != nil {
		t.Fatal(err)
	}
	w.genesis = wire(op.Rec, op.Sigs)
	w.append(w.genesis)
	t.Cleanup(func() { w.s.Close() })
	return w
}

// Two owners use the SAME task UUID, session key, machine id and event
// anchor. Nothing one owner signs can be admitted into, joined with, selected
// by or erase anything in the other owner's store.
func TestTaskIDCollisionAcrossOwnersCannotJoinOrSelect(t *testing.T) {
	ctx := context.Background()
	a := newWorld(t)
	b := newOwnerWorld(t, 44)
	if a.o.PinnedGenesisID == b.o.PinnedGenesisID {
		t.Fatal("fixture owners collide")
	}
	const aText, bText = "owner_a_task_canary_5c0d", "owner_b_task_canary_e817"
	aTask := a.task(1, aText)
	a.append(aTask)
	bTask := b.task(1, bText)
	b.append(bTask)
	ra, _ := record.Parse(aTask.HeaderJCS, aTask.BodyJCS, aTask.AdvisoryID)
	rb, _ := record.Parse(bTask.HeaderJCS, bTask.BodyJCS, bTask.AdvisoryID)
	if ra.Header.Subj.TaskID != rb.Header.Subj.TaskID || ra.Header.LID == rb.Header.LID {
		t.Fatal("fixture must collide on task UUID only")
	}
	task := ra.Header.Subj.TaskID
	aChunk := a.chunk(a.event("owner a transcript"))
	a.append(aChunk)
	aEvent := a.event("owner a transcript")
	before := a.snapshot()

	// The other owner's records, a graph join onto this owner's record and a
	// same-task completion are refused on admission and leave no bytes.
	bJoin := b.task(2, "owner b joins owner a", aTask.AdvisoryID)
	b.append(bJoin)
	if e := find(b.snapshot(), bJoin.AdvisoryID); e.State != "ancestry-pending" || len(e.BodyJCS) != 0 {
		t.Fatal("owner b joined a record it cannot see", e.State)
	}
	bDone := b.signed(record.Header{Type: record.KindTask, LID: record.TaskLID(b.o.PinnedGenesisID, task), Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: record.H("op", "b-complete"), Links: record.Links{Supersedes: []string{bTask.AdvisoryID}}}, &record.TaskBody{Name: "task", Goal: bText, Status: "completed"})
	b.append(bDone)
	bErase := b.control(1, record.KindErasure, aTask.AdvisoryID, aChunk.AdvisoryID)
	b.append(bErase)
	for name, in := range map[string]SignedRecord{"task": bTask, "join": bJoin, "completion": bDone, "control": bErase} {
		if _, err := a.s.Append(ctx, in); Code(err) != "unauthorized_record" {
			t.Fatal("foreign owner record admitted", name, err)
		}
		if _, err := a.s.ApplyControl(ctx, in); err == nil {
			t.Fatal("foreign owner control path admitted", name)
		}
	}
	// A bundle from the other identity is refused whole.
	sel, err := b.s.SelectBundle(ctx, []string{bTask.AdvisoryID})
	if err != nil || len(sel.Data) != 1 {
		t.Fatal(sel, err)
	}
	if _, err = a.s.ImportBundle(ctx, BundleImport{LocalKeyID: a.o.PinnedGenesisID, Keyring: sel.Keyring, Controls: append(sel.Controls, bErase), Data: sel.Data}); err == nil {
		t.Fatal("foreign identity bundle imported")
	}
	after := a.snapshot()
	if after.Generation != before.Generation || len(after.Entries) != len(before.Entries) {
		t.Fatal("refused foreign input changed this owner's store")
	}
	assertAbsent(t, a.o.Dir, bText, "owner b joins owner a")

	// This owner's own graph join onto the other owner's record never resolves.
	aJoin := a.task(4, "owner a joins owner b", bTask.AdvisoryID)
	a.append(aJoin)
	if e := find(a.snapshot(), aJoin.AdvisoryID); e.State != "ancestry-pending" || len(e.BodyJCS) != 0 {
		t.Fatal("join across owners served", e.State)
	}

	// This owner's selectors are owner scoped: an event selector naming the
	// other owner, with this owner's session and event id, erases nothing here.
	h := record.Header{Type: record.KindErasure, Prov: record.ProvUser}
	h.LID, _ = record.ControlLID(record.KindErasure, a.o.PinnedGenesisID, record.H("nonce", "foreign-owner-selector")[:32])
	foreignSelector := a.signed(h, &record.ErasureBody{Reason: "user_request", Selectors: record.Selectors{Events: []record.EventSelector{{Owner: b.o.PinnedGenesisID, SessionKey: a.sessionKey(), EventID: aEvent.ID}}}})
	if _, err = a.s.ApplyControl(ctx, foreignSelector); Code(err) != "unauthorized_record" {
		t.Fatal("selector naming another owner admitted", err)
	}
	if n := countRows(t, a.s, "SELECT count(*) FROM event_ban WHERE owner=?", a.o.PinnedGenesisID); n != 0 {
		t.Fatal("other owner's selector banned this owner's event", n)
	}
	if supp, err := a.s.Suppressed(ctx, SourceOccurrence{Owner: a.o.PinnedGenesisID, SessionKey: a.sessionKey(), EventIDs: []string{aEvent.ID}}); err != nil || supp.Suppressed {
		t.Fatal("other owner's selector suppressed this owner's capture", supp, err)
	}
	if _, err = a.s.Suppressed(ctx, SourceOccurrence{Owner: b.o.PinnedGenesisID, SessionKey: a.sessionKey(), EventIDs: []string{aEvent.ID}}); Code(err) != "invalid_request" {
		t.Fatal("suppression answered for another owner", err)
	}
	// An exact erase of the other owner's record id finds nothing of that
	// owner here; its closure reaches only this owner's own record that
	// declared the id as an ancestor.
	receipt, err := a.s.EraseExact(ctx, EraseRequest{IDs: []string{bTask.AdvisoryID}}, worldSigner{a.key})
	if err != nil || len(receipt.Requested) != 1 || receipt.Requested[0].Status != "not_present" || len(receipt.Closure) != 1 || receipt.Closure[0].ID != aJoin.AdvisoryID {
		t.Fatal("exact erase crossed owners", receipt, err)
	}

	snap := a.snapshot()
	for _, id := range []string{aTask.AdvisoryID, aChunk.AdvisoryID} {
		if e := find(snap, id); e.State != "live" || len(e.BodyJCS) == 0 {
			t.Fatal("this owner's record changed by the other owner", e.State)
		}
	}
	if e := find(snap, aTask.AdvisoryID); e.TaskStatus != "active" {
		t.Fatal("same task UUID completed across owners", e.TaskStatus)
	}
	var owner, status string
	if err = a.s.conn.QueryRowContext(ctx, "SELECT owner,status FROM task_state WHERE task=?", task).Scan(&owner, &status); err != nil || owner != a.o.PinnedGenesisID || status != "active" {
		t.Fatal("task state keyed across owners", owner, status, err)
	}
	if n := countRows(t, a.s, "SELECT count(*) FROM task_state WHERE task=?", task); n != 1 {
		t.Fatal("second owner's task state row", n)
	}
	// And the other owner's store is equally untouched by this owner's controls.
	if e := find(b.snapshot(), bDone.AdvisoryID); e.TaskStatus != "completed" {
		t.Fatal("owner b lost its own completion", e.TaskStatus)
	}
}
