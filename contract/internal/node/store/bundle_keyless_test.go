package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/replay"
	"github.com/Telara-Labs/hilo/contract/sig"
)

// kernelOnJoined runs a disclosure engine over a joined device's store with
// its own registered client credential, the way the receiver's daemon would.
func kernelOnJoined(t *testing.T, j *joinedDevice) *kernelWorld {
	t.Helper()
	ctx := context.Background()
	k := &kernelWorld{world: &world{t: t, s: j.s, o: j.o, key: j.key}}
	material, err := PreloadDisclosureAuthority(bytes.Repeat([]byte{10}, 32), j.key)
	if err != nil {
		t.Fatal(err)
	}
	if k.e, err = NewDisclosureEngine(ctx, j.s, material, DisclosureConfig{OwnerGenesis: j.o.PinnedGenesisID, MachineID: joinedMachine, MaxReplyBytes: 16384}); err != nil {
		t.Fatal(err)
	}
	if k.a, err = k.e.Administration(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := k.a.Register(ctx, RegisterClient{AdminOpID: "register-receiver-client", ClientName: "Receiver fixture", ReadGrant: Grant{Repos: AllLocalRepos(), Channels: []Channel{S}}, TaskWrites: TaskWriteGrant{Actions: []TaskMutation{Create, Checkpoint}, Repos: AllLocalRepos(), AllowUnscoped: true}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := r.Secret.Take()
	if err != nil {
		t.Fatal(err)
	}
	k.proof = CredentialProof{r.CredentialID, token}
	if k.h, err = k.e.Authenticate(ctx, k.proof); err != nil {
		t.Fatal(err)
	}
	if k.sc, err = k.e.Resolve(ctx, k.h, IdentityInput{ConversationHandle: "receiver-conversation"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.e.Close(); clear(token) })
	return k
}

// bodyCount counts stored bodies of ids.
func bodyCount(t *testing.T, s *Store, ids ...string) int {
	t.Helper()
	n := 0
	for _, id := range ids {
		n += countRows(t, s, "SELECT count(*) FROM record_body WHERE id=?", id)
	}
	return n
}

// TestBundleCheckpointCallKeylessRetryAfterRestoreAndErasure drives an
// explicit no-event checkpoint P and its call C through the operation engine,
// transfers them by bundle with omissions, late roots and a restart, erases
// only P.id on the receiver, carries that control back and requires every
// retry of the settled operation, matching or changed, to get one uniform
// result that compares nothing, before and after a rollback restore of the
// earlier bundle and across restarts. The node keeps no managed bundle or
// staging copy, so the managed scrub covers the database files only; exported
// files are unmanaged copies the erase receipt names.
func TestBundleCheckpointCallKeylessRetryAfterRestoreAndErasure(t *testing.T) {
	ctx := context.Background()
	k := newKernel(t)
	recv := joinDevice(t, k.world)
	task := k.taskID(k.execute("x4-task", "local.create_task", map[string]any{"goal": "x4 task goal"}))
	const text = "x4_checkpoint_canary_5d2a"
	matching := commandFor(t, "local.checkpoint_task", map[string]any{"task_id": task, "milestone": text})
	changed := commandFor(t, "local.checkpoint_task", map[string]any{"task_id": task, "milestone": "a different candidate milestone"})
	token := k.issued("x4-checkpoint")
	retry := func(c TypedCommand) (CommittedReplyHandle, error) {
		return k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: token}, c, ByteBudget{MaxBytes: 4096})
	}
	first, err := retry(matching)
	if err != nil {
		t.Fatal(err)
	}
	if got := k.release(first); !strings.Contains(got, rendered(text)) {
		t.Fatal("checkpoint not rendered", got)
	}
	var callID, argsHash, p string
	if err = k.s.conn.QueryRowContext(ctx, "SELECT call_id,args_hash FROM operation WHERE op=?", first.op).Scan(&callID, &argsHash); err != nil || argsHash == "" {
		t.Fatal("operation without comparator", err)
	}
	if err = k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=? AND role='mutation'", first.op).Scan(&p); err != nil {
		t.Fatal(err)
	}
	var callBody []byte
	if err = k.s.conn.QueryRowContext(ctx, "SELECT body FROM record_body WHERE id=?", callID).Scan(&callBody); err != nil {
		t.Fatal(err)
	}
	var call record.CallBody
	if json.Unmarshal(callBody, &call) != nil || call.ArgsHash != argsHash || !containsID(call.CommitmentDeps, p) {
		t.Fatal("call C does not commit to checkpoint P")
	}
	forbidden := append([]string{text, rendered(text)}, secretsOf(t, callBody)...)
	if len(forbidden) < 4 {
		t.Fatal("call fixture holds too few secrets", len(forbidden))
	}
	var pBody []byte
	if err = k.s.conn.QueryRowContext(ctx, "SELECT body FROM record_body WHERE id=?", p).Scan(&pBody); err != nil {
		t.Fatal(err)
	}
	forbidden = append(forbidden, secretsOf(t, pBody)...)

	// With the original live key a matching retry replays and a changed one
	// conflicts, without a second mutation.
	operations := countRows(t, k.s, "SELECT count(*) FROM operation")
	again, err := retry(matching)
	if err != nil || !strings.Contains(k.release(again), rendered(text)) {
		t.Fatal("live retry did not replay", err)
	}
	if _, err = retry(changed); Code(err) != "op_conflict" {
		t.Fatal("changed live retry", err)
	}
	if countRows(t, k.s, "SELECT count(*) FROM operation") != operations {
		t.Fatal("live retry mutated again")
	}

	// Every data record, in admission order.
	var data []string
	for _, e := range k.snapshot().Entries {
		r, err := record.Parse(e.HeaderJCS, e.BodyJCS, e.ID)
		if err == nil && bundleDataKind(r.Header.Type) && len(e.BodyJCS) > 0 {
			data = append(data, e.ID)
		}
	}
	// An omitted root never travels: the call alone, and the call with P but
	// without P's own task root, are excluded as lineage_incomplete.
	sel, err := k.s.SelectBundle(ctx, []string{callID})
	if err != nil || len(sel.Data) != 0 || excludedReason(sel, callID) != ExcludedLineageIncomplete {
		t.Fatal("call exported without its root", sel.Excluded, err)
	}
	if sel, err = k.s.SelectBundle(ctx, []string{callID, p}); err != nil || len(sel.Data) != 0 || excludedReason(sel, callID) != ExcludedLineageIncomplete || excludedReason(sel, p) != ExcludedLineageIncomplete {
		t.Fatal("P and C exported without the task root", sel.Excluded, err)
	}
	full, err := k.s.SelectBundle(ctx, data)
	if err != nil || len(full.Data) != len(data) {
		t.Fatal("complete selection", full.Excluded, err)
	}
	var cOnly []SignedRecord
	var rest []SignedRecord
	for _, r := range full.Data {
		if r.AdvisoryID == callID {
			cOnly = append(cOnly, r)
		} else {
			rest = append(rest, r)
		}
	}
	if len(data) < 3 || len(cOnly) != 1 || !containsID(data, p) {
		t.Fatal("expected task, P and C in the bundle", len(data), len(cOnly))
	}
	in := func(d []SignedRecord) BundleImport {
		return BundleImport{LocalKeyID: recv.KeyID(), Keyring: full.Keyring, Facts: full.Facts, Controls: full.Controls, Data: d}
	}

	// A receiver given only C admits nothing of it; its roots arriving later
	// in a second bundle, after the call in line order, admit both.
	report, err := recv.s.ImportBundle(ctx, in(cOnly))
	if err != nil || report.Data != 0 || len(report.Excluded) != 1 || report.Excluded[0].Reason != ExcludedLineageIncomplete {
		t.Fatal("call without its carried root", report, err)
	}
	if bodyCount(t, recv.s, callID) != 0 {
		t.Fatal("excluded call body stored")
	}
	assertAbsent(t, recv.o.Dir, forbidden...)
	late := append(append([]SignedRecord(nil), cOnly...), rest...)
	if report, err = recv.s.ImportBundle(ctx, in(late)); err != nil || report.Data != len(data) || len(report.Excluded) != 0 {
		t.Fatal("late roots", report, err)
	}
	reopenStore(t, &recv.s, recv.o)
	for _, id := range data {
		if e := find(recv.snapshotOf(t), id); e.State != "live" || len(e.BodyJCS) == 0 {
			t.Fatalf("restored %s is %q after restart", id[:8], e.State)
		}
	}

	// The receiver never settled the origin's operation: the origin's token is
	// unissued there for matching and changed arguments alike, and no
	// operation row or mutation appears.
	rk := kernelOnJoined(t, &recv)
	recordsBefore := countRows(t, recv.s, "SELECT count(*) FROM record")
	var codes []string
	for _, c := range []TypedCommand{matching, changed} {
		_, err := rk.e.Execute(ctx, rk.h, rk.sc, CallIdentity{SuppliedOpID: token}, c, ByteBudget{MaxBytes: 4096})
		codes = append(codes, Code(err))
	}
	if codes[0] != "unissued_operation" || codes[1] != codes[0] {
		t.Fatal("origin token on the receiver", codes)
	}
	if countRows(t, recv.s, "SELECT count(*) FROM operation") != 0 || countRows(t, recv.s, "SELECT count(*) FROM record") != recordsBefore {
		t.Fatal("receiver settled or mutated for a foreign token")
	}
	rk.e.Close()

	// Erase only P.id on the receiver: C goes with it, with every comparator
	// copy, before the receipt reports a complete scrub.
	receipt, err := recv.s.EraseExact(ctx, EraseRequest{IDs: []string{p}}, recv)
	if err != nil || receipt.Pending {
		t.Fatal(receipt, err)
	}
	if res, err := recv.s.Scrub(ctx, receipt.Control); err != nil || res.State != "complete" {
		t.Fatal(res, err)
	}
	if bodyCount(t, recv.s, p, callID) != 0 {
		t.Fatal("receiver kept P or C after exact erasure of P")
	}
	assertAbsent(t, recv.o.Dir, forbidden...)

	// The control reaches the origin: P, C and the operation comparator go.
	carryControls(t, recv.s, k.s, k.o.PinnedGenesisID)
	var control string
	for _, c := range func() []SignedRecord {
		s, _ := recv.s.SelectBundle(ctx, []string{strings.Repeat("0", 64)})
		return s.Controls
	}() {
		control = c.AdvisoryID
	}
	if res, err := k.s.Scrub(ctx, control); err != nil || res.State != "complete" {
		t.Fatal("origin scrub", res, err)
	}
	if bodyCount(t, k.s, p, callID) != 0 || countRows(t, k.s, "SELECT count(*) FROM operation WHERE op=? AND args_hash=''", first.op) != 1 {
		t.Fatal("origin kept P, C or the comparator after the carried erasure")
	}
	assertAbsent(t, k.o.Dir, forbidden...)

	// keyless asserts the uniform result for matching and changed retries,
	// with no new operation, record or body.
	keyless := func(stage string) {
		t.Helper()
		ops, recs := countRows(t, k.s, "SELECT count(*) FROM operation"), countRows(t, k.s, "SELECT count(*) FROM record")
		var results []string
		for _, c := range []TypedCommand{matching, changed} {
			r, err := retry(c)
			if err != nil {
				t.Fatal(stage, "keyless retry refused differently", err)
			}
			results = append(results, k.release(r))
		}
		if results[0] != replay.Unavailable || results[1] != results[0] {
			t.Fatal(stage, "keyless retry is an oracle", results)
		}
		if countRows(t, k.s, "SELECT count(*) FROM operation") != ops || countRows(t, k.s, "SELECT count(*) FROM record") != recs || bodyCount(t, k.s, p, callID) != 0 {
			t.Fatal(stage, "keyless retry mutated or re-keyed")
		}
		if countRows(t, k.s, "SELECT count(*) FROM operation WHERE op=? AND args_hash=''", first.op) != 1 {
			t.Fatal(stage, "comparator regenerated")
		}
		assertAbsent(t, k.o.Dir, forbidden...)
	}
	keyless("after erasure")

	// A rollback restore of the earlier bundle into the origin itself and into
	// the receiver carries C's complete body with its salt and commitments; the
	// tomb refuses both, so retries stay keyless.
	origin := BundleImport{LocalKeyID: k.o.PinnedGenesisID, Keyring: full.Keyring, Facts: full.Facts, Controls: full.Controls, Data: full.Data}
	if _, err = k.s.ImportBundle(ctx, origin); err != nil {
		t.Fatal("rollback restore into the origin", err)
	}
	keyless("after rollback restore")
	if _, err = recv.s.ImportBundle(ctx, in(full.Data)); err != nil {
		t.Fatal(err)
	}
	if bodyCount(t, recv.s, p, callID) != 0 {
		t.Fatal("rollback restore resurrected P or C on the receiver")
	}
	assertAbsent(t, recv.o.Dir, forbidden...)
	reopenKernel(k)
	keyless("after restart")
	// Nothing reappears on the receiver after a restart either.
	reopenStore(t, &recv.s, recv.o)
	assertAbsent(t, recv.o.Dir, forbidden...)

	// A tomb that arrives before its root: a fresh device that first receives
	// only the controls, then the earlier bundle, never stores P or C.
	third := joinThird(t, k.world)
	carryControls(t, recv.s, third.s, third.KeyID())
	if _, err = third.s.ImportBundle(ctx, BundleImport{LocalKeyID: third.KeyID(), Keyring: full.Keyring, Facts: full.Facts, Data: full.Data}); err != nil {
		t.Fatal(err)
	}
	if bodyCount(t, third.s, p, callID) != 0 {
		t.Fatal("tomb received before its root did not reach P and C")
	}
	assertAbsent(t, third.o.Dir, forbidden...)
	reopenStore(t, &third.s, third.o)
	snap := third.snapshotOf(t)
	for _, id := range []string{p, callID} {
		if e := find(snap, id); len(e.BodyJCS) != 0 {
			t.Fatalf("%s served after restart", id[:8])
		}
	}
}

func (j *joinedDevice) snapshotOf(t *testing.T) Snapshot {
	t.Helper()
	snap, err := j.s.Snapshot(context.Background(), ReadRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// joinThird enrolls one more device of the sender's genesis, with its own key
// and machine, by a device_add co-signed by the sender.
func joinThird(t *testing.T, sender *world) joinedDevice {
	t.Helper()
	const machine = "55555555-5555-4555-8555-555555555555"
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	pub := key.Public().(ed25519.PublicKey)
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(pub, record.RoleDevice, machine), Genesis: sender.o.PinnedGenesisID, Parents: []string{sender.genesis.AdvisoryID}}, sender.key.Public().(ed25519.PublicKey), testMachine, sender.at+1, key, sender.key)
	if err != nil {
		t.Fatal(err)
	}
	add := wire(op.Rec, op.Sigs)
	sender.append(add)
	o := testOptions(t)
	o.PinnedGenesisID, o.LocalMachineID = sender.o.PinnedGenesisID, machine
	st, err := Open(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	keyring, err := sender.s.Keyring(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range keyring {
		if _, err = st.Append(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	return joinedDevice{s: st, o: o, key: key, add: add}
}
