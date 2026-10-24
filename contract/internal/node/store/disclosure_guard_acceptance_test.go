package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"testing"
)

// Seed retained, metadata-only historical exposure rows with actual owner/root/
// attempt identity. Overflow reconstruction then goes through public Store APIs.
func seedDisclosureExposureHistory(t *testing.T, k *kernelWorld, r CommittedReplyHandle, total int) {
	t.Helper()
	ctx := context.Background()
	var root, attempt, call string
	var fence int64
	k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=?", r.op).Scan(&root)
	k.s.conn.QueryRowContext(ctx, "SELECT id FROM render_attempt WHERE op=? LIMIT 1", r.op).Scan(&attempt)
	k.s.conn.QueryRowContext(ctx, "SELECT call_ref FROM operation WHERE op=?", r.op).Scan(&call)
	k.s.conn.QueryRowContext(ctx, "SELECT next_seq-1 FROM meta").Scan(&fence)
	err := k.s.write(ctx, func() error {
		var current int
		k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM exposure").Scan(&current)
		for i := current; i < total; i++ {
			id := fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012x", i)
			if _, err := k.s.conn.ExecContext(ctx, "INSERT INTO exposure VALUES(?,?,?,?,?,?,?,?,?,'local-admission-fence/1')", id, k.o.PinnedGenesisID, testMachine, k.h.credential, k.sc.id, root, call, attempt, fence); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestDisclosureNewExposureCapacityRefusesWithoutOwnerFreeze(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	r := k.execute("capacity-root", "local.create_task", map[string]any{"goal": "capacity root"})
	seedDisclosureExposureHistory(t, k, r, 8192)
	before := disclosureTransactionState(t, k)
	out, err := k.e.Release(ctx, k.h, r)
	if Code(err) != "exposure_limit" || out.Text() != "" {
		t.Fatal("new uncommitted proposal claimed destructive uncertainty", err)
	}
	requireSameDisclosureState(t, k, before)
	var n int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_hold").Scan(&n)
	if n != 0 {
		t.Fatal("new proposal froze owner")
	}
	if _, err = k.s.Snapshot(ctx, ReadRequest{}); err != nil {
		t.Fatal("previous committed state no longer readable", err)
	}
}
func TestDisclosureProjectionGuardFaultSettlementAndRecovery(t *testing.T) {
	for _, phase := range []string{"insert", "generation", "jobs", "render", "commit"} {
		t.Run(phase, func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			r := k.execute("guard-root", "local.create_task", map[string]any{"goal": "guard root"})
			k.release(r)
			seedDisclosureExposureHistory(t, k, r, 8193)
			before := disclosureTransactionState(t, k)
			event, table := "INSERT", "projection_hold"
			switch phase {
			case "generation":
				event, table = "UPDATE", "meta"
			case "jobs":
				event, table = "DELETE", "projection_job"
			case "render":
				event, table = "DELETE", "render_body"
			}
			installDisclosureFault(t, k, event, table, phase == "commit")
			_, err := k.s.Snapshot(ctx, ReadRequest{})
			if err == nil {
				t.Fatal("failed guard returned source")
			}
			if h, ok := err.(*Error); ok && h.OwnerBlocked {
				t.Fatal("failed FULL guard claimed durable owner block", err)
			}
			requireSameDisclosureState(t, k, before)
			var n int
			k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_hold").Scan(&n)
			if n != 0 {
				t.Fatal("failed guard partly committed")
			}
			if _, err = k.s.Snapshot(ctx, ReadRequest{}); Code(err) != "unavailable" {
				t.Fatal("failed settlement handle not poisoned", err)
			}
			if _, err = k.s.conn.ExecContext(ctx, "DROP TRIGGER phase_fault"); err != nil {
				t.Fatal(err)
			}
			k.s.Close()
			st, err := Open(ctx, k.o)
			if err != nil {
				t.Fatal("normal recovery failed to reconstruct guard", err)
			}
			k.s = st
			if _, err = k.s.Snapshot(ctx, ReadRequest{}); err == nil {
				t.Fatal("normal recovery forgot retained over-bound truth")
			}
			// Current, bounded actual key authority is independent of unavailable
			// ordinary projections. Enroll then revoke, preserving the durable guard.
			next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x49}, 32))
			add := k.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(next.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: k.o.PinnedGenesisID, Parents: []string{k.genesis.AdvisoryID}}, k.key, k.key, next)
			if _, err = k.s.Append(ctx, add); err != nil {
				t.Fatal("guard disabled enrollment", err)
			}
			revoke := k.op(record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: sig.KeyRefOf(next.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: k.o.PinnedGenesisID, Parents: []string{add.AdvisoryID}, Reason: "compromised"}, k.key, k.key)
			if _, err = k.s.Append(ctx, revoke); err != nil {
				t.Fatal("guard disabled revocation", err)
			}
			if err = k.s.write(ctx, func() error {
				d, err := k.s.loadAuthority(ctx)
				if err != nil {
					return err
				}
				key := d.kr.State().KeyFor(sig.KeyID(next.Public().(ed25519.PublicKey)), record.RoleDevice, "")
				if key == nil || key.Status != sig.KeyRevoked {
					t.Fatal("revocation not actually folded", key)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDisclosureSharedAdmissionBoundsSessionViewsBeforeAnyCandidateSQL(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	for i := 0; i < 128; i++ {
		native := fmt.Sprintf("cccccccc-cccc-4ccc-8ccc-%012x", i)
		sk, err := record.SessionKey("claude-code", "local", record.NativeGlobal, native, "")
		if err != nil {
			t.Fatal(err)
		}
		page := k.signed(record.Header{Type: record.KindSession, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.SessionLID(sk, testMachine, 0)}, &record.SessionBody{NativeID: native, NativeIDKind: record.NativeGlobal, MachineOS: "darwin", Chunks: []string{}, SettledThrough: 0})
		k.append(page)
	}
	before := disclosureTransactionState(t, k)
	native := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	sk, err := record.SessionKey("claude-code", "local", record.NativeGlobal, native, "")
	if err != nil {
		t.Fatal(err)
	}
	extra := k.signed(record.Header{Type: record.KindSession, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.SessionLID(sk, testMachine, 0)}, &record.SessionBody{NativeID: native, NativeIDKind: record.NativeGlobal, MachineOS: "darwin", Chunks: []string{}, SettledThrough: 0})
	if _, err = k.s.Append(ctx, extra); Code(err) != "lineage_evaluation_required" {
		t.Fatal("129th session admitted despite complete-view cap", err)
	}
	requireSameDisclosureState(t, k, before)
}

func TestDisclosureProjectionGuardPreservesOriginalCaptureReceiptWithoutBodies(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	producer := producerFor(k.world, "original captured receipt source")
	original := producer.commit()
	r := k.execute("receipt-guard-root", "local.create_task", map[string]any{"goal": "receipt guard root"})
	seedDisclosureExposureHistory(t, k, r, 8193)
	if _, err := k.s.Snapshot(ctx, ReadRequest{}); Code(err) != "lineage_evaluation_required" {
		t.Fatal("guard not established", err)
	}
	check := func() {
		t.Helper()
		replayed, err := k.s.Capture(ctx, producer.q, func(*CaptureTxn) (CommitPlan, error) {
			t.Fatal("projection guard replay resealed")
			return CommitPlan{}, nil
		})
		if err != nil || replayed.TransitionID != original.TransitionID || len(replayed.ActualRecordRefs) != len(original.ActualRecordRefs) {
			t.Fatal("guard forgot immutable receipt", replayed, err)
		}
		for i, ref := range replayed.ActualRecordRefs {
			if ref != original.ActualRecordRefs[i] || replayed.CurrentAvailability[ref.ID] != "owner_blocked" {
				t.Fatal("guard exposed or rewrote receipt", replayed)
			}
		}
		if _, err = k.s.Snapshot(ctx, ReadRequest{}); Code(err) != "lineage_evaluation_required" {
			t.Fatal("projection uncertainty mislabeled as erasure budget", err)
		}
	}
	check()
	k.s.Close()
	st, err := Open(ctx, k.o)
	if err != nil {
		t.Fatal(err)
	}
	k.s = st
	check()
}

// Retain strong, private in-RAM snapshots of producer/effect state as well as
// disclosure state. No candidate bytes or hashes become production metadata.
func disclosureGuardState(t *testing.T, k *kernelWorld) map[string]string {
	t.Helper()
	out := disclosureTransactionState(t, k)
	for _, table := range []string{"capture_progress", "capture_source", "capture_page", "capture_transition", "capture_transition_record", "capture_transition_source", "capture_transition_page", "erasure_effect", "tomb", "privacy_barrier", "projection_hold"} {
		rows, err := k.s.conn.QueryContext(context.Background(), "SELECT * FROM "+table+" ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		for rows.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err = rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(h, "%#v\n", values)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[table+"/contents"] = fmt.Sprintf("%x", h.Sum(nil))
	}
	return out
}
func requireSameDisclosureGuardState(t *testing.T, k *kernelWorld, before map[string]string) {
	t.Helper()
	for key, v := range disclosureGuardState(t, k) {
		if before[key] != v {
			t.Fatal("refusal changed prior private state", key)
		}
	}
}

func TestDisclosureNewUnreleasedExposureWorkLimitCannotFreezeCompleteOldState(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	var inputs []SignedRecord
	for i := 0; i < 1000; i++ {
		inputs = append(inputs, k.task(20000+i, "pre-fence bounded source"))
	}
	k.seedPending(inputs)
	command := commandFor(t, "local.lookup_record", map[string]any{"record_id": inputs[0].AdvisoryID})
	r, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued("work-bound-replay")}, command, ByteBudget{MaxBytes: 4096})
	if err != nil {
		t.Fatal("initial authorized lookup", err)
	}
	k.release(r)
	var records int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record").Scan(&records)
	durable := 1048576 / records
	if durable >= 8192 || durable*records > 1048576 || (durable+1)*records <= 1048576 {
		t.Fatal("invalid exact work-bound fixture", durable, records)
	}
	seedDisclosureExposureHistory(t, k, r, durable)
	if snap, err := k.s.Snapshot(ctx, ReadRequest{}); err != nil || len(snap.Entries) != records {
		t.Fatal("old durable state is not completely readable", len(snap.Entries), records, err)
	}
	before := disclosureGuardState(t, k)
	check := func(label string, err error, returned bool) {
		t.Helper()
		blocked := false
		if fixed, ok := err.(*Error); ok {
			blocked = fixed.OwnerBlocked
		}
		if Code(err) != "exposure_limit" || blocked || returned {
			t.Fatalf("%s new proposal froze old state: oldWork=%d proposalWork=%d code=%s blocked=%v", label, records*durable, records*(durable+1), Code(err), blocked)
		}
		requireSameDisclosureGuardState(t, k, before)
		if snap, e := k.s.Snapshot(ctx, ReadRequest{}); e != nil || len(snap.Entries) != records {
			t.Fatal("old Snapshot lost", label, e)
		}
		requireSameDisclosureGuardState(t, k, before)
	}
	// Replay adds no signed Call or first-admission ordinal. Direct Release
	// takes the independent delivery path through the same proposal boundary.
	out, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued("work-bound-replay")}, command, ByteBudget{MaxBytes: 4096})
	check("Execute replay", err, out.engine != nil)
	delivery, err := k.e.Release(ctx, k.h, r)
	check("Release", err, delivery.Text() != "")
	other, err := Open(ctx, k.o)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if snap, e := other.Snapshot(ctx, ReadRequest{}); e != nil || len(snap.Entries) != records {
		t.Fatal("second handle lost prior state", e)
	}
	requireSameDisclosureGuardState(t, k, before)
}

func TestDisclosureNewProposalOverflowPreservesGenuinePriorLineageGuard(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	var inputs []SignedRecord
	for i := 0; i < 1000; i++ {
		inputs = append(inputs, k.task(24000+i, "prior readable source"))
	}
	k.seedPending(inputs)
	reply := k.execute("prior-work-root", "local.lookup_record", map[string]any{"record_id": inputs[0].AdvisoryID})
	k.release(reply)
	var n int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record").Scan(&n)
	durable := 1048576 / n
	seedDisclosureExposureHistory(t, k, reply, durable)
	before := disclosureGuardState(t, k)
	candidate := k.task(26000, "new trusted admission exceeds prior work")
	invalid := candidate
	invalid.Sigs = append([]record.Signature(nil), candidate.Sigs...)
	invalid.Sigs[0].Value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := k.s.Append(ctx, invalid); err == nil {
		t.Fatal("invalid crypto became trusted proof")
	}
	requireSameDisclosureGuardState(t, k, before)
	_, err := k.s.Append(ctx, candidate)
	fixed, ok := err.(*Error)
	if !ok || fixed.Code != "lineage_evaluation_required" || !fixed.OwnerBlocked {
		t.Fatal("genuine retained lineage overflow did not hold", err)
	}
	var holds, records int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_hold").Scan(&holds)
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record").Scan(&records)
	if holds != 1 || records != n {
		t.Fatal("guard lost or candidate persisted", holds, records, n)
	}
	if _, err = k.s.Snapshot(ctx, ReadRequest{}); Code(err) != "lineage_evaluation_required" {
		t.Fatal("old incomplete state read through guard", err)
	}
}

func TestDisclosureNewProposalOverflowPreservesVerifiedPriorErasureLoss(t *testing.T) {
	// This is the internal shared verifier/render transaction, not a native
	// completeness adapter. Every proof is a real signed body, admitted only in
	// RAM; only accepted-cause metadata may survive its refused delivery.
	for _, extra := range []int{200, 1001} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			f, _, plan, cause := lateProducerPlan(t, extra, false)
			k := newKernelForWorld(f.w)
			ctx := context.Background()
			safe := k.task(29000, "independent prior readable output")
			k.append(safe)
			reply := k.execute("safe-work-root", "local.lookup_record", map[string]any{"record_id": safe.AdvisoryID})
			k.release(reply)
			var n int
			k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record").Scan(&n)
			// Each old exposure scans all candidate records and adds the one
			// post-fence proof edge; the new proposal scans without that edge.
			durable := 1048576 / (n + 2)
			if durable >= 8192 || durable*(n+2) > 1048576 || durable*(n+2)+(n+1) <= 1048576 {
				t.Fatal("invalid candidate work boundary", n, durable)
			}
			seedDisclosureExposureHistory(t, k, reply, durable)
			before := disclosureGuardState(t, k)
			pool, err := newDisclosureEntropy()
			if err != nil {
				t.Fatal(err)
			}
			defer pool.clear()
			err = k.s.writeMode(ctx, true, func() error {
				d, e := k.s.load(ctx)
				if e != nil {
					return e
				}
				generation := d.generation
				c, e := k.e.client(ctx, k.h)
				if e != nil {
					return e
				}
				sc, e := k.e.scope(ctx, k.h, k.sc)
				if e != nil {
					return e
				}
				o, e := k.s.loadOutcome(ctx, k.h.credential, reply.op)
				if e != nil {
					return e
				}
				parsed, signatures, e := parse(plan.NewRecords[0])
				if e != nil {
					return e
				}
				if _, e = k.s.prepareNew(d, parsed, signatures); e != nil {
					t.Fatal("prior-only candidate must reconstruct completely", e)
				}
				render, e := k.e.prepareRender(ctx, d, c, sc, o, pool, ByteBudget{MaxBytes: 4096}, generation, false)
				if render != nil || e == nil {
					t.Fatal("new exposure was not refused")
				}
				// The actual caller also routes refusals through this helper. A Store-only
				// known-commit refusal must not settle the same metadata twice.
				return k.s.refuseVerified(ctx, d, e)
			})
			want := "privacy_hold_required"
			if extra > 996 {
				want = "bulk_confirmation_required"
			}
			fixed, ok := err.(*Error)
			if !ok || fixed.Code != want || !fixed.OwnerBlocked {
				t.Fatal("discarded proposal hid accepted erasure knowledge", Code(err), fixed)
			}
			after := disclosureGuardState(t, k)
			for _, table := range []string{"record", "record_body", "operation", "outcome_member", "exposure", "exposure_affect", "capture_progress", "capture_source", "capture_page", "capture_transition", "capture_transition_record", "capture_transition_source", "capture_transition_page", "erasure_effect", "tomb"} {
				if before[table+"/contents"] != after[table+"/contents"] {
					t.Fatal("candidate or partial effects persisted", table)
				}
			}
			if before["next_seq"] != after["next_seq"] {
				t.Fatal("candidate ordinal persisted")
			}
			var control, reason string
			var generation int64
			if e := k.s.conn.QueryRowContext(ctx, "SELECT control,reason,generation FROM privacy_barrier").Scan(&control, &reason, &generation); e != nil || control != cause.AdvisoryID {
				t.Fatal("missing exact accepted cause", e)
			}
			var previous int64
			fmt.Sscan(before["generation"], &previous)
			if generation != previous+1 {
				t.Fatal("metadata refusal settled twice", generation, previous)
			}
			var holds int
			k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_hold").Scan(&holds)
			if holds != 0 {
				t.Fatal("complete prior proof mislabeled uncertain")
			}
			if _, e := k.s.Snapshot(ctx, ReadRequest{}); e == nil {
				t.Fatal("accepted erasure loss remained readable")
			}
		})
	}
}
