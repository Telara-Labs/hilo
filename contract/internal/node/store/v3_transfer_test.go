package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

// This exercises authenticated record transfer/restore with actual SQLite.
// Encryption/age archives and their unopened managed copies remain a separate
// unavailable adapter; no encrypted bundle conformance is inferred here.
func TestV3TransferredNoEventCallRebuildsWireEdgesAndErasesInEitherOrder(t *testing.T) {
	for _, controlFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "data-first", true: "control-first"}[controlFirst], func(t *testing.T) {
			sender := newWorld(t)
			receiver := newWorld(t)
			ctx := context.Background()
			task := "4a333333-3333-4333-8333-333333333333"
			op := record.H("transfer-opaque-operation")
			source := sender.signed(record.Header{Type: record.KindCheckpoint, LID: record.CheckpointLID(sender.o.PinnedGenesisID, task, testMachine, op), Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: op}, &record.CheckpointBody{Milestone: "transferred erasable checkpoint 9c332102"})
			ref, err := record.NewCallRef()
			if err != nil {
				t.Fatal(err)
			}
			call, err := record.BuildCall(record.Header{Type: record.KindCall, LID: record.CallLID(ref), At: 1761150000001, Author: record.Author{MachineID: testMachine, KeyID: sender.o.PinnedGenesisID}, Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: op, Red: record.Redact{Profile: record.ProfileLocal}, Links: record.Links{DerivedFrom: []string{source.AdvisoryID}}}, record.CallBody{CallRef: ref, ScopeID: "sc1:" + testMachine + ":" + strings.Repeat("1", 32), Tool: "telara_task_checkpoint", TaskID: task, Outcome: "ok", CommitmentDeps: []string{source.AdvisoryID}}, json.RawMessage(`{"milestone":"transferred erasable checkpoint 9c332102"}`), json.RawMessage(`{"status":"checkpointed"}`))
			if err != nil {
				t.Fatal(err)
			}
			sg, err := sig.SignRecord(sender.key, call.ID)
			if err != nil {
				t.Fatal(err)
			}
			callWire := wire(call, []record.Signature{sg})
			control := sender.control(99001, record.KindErasure, source.AdvisoryID)
			if controlFirst {
				receiver.append(control)
			}
			receiver.append(callWire)
			if !controlFirst {
				if got := find(receiver.snapshot(), call.ID); got.State != "ancestry-pending" || len(got.BodyJCS) != 0 {
					t.Fatal("unknown ancestry made comparator usable", got.State)
				}
			}
			receiver.append(source)
			// Delete disposable edges, then require exact signed-wire reconstruction on
			// normal recovery. Body provenance cannot be defaulted to an empty set.
			if _, err = receiver.s.conn.ExecContext(ctx, "DELETE FROM dep WHERE id=?", call.ID); err != nil {
				t.Fatal(err)
			}
			receiver.s.Close()
			st, err := Open(ctx, receiver.o)
			if err != nil {
				t.Fatal(err)
			}
			receiver.s = st
			var n int
			st.conn.QueryRowContext(ctx, "SELECT count(*) FROM dep WHERE id=? AND parent=?", call.ID, source.AdvisoryID).Scan(&n)
			if n != 1 {
				t.Fatal("wire dependency lost on restore")
			}
			if !controlFirst {
				receiver.append(control)
			}
			receiver.append(callWire)
			st.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_body WHERE id IN(?,?)", source.AdvisoryID, call.ID).Scan(&n)
			if n != 0 {
				t.Fatal("transferred source/call key survived exact-id erasure")
			}
			if result, err := st.Scrub(ctx, control.AdvisoryID); err != nil || result.State != "complete" {
				t.Fatal("transfer erasure scrub", result, err)
			}
		})
	}
}

func TestV3LegacyMajorRefusesRatherThanRelabelingRetainedVerifier(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	r := w.task(99001, "legacy verifier cannot be called protected")
	w.append(r)
	if _, err := w.s.conn.ExecContext(ctx, "UPDATE meta SET contract_major=2"); err != nil {
		t.Fatal(err)
	}
	w.s.Close()
	st, err := Open(ctx, w.o)
	if Code(err) != "incompatible_database" {
		if st != nil {
			st.Close()
		}
		t.Fatal("legacy data served without reconciliation", err)
	}
}

func TestV3OmittedKnownMutationDependencyIsRefusedOrPurgedWhenLate(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "known", true: "late"}[late], func(t *testing.T) {
			w := newWorld(t)
			ctx := context.Background()
			op := record.H("opaque-omitted-mutation-op")
			task := "4a333333-3333-4333-8333-333333333333"
			source := w.signed(record.Header{Type: record.KindCheckpoint, LID: record.CheckpointLID(w.o.PinnedGenesisID, task, testMachine, op), Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: op}, &record.CheckpointBody{Milestone: "secret requiring signed ancestry"})
			ref, err := record.NewCallRef()
			if err != nil {
				t.Fatal(err)
			}
			call, err := record.BuildCall(record.Header{Type: record.KindCall, LID: record.CallLID(ref), At: 1761150000001, Author: record.Author{MachineID: testMachine, KeyID: w.o.PinnedGenesisID}, Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: op, Red: record.Redact{Profile: record.ProfileLocal}}, record.CallBody{CallRef: ref, ScopeID: "sc1:" + testMachine + ":" + strings.Repeat("1", 32), Tool: "telara_task_checkpoint", TaskID: task, Outcome: "ok", CommitmentDeps: []string{}}, json.RawMessage(`{"milestone":"secret requiring signed ancestry"}`), json.RawMessage(`{"status":"checkpointed"}`))
			if err != nil {
				t.Fatal(err)
			}
			sg, err := sig.SignRecord(w.key, call.ID)
			if err != nil {
				t.Fatal(err)
			}
			input := wire(call, []record.Signature{sg})
			if !late {
				w.append(source)
				if _, err = w.s.Append(ctx, input); err == nil {
					t.Fatal("omitted known mutation admitted")
				}
				return
			}
			w.append(input)
			w.append(source)
			var n int
			if err = w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_body WHERE id=?", call.ID).Scan(&n); err != nil || n != 0 {
				t.Fatal("late omitted dependency preserved comparator", n, err)
			}
			w.s.Close()
			st, err := Open(ctx, w.o)
			if err != nil {
				t.Fatal(err)
			}
			w.s = st
			w.append(input)
			if err = st.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_body WHERE id=?", call.ID).Scan(&n); err != nil || n != 0 {
				t.Fatal("late tomb refilled after recovery", n, err)
			}
		})
	}
}
