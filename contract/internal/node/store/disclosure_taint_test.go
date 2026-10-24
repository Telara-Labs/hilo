package store

import (
	"context"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"testing"
)

func TestKernelBindingCorrectionRetainsActualObservedWitnesses(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	makeSession := func(native, tag string) (string, string, string) {
		sk, err := record.SessionKey("claude-code", "local", record.NativeGlobal, native, "")
		if err != nil {
			t.Fatal(err)
		}
		eid, err := record.EventID(sk, "assistant_final", record.Anchor{NativeItemID: "boundary"})
		if err != nil {
			t.Fatal(err)
		}
		ev, err := record.ReviseEvent(record.Event{ID: eid, Seq: 0, Kind: "assistant_final", Prov: "transcript", Text: &record.Text{Body: "observed boundary"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		trust := record.Trust{}
		if tag != "" {
			trust.Taint = []string{"third-party-mcp", tag}
		}
		chunk := k.signed(record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.ChunkLID(sk, testMachine, eid), Trust: trust}, &record.ChunkBody{Events: []record.Event{ev}})
		k.append(chunk)
		page := k.signed(record.Header{Type: record.KindSession, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.SessionLID(sk, testMachine, 0)}, &record.SessionBody{NativeID: native, NativeIDKind: record.NativeGlobal, MachineOS: "darwin", Chunks: []string{chunk.AdvisoryID}, SettledThrough: 0})
		k.append(page)
		return sk, chunk.AdvisoryID, eid
	}
	a, sourceA, eventA := makeSession("88888888-8888-4888-8888-888888888888", "web")
	b, _, eventB := makeSession("99999999-9999-4999-8999-999999999999", "")
	task := k.execute("create", "local.create_task", map[string]any{"goal": "explicit task"})
	id := k.taskID(task)
	conclusion := k.execute("complete", "local.complete_task", map[string]any{"task_id": id, "final_summary": "explicit conclusion", "token_estimate": 0})
	var cid, callRef string
	k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=?", conclusion.op).Scan(&cid)
	k.s.conn.QueryRowContext(ctx, "SELECT call_ref FROM operation WHERE op=?", conclusion.op).Scan(&callRef)
	bind := func(session, eid string, parents ...string) SignedRecord {
		return k.signed(record.Header{Type: record.KindBinding, Prov: record.ProvDerived, LID: record.BindingLID(callRef), Links: record.Links{Supersedes: parents}}, &record.BindingBody{CallRef: callRef, Status: "bound", Confidence: "transcript-echo", Target: &record.BindTarget{SessionKey: session}, Evidence: &record.BindEvidence{SightingEventIDs: []string{eid}}})
	}
	if err := k.s.write(ctx, func() error {
		d, err := k.s.load(ctx)
		if err != nil {
			return err
		}
		if err = d.computeTrust([]string{cid}); err != nil {
			return err
		}
		if !d.trust[cid].Uncertain || d.trust[cid].Coverage != "incomplete" {
			t.Fatal("unbound source was certified complete", d.trust[cid])
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	first := bind(a, eventA)
	k.append(first)
	check := func() {
		t.Helper()
		var tags, witness int
		if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_observed_taint WHERE id=? AND tag IN('web','third-party-mcp')", cid).Scan(&tags); err != nil || tags != 2 {
			t.Fatal("observed union lost", tags, err)
		}
		if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_taint_evidence WHERE id=? AND kind='binding_projection' AND evidence=? AND source=? AND boundary=?", cid, first.AdvisoryID, sourceA, eventA).Scan(&witness); err != nil || witness != 2 {
			t.Fatal("actual A witness lost", witness, err)
		}
		if err := k.s.write(ctx, func() error {
			d, err := k.s.load(ctx)
			if err != nil {
				return err
			}
			if err = d.computeTrust([]string{cid}); err != nil {
				return err
			}
			if d.trust[cid].Coverage != "complete" || d.trust[cid].Uncertain {
				t.Fatal("current session coverage not recomputed", d.trust[cid])
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check()
	second := bind(b, eventB, first.AdvisoryID)
	k.append(second)
	check()
	if err := k.s.Reindex(ctx); err != nil {
		t.Fatal(err)
	}
	check()
	erase := k.control(99, record.KindErasure, sourceA)
	k.append(erase)
	check()
	k.s.Close()
	st, err := Open(ctx, k.o)
	if err != nil {
		t.Fatal(err)
	}
	k.s = st
	check()
	var unknown int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_observed_taint WHERE tag='taint-unknown'").Scan(&unknown)
	if unknown != 0 {
		t.Fatal("uncertainty became permanent")
	}
}
