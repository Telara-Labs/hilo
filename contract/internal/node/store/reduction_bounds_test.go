package store

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/heads"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/view"
	"reflect"
	"testing"
)

func TestReviewSessionDistinctEventWorkIsBoundedBeforeAdmission(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	var total int
	for chunkIndex := 0; chunkIndex < 8; chunkIndex++ {
		var events []record.Event
		for j := 0; j < 256; j++ {
			seq := chunkIndex*256 + j
			eid, e := record.EventID(w.sessionKey(), "assistant_final", record.Anchor{NativeItemID: fmt.Sprintf("work-item-%d", seq)})
			if e != nil {
				t.Fatal(e)
			}
			event, e := record.ReviseEvent(record.Event{ID: eid, Seq: int64(seq), Kind: "assistant_final", Prov: "transcript", Text: &record.Text{Body: "bounded native event"}}, nil)
			if e != nil {
				t.Fatal(e)
			}
			events = append(events, event)
		}
		in := w.signed(record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: w.sessionKey()}, LID: record.ChunkLID(w.sessionKey(), testMachine, events[0].ID)}, &record.ChunkBody{Events: events})
		before := w.snapshot()
		_, err := w.s.Append(ctx, in)
		if err != nil {
			if total < 256 || Code(err) != "lineage_evaluation_required" {
				t.Fatal("missing admitted control or wrong refusal", total, err)
			}
			var holds int
			w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_hold").Scan(&holds)
			if holds != 0 {
				t.Fatal("discardable new input froze owner")
			}
			var n int
			w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record WHERE id=?", in.AdvisoryID).Scan(&n)
			if n != 0 {
				t.Fatal("overwork candidate persisted")
			}
			after, e := w.s.Snapshot(ctx, ReadRequest{})
			if e != nil || after.Generation != before.Generation || len(after.Entries) != len(before.Entries) {
				t.Fatal("new independent event work froze or changed old state", e)
			}
			return
		}
		total += 256
	}
	var presence int
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM presence").Scan(&presence)
	// These are actual reducer input counts: each event scans retained+body
	// presence and all body copies, before pair and frontier work.
	lowerBound := total * (presence + 2*total)
	if lowerBound > 1048576 {
		t.Fatalf("admitted actual native session reducer overwork: events=%d retainedPresence=%d perEventScanLowerBound=%d", total, presence, lowerBound)
	}
}
func TestReviewSessionGeneratedWitnessUnionRefusedBeforePersistence(t *testing.T) {
	f := newProducer(t, "same protected event payload")
	w := f.w
	ctx := context.Background()
	var chunks []SignedRecord
	var ids, revisions []string
	for i := 0; i < 363; i++ {
		ev := f.event(f.q.EventIDs[0], 0, "same protected event payload")
		chunks = append(chunks, f.chunk([]record.Event{ev}, nil))
		ids = append(ids, chunks[len(chunks)-1].AdvisoryID)
		revisions = append(revisions, ev.Revision)
	}
	w.seedPending(chunks)
	// Historical-bodyless fixture, not a public erasure receipt. Signed headers
	// and observed protected revisions survive while 360 bodies are unavailable.
	// Full 362-copy materialization is tested separately against encoding volume.
	err := w.s.write(ctx, func() error {
		if _, e := w.s.conn.ExecContext(ctx, "DELETE FROM record_body WHERE id IN (SELECT source FROM presence)"); e != nil {
			return e
		}
		for _, in := range chunks[360:] {
			if _, e := w.s.conn.ExecContext(ctx, "INSERT INTO record_body VALUES(?,?)", in.AdvisoryID, in.BodyJCS); e != nil {
				return e
			}
		}
		stmt, e := w.s.conn.PrepareContext(ctx, "INSERT INTO witness VALUES(?,?,?,?,?,?,?)")
		if e != nil {
			return e
		}
		defer stmt.Close()
		for i := 0; i < 362; i++ {
			for j := i + 1; j < 362; j++ {
				if _, e = stmt.ExecContext(ctx, w.o.PinnedGenesisID, f.q.Occurrence.SessionKey, f.q.EventIDs[0], revisions[i], revisions[j], ids[i], ids[j]); e != nil {
					return e
				}
			}
		}
		// Reverse SQL tuples remain distinct capacity even though pure aliases
		// normalize the orientation. No retained tuple is dropped or clipped.
		_, e = w.s.conn.ExecContext(ctx, "INSERT INTO witness SELECT owner,session,event_id,b,a,source_b,source_a FROM witness LIMIT 194")
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	var witnesses int
	if e := w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM witness").Scan(&witnesses); e != nil || witnesses != 65535 {
		t.Fatal("wrong retained SQL-key fixture", witnesses, e)
	}
	if e := w.s.Reindex(ctx); e != nil {
		t.Fatal("within-bound historical reconstruction", e)
	}
	// One genuinely new equality tuple reaches the exact SQL capacity.
	oldPage := f.page(ids[361:], 0, "")
	w.append(oldPage)
	if e := w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM witness").Scan(&witnesses); e != nil || witnesses != 65536 {
		t.Fatal("within-cap public pair admission", witnesses, e)
	}
	before := w.snapshot()
	page := f.page(ids[360:], 0, oldPage.AdvisoryID)
	_, err = w.s.Append(ctx, page)
	var persisted, holds int
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM witness").Scan(&witnesses)
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record WHERE id=?", page.AdvisoryID).Scan(&persisted)
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_hold").Scan(&holds)
	if Code(err) != "lineage_evaluation_required" || witnesses != 65536 || persisted != 0 || holds != 0 {
		t.Fatal("candidate SQL-key union overflow", err, witnesses, persisted, holds)
	}
	after, e := w.s.Snapshot(ctx, ReadRequest{})
	if e != nil || after.Generation != before.Generation || len(after.Entries) != len(before.Entries) {
		t.Fatal("candidate overflow changed old state", e)
	}
	w.s.Close()
	w.s, e = Open(ctx, w.o)
	if e != nil {
		t.Fatal(e)
	}
	if e = w.s.Reindex(ctx); e != nil {
		t.Fatal("retained SQL-key capacity not reconstructible after reopen", e)
	}
}

func TestReductionGroupsMatchCompletePureInputsAndInvalidate(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	first := w.task(1, "first")
	w.append(first)
	old, _, err := parse(first)
	if err != nil {
		t.Fatal(err)
	}
	// Unknown and cross-LID predecessors remain exactly the pure reducer's concern.
	second := w.signed(record.Header{Type: record.KindTask, LID: old.Header.LID, Prov: record.ProvMCPExplicit, Subj: old.Header.Subj, Op: record.H("op", "second"), Links: record.Links{Supersedes: []string{first.AdvisoryID, record.H("unknown predecessor")}}}, &record.TaskBody{Name: "second", Goal: "second", Status: "active"})
	w.append(second)
	other := w.task(2, "other group")
	w.append(other)
	check := func() {
		t.Helper()
		if err := w.s.write(ctx, func() error {
			d, e := w.s.load(ctx)
			if e != nil {
				return e
			}
			all := d.observed()
			for _, x := range d.records {
				if task := x.rec.Header.Subj.TaskID; task != "" {
					want := view.TaskStatus(all, nil, x.owner, task)
					if got := d.taskStatus(x.owner, task); got != want {
						t.Fatalf("task grouping changed complete pure status %s %s", got, want)
					}
				}
			}
			var versions []heads.Version
			groups := map[[3]string]bool{}
			want := map[string]bool{}
			for _, x := range d.records {
				h := x.rec.Header
				if h.Type.IsControl() {
					continue
				}
				versions = append(versions, heads.FromHeader(x.rec.ID, &h, x.owner, available(x)))
				groups[[3]string{x.owner, string(h.Type), h.LID}] = true
				if available(x) && record.ReducerOf(h.Type, h.Prov) == record.Set {
					want[x.rec.ID] = true
				}
			}
			for k := range groups {
				for _, v := range heads.HeadsForOwner(versions, nil, k[2], record.Kind(k[1]), k[0]) {
					want[v.ID] = true
				}
			}
			if got := currentHeads(d); !reflect.DeepEqual(got, want) {
				t.Fatal("grouped heads changed complete pure result")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check()
	w.append(w.control(1, record.KindErasure, second.AdvisoryID))
	check()
	if err = w.s.write(ctx, func() error {
		d, e := w.s.load(ctx)
		if e != nil {
			return e
		}
		if currentHeads(d)[first.AdvisoryID] {
			t.Fatal("bodyless superseder restored superseded predecessor")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReviewReductionBudgetProposalCannotFreezePriorCompleteState(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	root := k.execute("before-native-budget", "local.create_task", map[string]any{"goal": "prior complete root"})
	k.release(root)
	f := producerFor(k.world, "native input")
	var inputs []SignedRecord
	for i := 0; i < 1000; i++ {
		inputs = append(inputs, k.task(65000+i, "independent task"))
	}
	const count = 526
	for at := 0; at < count; {
		var events []record.Event
		for len(events) < 256 && at < count {
			eid, err := record.EventID(f.q.Occurrence.SessionKey, "assistant_final", record.Anchor{NativeItemID: fmt.Sprint("fallback-native-", at)})
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, f.event(eid, int64(at), "native budget input"))
			at++
		}
		inputs = append(inputs, f.chunk(events, nil))
	}
	k.seedPending(inputs)
	before := disclosureGuardState(t, k)
	if _, err := k.s.Snapshot(ctx, ReadRequest{}); err != nil {
		t.Fatal("prior state not complete", err)
	}
	command := commandFor(t, "local.lookup_record", map[string]any{"record_id": inputs[0].AdvisoryID})
	_, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued("new-native-budget-attempt")}, command, ByteBudget{MaxBytes: 4096})
	t.Log("proposal code", Code(err))
	var holds int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_hold").Scan(&holds)
	if holds != 0 {
		t.Fatal("discardable proposal budget froze previously complete state", holds)
	}
	if err != nil {
		requireSameDisclosureGuardState(t, k, before)
	}
	if _, err = k.s.Snapshot(ctx, ReadRequest{}); err != nil {
		t.Fatal("prior complete state lost after new proposal", err)
	}
}

func TestReviewReductionBudgetProposalLargeStateCannotFreeze(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	r := k.execute("large-prior-root", "local.create_task", map[string]any{"goal": "large prior root"})
	k.release(r)
	var inputs []SignedRecord
	for i := 0; i < 7000; i++ {
		inputs = append(inputs, k.task(85000+i, "ordinary prior source"))
	}
	k.seedPending(inputs)
	var n, affects int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record").Scan(&n)
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM exposure_affect").Scan(&affects)
	total := (1048576 - affects) / (n + 2)
	seedDisclosureExposureHistory(t, k, r, total)
	if _, e := k.s.Snapshot(ctx, ReadRequest{}); e != nil {
		t.Fatal("old actual state not complete", n, total, affects, e)
	}
	before := disclosureGuardState(t, k)
	command := commandFor(t, "local.lookup_record", map[string]any{"record_id": inputs[0].AdvisoryID})
	_, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued("new-large-prior-attempt")}, command, ByteBudget{MaxBytes: 4096})
	var holds int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_hold").Scan(&holds)
	t.Log("actual records/exposures/affects/oldwork/proposal", n, total, affects, total*n+affects, Code(err))
	if holds != 0 {
		t.Fatal("new discardable attempt starved prior reconstruction and froze owner", holds)
	}
	if err != nil {
		requireSameDisclosureGuardState(t, k, before)
	}
	if _, e := k.s.Snapshot(ctx, ReadRequest{}); e != nil {
		t.Fatal("old state unreadable after proposal", e)
	}
}

func TestReviewWitnessEnvelopeVolumeRefusedBeforePureCall(t *testing.T) {
	f := newProducer(t, "same protected event payload")
	var chunks []SignedRecord
	var ids []string
	var sample record.Event
	for i := 0; i < 362; i++ {
		ev := f.event(f.q.EventIDs[0], 0, "same protected event payload")
		if i == 0 {
			sample = ev
		}
		in := f.chunk([]record.Event{ev}, nil)
		chunks = append(chunks, in)
		ids = append(ids, in.AdvisoryID)
	}
	f.w.seedPending(chunks)
	raw, _ := json.Marshal(sample)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "revision")
	delete(fields, "salt")
	delete(fields, "replaces")
	mapped, _ := json.Marshal(fields)
	payload, err := record.EventPayload(sample)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jcs.StringArray("mnc1", "event-equality", f.w.o.PinnedGenesisID, f.q.Occurrence.SessionKey, sample.ID, sample.Revision, sample.Revision, ids[0], ids[1])
	if err != nil {
		t.Fatal(err)
	}
	lowerBound := 362 * 361 / 2 * (len(raw) + len(mapped) + len(payload) + len(key))
	if lowerBound <= 64<<20 {
		t.Fatal("fixture does not exceed actual full helper volume", lowerBound)
	}
	before := f.w.snapshot()
	page := f.page(ids, 0, "")
	_, err = f.w.s.Append(context.Background(), page)
	var persisted, holds int
	f.w.s.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM record WHERE id=?", page.AdvisoryID).Scan(&persisted)
	f.w.s.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM projection_hold").Scan(&holds)
	if Code(err) != "lineage_evaluation_required" || persisted != 0 || holds != 0 {
		t.Fatal("witness envelope bytes bypass encoding gate", Code(err), persisted, holds, lowerBound)
	}
	after, e := f.w.s.Snapshot(context.Background(), ReadRequest{})
	if e != nil || after.Generation != before.Generation || len(after.Entries) != len(before.Entries) {
		t.Fatal("refusal changed prior complete state", e)
	}
}

func TestReviewWithinBudgetFullBodyWitnessGeneration(t *testing.T) {
	f := newProducer(t, "bounded equality source")
	var chunks []SignedRecord
	var ids []string
	for i := 0; i < 100; i++ {
		e := f.event(f.q.EventIDs[0], 0, "bounded equality source")
		in := f.chunk([]record.Event{e}, nil)
		chunks = append(chunks, in)
		ids = append(ids, in.AdvisoryID)
	}
	f.w.seedPending(chunks)
	page := f.page(ids, 0, "")
	f.w.append(page)
	var witnesses int
	if err := f.w.s.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM witness").Scan(&witnesses); err != nil || witnesses != 4950 {
		t.Fatal("complete within-budget witness generation", witnesses, err)
	}
	if err := f.w.s.Reindex(context.Background()); err != nil {
		t.Fatal("within-budget full bodies not reconstructible", err)
	}
}
