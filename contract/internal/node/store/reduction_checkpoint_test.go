package store

import (
	"context"
	"encoding/json"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/view"
)

func TestReductionEventEncodingSizeMatchesFixedDTO(t *testing.T) {
	values := []record.Event{
		{}, {ID: "ordinary", Seq: -1, Text: &record.Text{Body: "<tag>&\u2028\n\t\"\\ café"}, Meta: map[string]string{"<&": "value"}},
		{Text: &record.Text{}, Call: &record.ToolCall{Args: map[string]string{"b": "\x01\xff", "a": ""}, RawArgs: map[string]bool{"b": false}}, Result: &record.ToolResult{OutIDs: []string{}, OutPaths: []string{"path"}, Bytes: 13}, Src: &record.SourcePos{Line: 15}},
	}
	c := newReductionContext()
	for _, e := range values {
		n, err := c.eventEncodingSize(e)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != n {
			t.Fatal("fixed DTO encoding was not conservatively measured", len(raw), n)
		}
		clear(raw)
	}
}

// This is copy-isolation/counter-retention unit evidence. The separate public
// SQLite fixtures prove the budget boundary without assigning synthetic work.
func TestReductionCheckpointDetachesMutableStateAndNeverRefundsWork(t *testing.T) {
	k := newKernel(t)
	k.execute("checkpoint-source", "local.create_task", map[string]any{"goal": "checkpoint source"})
	ctx := context.Background()
	if err := k.s.write(ctx, func() error {
		d, err := k.s.load(ctx)
		if err != nil {
			return err
		}
		if err = d.prepareRelations(); err != nil {
			return err
		}
		if d.taintWitnesses == nil {
			d.taintWitnesses = map[taintWitness]bool{}
		}
		prior, err := d.checkpointVerified()
		if err != nil {
			return err
		}
		id := d.records[0].rec.ID
		oldState := d.records[0].state
		d.records[0].state = "unit changed status"
		d.taint[id] = map[string]bool{"web": true}
		d.taintWitnesses[taintWitness{id: id, tag: "web"}] = true
		d.exposures[0].affects[id] = true
		d.nonces["unit candidate nonce"] = true
		d.nonceLookups = 7
		c, _ := d.reductions()
		work, encoded := c.work, c.encoded
		if err = c.charge(17); err != nil {
			return err
		}
		if err = c.encode(3, 1); err != nil {
			return err
		}
		d.restoreVerified(prior)
		if d.records[0].state != oldState || d.byID[id] != d.records[0] || d.taint[id]["web"] || d.taintWitnesses[taintWitness{id: id, tag: "web"}] || d.exposures[0].affects[id] || d.nonces["unit candidate nonce"] {
			t.Fatal("proposal mutated checkpoint aliases")
		}
		if d.nonceLookups != 7 || c.work != work+17 || c.encoded != encoded+3 {
			t.Fatal("checkpoint refunded actual work")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReductionReservationsCoverCompleteActualEncodingChains(t *testing.T) {
	f := newProducer(t, "encoding source")
	for _, text := range []string{"", strings.Repeat("a", 3200), strings.Repeat("\"\\\n<>&", 128), "Résumé café\u2028😀"} {
		e := f.event(f.q.EventIDs[0], 0, text, record.H("encoding predecessor"))
		c := newReductionContext()
		n, err := c.eventEncodingSize(e)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		delete(fields, "revision")
		mapped, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := jcs.MarshalRecord(fields)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := jcs.StringArray("mnc1", "event-rev", e.ID, string(canonical))
		if err != nil {
			t.Fatal(err)
		}
		actual := len(raw) + len(mapped) + len(canonical) + len(envelope)
		if err = c.reserveRevisionEncoding(e, n); err != nil {
			t.Fatal(err)
		}
		if c.encoded < actual {
			t.Fatal("revision/helper envelope was undercounted", c.encoded, actual)
		}
		clear(mapped)
		clear(canonical)
		clear(envelope)
		delete(fields, "salt")
		delete(fields, "replaces")
		mapped, err = json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := record.EventPayload(e)
		if err != nil {
			t.Fatal(err)
		}
		actual = len(raw) + len(mapped) + len(payload)
		c = newReductionContext()
		if err = c.reservePayloadEncoding(n, 2); err != nil {
			t.Fatal(err)
		}
		if c.encoded < 2*actual {
			t.Fatal("outer/head payload helper was undercounted", c.encoded, actual)
		}
		c = newReductionContext()
		if err = c.reservePayloadEncoding(n, 1); err != nil {
			t.Fatal(err)
		}
		if c.encoded < actual {
			t.Fatal("inner payload helper was undercounted", c.encoded, actual)
		}
		clear(raw)
		clear(mapped)
		clear(payload)
	}
}

func TestReviewActualPayloadEncodingVolumeRefusedBeforePureCall(t *testing.T) {
	f := newProducer(t, strings.Repeat("a", 3200))
	w := f.w
	ctx := context.Background()
	var ids []string
	var encodedInner int
	for i := 0; i < 128; i++ {
		event := f.event(f.q.EventIDs[0], 0, strings.Repeat("a", 3200))
		if i == 0 {
			raw, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, "revision")
			delete(fields, "salt")
			delete(fields, "replaces")
			mapped, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := record.EventPayload(event)
			if err != nil {
				t.Fatal(err)
			}
			encodedInner = len(raw) + len(mapped) + len(canonical)
			clear(raw)
			clear(mapped)
			clear(canonical)
		}
		in := f.chunk([]record.Event{event}, nil)
		w.append(in)
		ids = append(ids, in.AdvisoryID)
	}
	if inner := encodedInner * 128 * 127 / 2; inner <= 64<<20 {
		t.Fatal("fixture does not actually exceed encoding volume", inner)
	}
	before := w.snapshot()
	page := f.page(ids, 0, "")
	_, err := w.s.Append(ctx, page)
	var persisted, holds int
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record WHERE id=?", page.AdvisoryID).Scan(&persisted)
	w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_hold").Scan(&holds)
	if Code(err) != "lineage_evaluation_required" || persisted != 0 || holds != 0 {
		t.Fatal("actual payload encodings exceeded gate before reducer", Code(err), persisted, holds, encodedInner*128*127/2)
	}
	after, err := w.s.Snapshot(ctx, ReadRequest{})
	if err != nil || after.Generation != before.Generation || len(after.Entries) != len(before.Entries) {
		t.Fatal("encoding refusal changed prior complete state", err)
	}
}

func TestReductionWitnessEncodingReservationCoversActualHashEnvelope(t *testing.T) {
	f := newProducer(t, "witness envelope source")
	a := f.event(f.q.EventIDs[0], 0, "equal source")
	b := f.event(f.q.EventIDs[0], 0, "equal source")
	for _, reverse := range []bool{false, true} {
		w := view.EqualityWitness{Owner: f.w.o.PinnedGenesisID, SessionKey: f.q.Occurrence.SessionKey, EventID: a.ID, A: a.Revision, B: b.Revision, RecordA: f.plan.NewRecords[0].AdvisoryID, RecordB: record.H("second witness source")}
		if reverse {
			w.A, w.B = w.B, w.A
			w.RecordA, w.RecordB = w.RecordB, w.RecordA
		}
		c := newReductionContext()
		if err := c.reserveWitnessEncoding(w); err != nil {
			t.Fatal(err)
		}
		raw, err := jcs.StringArray("mnc1", "event-equality", w.Owner, w.SessionKey, w.EventID, w.A, w.B, w.RecordA, w.RecordB)
		if err != nil {
			t.Fatal(err)
		}
		if c.encoded != len(raw) {
			t.Fatal("complete equality-key envelope not reserved", c.encoded, len(raw))
		}
	}
	bad := view.EqualityWitness{Owner: f.w.o.PinnedGenesisID, SessionKey: f.q.Occurrence.SessionKey, EventID: a.ID, A: "invalid", B: b.Revision, RecordA: f.plan.NewRecords[0].AdvisoryID, RecordB: record.H("source")}
	if err := newReductionContext().reserveWitnessEncoding(bad); Code(err) != "invalid_causal_state" {
		t.Fatal("malformed retained identifier reached hash envelope", err)
	}
}
