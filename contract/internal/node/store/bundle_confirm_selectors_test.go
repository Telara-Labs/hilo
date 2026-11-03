package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
)

// TestBundleConfirmedSelectorControlsRestore carries a valid same-genesis
// erasure for every unbounded selector type, alone and mixed. Unconfirmed,
// each refuses the whole bundle and changes nothing; review lists it with
// its selector counts; the receiving owner's confirmation of that exact
// control applies it and purges exactly the matching record. A confirmed
// control from a key outside the keyring is still refused, and outside a
// bundle import the same selectors are never admitted.
func TestBundleConfirmedSelectorControlsRestore(t *testing.T) {
	type fixture struct {
		task, chunk SignedRecord
		taskID, lid string
		session     string
		source      string
		event       record.EventSelector
	}
	cases := []struct {
		name   string
		sel    func(w *world, f fixture) record.Selectors
		erased func(f fixture) []string
		review func(r ControlReview) bool
	}{
		{"tasks", func(w *world, f fixture) record.Selectors {
			return record.Selectors{Tasks: []record.TaskSelector{{Owner: w.o.PinnedGenesisID, TaskID: f.taskID}}}
		}, func(f fixture) []string { return []string{f.task.AdvisoryID} }, func(r ControlReview) bool { return r.Tasks == 1 }},
		{"lids", func(w *world, f fixture) record.Selectors {
			return record.Selectors{LIDs: []string{f.lid}}
		}, func(f fixture) []string { return []string{f.task.AdvisoryID} }, func(r ControlReview) bool { return r.LIDs == 1 }},
		{"sessions", func(w *world, f fixture) record.Selectors {
			return record.Selectors{Sessions: []string{f.session}}
		}, func(f fixture) []string { return []string{f.chunk.AdvisoryID} }, func(r ControlReview) bool { return r.Sessions == 1 }},
		// A source selector states the event coverage of what it erases.
		{"sources", func(w *world, f fixture) record.Selectors {
			return record.Selectors{Sources: []string{f.source}, Events: []record.EventSelector{f.event}}
		}, func(f fixture) []string { return []string{f.chunk.AdvisoryID} }, func(r ControlReview) bool { return r.Sources == 1 && r.Events == 1 }},
		{"mixed", func(w *world, f fixture) record.Selectors {
			return record.Selectors{Tasks: []record.TaskSelector{{Owner: w.o.PinnedGenesisID, TaskID: f.taskID}}, Sessions: []string{f.session}, LIDs: []string{f.lid}, Sources: []string{f.source}}
		}, func(f fixture) []string { return []string{f.task.AdvisoryID, f.chunk.AdvisoryID} }, func(r ControlReview) bool {
			return r.Tasks == 1 && r.Sessions == 1 && r.LIDs == 1 && r.Sources == 1
		}},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			w := newWorld(t)
			recv := joinDevice(t, w)
			source, err := record.SourceKey("claude-code", testMachine, ".claude/fixture/selector.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			task := w.task(70+i, "selector_restore_task_canary_5d21")
			e := w.event("selector_restore_chunk_canary_9a0c")
			sk := w.sessionKey()
			chunk := w.signed(record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk, Source: source}, LID: record.ChunkLID(sk, testMachine, e.ID)}, &record.ChunkBody{Events: []record.Event{e}})
			w.append(task)
			w.append(chunk)
			parsed, err := record.Parse(task.HeaderJCS, task.BodyJCS, task.AdvisoryID)
			if err != nil {
				t.Fatal(err)
			}
			f := fixture{task: task, chunk: chunk, taskID: parsed.Header.Subj.TaskID, lid: parsed.Header.LID, session: sk, source: source, event: record.EventSelector{Owner: w.o.PinnedGenesisID, SessionKey: sk, EventID: e.ID}}
			ids := []string{task.AdvisoryID, chunk.AdvisoryID}
			sel, err := w.s.SelectBundle(ctx, ids)
			if err != nil || len(sel.Data) != 2 {
				t.Fatal(sel.Excluded, err)
			}
			if _, err = recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Keyring: sel.Keyring, Data: sel.Data}); err != nil {
				t.Fatal(err)
			}
			bodies := func() map[string]int {
				out := map[string]int{}
				for _, id := range ids {
					out[id] = countRows(t, recv.s, "SELECT count(*) FROM record_body WHERE id=?", id)
				}
				return out
			}
			control := deviceControl(t, w.key, testMachine, "selector-"+c.name, w.at+10, c.sel(w, f))
			in := BundleImport{LocalKeyID: recv.KeyID(), Keyring: sel.Keyring, Controls: []SignedRecord{control}}

			// Unconfirmed: refused whole, nothing changes.
			if _, err = recv.s.ImportBundle(ctx, in); Code(err) != "bulk_confirmation_required" {
				t.Fatal("unconfirmed selector control applied", err)
			}
			for id, n := range bodies() {
				if n != 1 {
					t.Fatal("refused control purged", id)
				}
			}
			if countRows(t, recv.s, "SELECT count(*) FROM record WHERE id=?", control.AdvisoryID) != 0 {
				t.Fatal("refused control retained")
			}
			// Confirming another control does not confirm this one.
			other := in
			other.ConfirmedControls = []string{task.AdvisoryID}
			if _, err = recv.s.ImportBundle(ctx, other); Code(err) != "bulk_confirmation_required" {
				t.Fatal("confirmation of another id applied the control", err)
			}
			// Outside a bundle import the selector is never admitted, even
			// on the issuing device's own store.
			if _, err = w.s.Append(ctx, control); Code(err) != "bulk_confirmation_required" {
				t.Fatal("selector control admitted outside a confirmed bundle", err)
			}
			review, err := recv.s.ReviewBundleControls(ctx, in.Controls)
			if err != nil || len(review) != 1 || review[0].ID != control.AdvisoryID || !c.review(review[0]) {
				t.Fatal("review", review, err)
			}

			// A confirmed control from a key this genesis never enrolled.
			stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
			forged := deviceControl(t, stranger, testMachine, "selector-forged-"+c.name, w.at+11, c.sel(w, f))
			if _, err = recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Keyring: sel.Keyring, Controls: []SignedRecord{forged}, ConfirmedControls: []string{forged.AdvisoryID}}); err == nil {
				t.Fatal("confirmed control from an unenrolled key applied")
			}
			for id, n := range bodies() {
				if n != 1 {
					t.Fatal("forged control purged", id)
				}
			}

			// Confirmed: applied, exactly the matching records purged.
			confirmed := in
			confirmed.ConfirmedControls = []string{control.AdvisoryID}
			r, err := recv.s.ImportBundle(ctx, confirmed)
			if err != nil || r.Controls != 1 {
				t.Fatal("confirmed selector control", r, err)
			}
			erased := map[string]bool{}
			for _, id := range c.erased(f) {
				erased[id] = true
			}
			if n := countRows(t, recv.s, "SELECT count(*) FROM erasure_pending"); n != 0 {
				t.Fatal("confirmed control left the owner pending", n)
			}
			snap, err := recv.s.Snapshot(ctx, ReadRequest{IDs: ids})
			if err != nil {
				t.Fatal(err)
			}
			for id, n := range bodies() {
				if erased[id] && n != 0 {
					t.Fatal("confirmed control left the matching body", id)
				}
				if !erased[id] && (n != 1 || find(snap, id).State != "live") {
					t.Fatal("confirmed control reached an unmatched record", id, find(snap, id).State)
				}
			}
			if review, err = recv.s.ReviewBundleControls(ctx, in.Controls); err != nil || len(review) != 0 {
				t.Fatal("admitted control still reviewed", review, err)
			}
		})
	}
}
