package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

type producerFixture struct {
	w    *world
	q    CaptureRequest
	plan CommitPlan
}

func producerFor(w *world, text string) *producerFixture {
	w.t.Helper()
	source, e := record.SourceKey("claude-code", testMachine, ".claude/fixture/22222222-2222-4222-8222-222222222222.jsonl")
	if e != nil {
		w.t.Fatal(e)
	}
	id, e := record.EventID(w.sessionKey(), "user_prompt", record.Anchor{NativeItemID: "producer-user"})
	if e != nil {
		w.t.Fatal(e)
	}
	q := CaptureRequest{Occurrence: SourceOccurrence{Owner: w.o.PinnedGenesisID, Source: source, SessionKey: w.sessionKey()}, AuthorKeyID: w.o.PinnedGenesisID, Reader: record.SourceRef{Reader: "claude-code", ReaderVersion: "native-jsonl-runtime.1"}, RulesetFingerprint: record.H("synthetic-ruleset"), EventIDs: []string{id}, Range: CaptureRange{0, 1}}
	f := &producerFixture{w: w, q: q}
	ev := f.event(id, 0, text)
	chunk := f.chunk([]record.Event{ev}, nil)
	page := f.page([]string{chunk.AdvisoryID}, 0, "")
	f.plan = CommitPlan{NewRecords: []SignedRecord{chunk, page}, Next: CaptureNext{SettledThrough: 0, LastSourceRecordIDs: []string{chunk.AdvisoryID}, SessionPageIDs: []PageRef{{0, page.AdvisoryID}}, Reader: q.Reader, RulesetFingerprint: q.RulesetFingerprint, Range: q.Range}}
	return f
}
func newProducer(t *testing.T, text string) *producerFixture { return producerFor(newWorld(t), text) }
func (f *producerFixture) event(id string, seq int64, text string, parents ...string) record.Event {
	f.w.t.Helper()
	e, err := record.ReviseEvent(record.Event{ID: id, Seq: seq, Kind: "user_prompt", Prov: "transcript", Text: &record.Text{Body: text, Bytes: len(text)}}, parents)
	if err != nil {
		f.w.t.Fatal(err)
	}
	return e
}
func (f *producerFixture) build(k record.Kind, lid string, b any, links record.Links) SignedRecord {
	f.w.t.Helper()
	f.w.at++
	r, e := record.Build(record.Header{Type: k, LID: lid, At: f.w.at, Author: record.Author{MachineID: testMachine, KeyID: f.q.AuthorKeyID}, Prov: record.ProvTranscript, Subj: record.Subject{Source: f.q.Occurrence.Source, SessionKey: f.q.Occurrence.SessionKey, Client: &record.ClientRef{ID: f.q.Reader.Reader, Surface: "cli"}}, Red: record.Redact{Profile: record.ProfileLocal, Fingerprint: f.q.RulesetFingerprint}, Links: links}, b)
	if e != nil {
		f.w.t.Fatal(e)
	}
	sg, e := sig.SignRecord(f.w.key, r.ID)
	if e != nil {
		f.w.t.Fatal(e)
	}
	return wire(r, []record.Signature{sg})
}
func (f *producerFixture) chunk(events []record.Event, deps []string) SignedRecord {
	return f.build(record.KindChunk, record.ChunkLID(f.q.Occurrence.SessionKey, testMachine, events[0].ID), &record.ChunkBody{Events: events}, record.Links{DerivedFrom: deps})
}
func (f *producerFixture) page(chunks []string, settled int64, prev string) SignedRecord {
	l := record.Links{Prev: prev}
	if prev != "" {
		l.Supersedes = []string{prev}
	}
	return f.build(record.KindSession, record.SessionLID(f.q.Occurrence.SessionKey, testMachine, 0), &record.SessionBody{NativeID: "22222222-2222-4222-8222-222222222222", NativeIDKind: record.NativeGlobal, Chunks: chunks, SettledThrough: settled, Reader: &f.q.Reader}, l)
}
func (f *producerFixture) commit() CaptureReceipt {
	f.w.t.Helper()
	r, e := f.w.s.Capture(context.Background(), f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil })
	if e != nil {
		f.w.t.Fatal(e)
	}
	return r
}
func TestProducerConcurrentDifferentPlansOneTransition(t *testing.T) {
	f := newProducer(t, "winner candidate one")
	g := producerFor(f.w, "winner candidate two")
	ctx := context.Background()
	other, e := Open(ctx, f.w.o)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	var calls atomic.Int64
	var wg sync.WaitGroup
	got := make([]CaptureReceipt, 2)
	errs := make([]error, 2)
	for i, s := range []*Store{f.w.s, other} {
		wg.Add(1)
		go func(i int, s *Store) {
			defer wg.Done()
			plan := f.plan
			if i == 1 {
				plan = g.plan
			}
			got[i], errs[i] = s.Capture(ctx, f.q, func(*CaptureTxn) (CommitPlan, error) { calls.Add(1); return plan, nil })
		}(i, s)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || calls.Load() != 1 || got[0].TransitionID != got[1].TransitionID || got[0].ActualRecordRefs[0] != got[1].ActualRecordRefs[0] || got[0].Status == got[1].Status {
		t.Fatal("CAS/receipt split", got, errs, calls.Load())
	}
	q := f.q
	q.ExpectedVersion = 7
	_, e = f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { t.Fatal("stale CAS minted"); return CommitPlan{}, nil })
	if Code(e) != "stale_progress" {
		t.Fatal(e)
	}
}
func TestProducerSQLFailuresRollbackWholeBatchAndProgress(t *testing.T) {
	for _, table := range []string{"record", "record_body", "item_order", "item_event", "dep", "presence", "passage", "projection_job", "capture_progress", "capture_transition", "capture_transition_record", "capture_transition_source", "capture_transition_page"} {
		t.Run(table, func(t *testing.T) {
			f := newProducer(t, "rollback candidate")
			seedFreshCheckpoint(f.w, "fresh projection fault fixture")
			ctx := context.Background()
			before := f.w.snapshot()
			// A page always has a copied chunk dependency, so every listed gate executes.
			if _, e := f.w.s.conn.ExecContext(ctx, "CREATE TRIGGER capture_fault BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(ABORT,'private fault text'); END"); e != nil {
				t.Fatal(e)
			}
			r, e := f.w.s.Capture(ctx, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil })
			if Code(e) != "storage_error" || r.Status != "" || len(r.ActualRecordRefs) != 0 {
				t.Fatal("fault acknowledged", r, e)
			}
			p, e := f.w.s.InspectCapture(ctx, f.q.Occurrence)
			if e != nil || p.Progress.Version != 0 {
				t.Fatal("fault progressed", p, e)
			}
			after := f.w.snapshot()
			if len(after.Entries) != len(before.Entries) || after.Generation != before.Generation {
				t.Fatal("partial batch")
			}
			var n int
			if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM capture_transition").Scan(&n) != nil || n != 0 {
				t.Fatal("partial receipt")
			}
			if _, e = f.w.s.conn.ExecContext(ctx, "DROP TRIGGER capture_fault"); e != nil {
				t.Fatal(e)
			}
			if f.commit().Status != "committed" {
				t.Fatal("confirmed rollback poisoned safe retry")
			}
		})
	}
}
func TestProducerUnknownCommitPoisonsUntilNormalRecovery(t *testing.T) {
	f := newProducer(t, "commit fault candidate")
	ctx := context.Background()
	for _, q := range []string{"CREATE TABLE fault_parent(id INTEGER PRIMARY KEY)", "CREATE TABLE fault_child(id INTEGER REFERENCES fault_parent(id) DEFERRABLE INITIALLY DEFERRED)", "CREATE TRIGGER commit_fault AFTER INSERT ON capture_transition BEGIN INSERT INTO fault_child VALUES(999); END"} {
		if _, e := f.w.s.conn.ExecContext(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	r, e := f.w.s.Capture(ctx, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil })
	if Code(e) != "outcome_unknown" || r.Status != "" {
		t.Fatal("ambiguous commit acknowledged", r, e)
	}
	_, e = f.w.s.Capture(ctx, f.q, func(*CaptureTxn) (CommitPlan, error) { t.Fatal("poisoned producer minted"); return CommitPlan{}, nil })
	if Code(e) != "outcome_unknown" {
		t.Fatal(e)
	}
	f.w.s.Close()
	s, e := Open(ctx, f.w.o)
	if e != nil {
		t.Fatal(e)
	}
	f.w.s = s
	p, e := s.InspectCapture(ctx, f.q.Occurrence)
	if e != nil || p.Progress.Version != 0 {
		t.Fatal("normal recovery facts", p, e)
	}
	if _, e = s.conn.ExecContext(ctx, "DROP TRIGGER commit_fault"); e != nil {
		t.Fatal(e)
	}
	// This test covers normal recovery of this database, not restored old copies.
	if f.commit().ResultingProgress.Version != 1 {
		t.Fatal("recovered absence could not admit")
	}
}
func TestProducerHistoryNeverTurnsUnavailableMaximalPresenceIntoAbsence(t *testing.T) {
	f := newProducer(t, "original")
	f.commit()
	ctx := context.Background()
	changed := f.event(f.q.EventIDs[0], 0, "unavailable independent revision")
	other := f.chunk([]record.Event{changed}, nil)
	f.w.append(other)
	f.w.append(f.w.control(512, record.KindRetraction, other.AdvisoryID))
	q := f.q
	q.ExpectedVersion = 1
	_, e := f.w.s.Capture(ctx, q, func(tx *CaptureTxn) (CommitPlan, error) {
		h, e := tx.Events(q.EventIDs)
		if e != nil {
			t.Fatal(e)
		}
		v := h[q.EventIDs[0]]
		if !v.KnownPresence || !v.Pending || v.CompleteFrontier || len(v.Copies) != 1 || len(v.Facts.Presence) < 2 {
			t.Fatal("bodyless frontier lost", v)
		}
		return CommitPlan{}, errors.New("hold")
	})
	if Code(e) != "producer_refused" {
		t.Fatal(e)
	}
}
func TestProducerNineRevisionHeadsHoldBeforeConstruction(t *testing.T) {
	f := newProducer(t, "original")
	f.commit()
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		ev := f.event(f.q.EventIDs[0], 0, fmt.Sprintf("branch%d", i))
		f.w.append(f.chunk([]record.Event{ev}, nil))
	}
	q := f.q
	q.ExpectedVersion = 1
	_, e := f.w.s.Capture(ctx, q, func(tx *CaptureTxn) (CommitPlan, error) {
		h, e := tx.Events(q.EventIDs)
		if e != nil {
			t.Fatal(e)
		}
		v := h[q.EventIDs[0]]
		if len(v.MaximalRevisionIDs) != 9 || !v.Pending || v.CompleteFrontier || !v.Conflict {
			t.Fatal("excessive heads did not hold", v)
		}
		return CommitPlan{}, errors.New("hold")
	})
	if Code(e) != "producer_refused" {
		t.Fatal(e)
	}
}
func TestProducerCounterExhaustionAndIdentityDoNotAttestRestore(t *testing.T) {
	for _, counter := range []string{"next_seq", "generation", "authority_epoch"} {
		t.Run(counter, func(t *testing.T) {
			w := newWorld(t)
			ctx := context.Background()
			r := w.task(1, "bounded ordinal")
			if counter == "authority_epoch" {
				next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{29}, 32))
				r = w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Genesis: w.o.PinnedGenesisID, Subject: sig.KeyRefOf(next.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Parents: []string{w.genesis.AdvisoryID}}, w.key, w.key, next)
			}
			if _, e := w.s.conn.ExecContext(ctx, "UPDATE meta SET "+counter+"=?", int64(math.MaxInt64)); e != nil {
				t.Fatal(e)
			}
			if _, e := w.s.Append(ctx, r); Code(e) != "ordinal_limit" {
				t.Fatal(counter, e)
			}
			var n int
			if w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record").Scan(&n) != nil || n != 1 {
				t.Fatal("overflow wrote candidate")
			}
		})
	}
	f := newProducer(t, "identity")
	ctx := context.Background()
	id, e := f.w.s.Identity(ctx)
	if e != nil || id.OwnerGenesis != f.w.o.PinnedGenesisID || len(id.StoreInstanceID) != 32 {
		t.Fatal(id, e)
	}
	if _, e = f.w.s.conn.ExecContext(ctx, "UPDATE capture_instance SET id='different'"); e != nil {
		t.Fatal(e)
	}
	_, e = f.w.s.Capture(ctx, f.q, func(*CaptureTxn) (CommitPlan, error) { t.Fatal("replaced instance minted"); return f.plan, nil })
	if Code(e) != "outcome_unknown" {
		t.Fatal(e)
	}
}

func TestProducerHistoryAndVersionLimitsPrecedeCallback(t *testing.T) {
	t.Run("history", func(t *testing.T) {
		f := newProducer(t, "bounded history")
		r, _ := record.Parse(f.plan.NewRecords[0].HeaderJCS, f.plan.NewRecords[0].BodyJCS, "")
		event := r.Body.(*record.ChunkBody).Events[0]
		var copies []SignedRecord
		for i := 0; i < 65; i++ {
			copies = append(copies, f.chunk([]record.Event{event}, nil))
		}
		f.w.seedPending(copies)
		_, e := f.w.s.Capture(context.Background(), f.q, func(*CaptureTxn) (CommitPlan, error) {
			t.Fatal("oversized history reached constructor")
			return f.plan, nil
		})
		if Code(e) != "history_limit" {
			t.Fatal(e)
		}
	})
	for _, counter := range []string{"next_seq", "generation", "version"} {
		t.Run(counter, func(t *testing.T) {
			f := newProducer(t, "bounded version")
			f.commit()
			ctx := context.Background()
			q := f.q
			q.ExpectedVersion = 1
			sql := "UPDATE meta SET " + counter + "=?"
			if counter == "version" {
				sql = "UPDATE capture_progress SET version=?"
				q.ExpectedVersion = math.MaxInt64
			}
			if _, e := f.w.s.conn.ExecContext(ctx, sql, int64(math.MaxInt64)); e != nil {
				t.Fatal(e)
			}
			_, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { t.Fatal("exhausted ordinal minted"); return f.plan, nil })
			if Code(e) != "ordinal_limit" {
				t.Fatal(counter, e)
			}
		})
	}
}
