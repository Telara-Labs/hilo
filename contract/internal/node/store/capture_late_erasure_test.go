package store

import (
	"context"
	"errors"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"strings"
	"testing"
)

func TestProducerLateErasureProofRefusalPersistsOnlyPrivacyBarrier(t *testing.T) {
	for _, extra := range []int{0, 996, 1001} {
		name := "under_cap"
		if extra == 996 {
			name = "exactly1000_effects"
		}
		if extra > 996 {
			name = "over_cap"
		}
		t.Run(name, func(t *testing.T) {
			f := newProducer(t, "late-erasure-exact-seal-canary")
			first := f.commit()
			ctx := context.Background()
			original := f.plan.NewRecords[0]
			oldPage := f.plan.NewRecords[1]
			parsed, e := record.Parse(original.HeaderJCS, original.BodyJCS, original.AdvisoryID)
			if e != nil {
				t.Fatal(e)
			}
			event := parsed.Body.(*record.ChunkBody).Events[0]
			replacement := f.chunk([]record.Event{event}, []string{original.AdvisoryID})
			nextPage := f.page([]string{original.AdvisoryID, replacement.AdvisoryID}, 0, oldPage.AdvisoryID)
			cause := f.w.control(9201, record.KindErasure, replacement.AdvisoryID)
			f.w.append(cause)
			var copies []SignedRecord
			for i := 0; i < extra; i++ {
				copies = append(copies, f.chunk([]record.Event{event}, nil))
			}
			if len(copies) > 0 {
				f.w.seedPending(copies)
			}
			before := f.w.snapshot()
			var oldSeq, oldEffects, oldBodies, oldRecords, oldReceipts int64
			for _, q := range []struct {
				sql string
				out *int64
			}{{"SELECT next_seq FROM meta", &oldSeq}, {"SELECT count(*) FROM erasure_effect", &oldEffects}, {"SELECT count(*) FROM record_body", &oldBodies}, {"SELECT count(*) FROM record", &oldRecords}, {"SELECT count(*) FROM capture_transition", &oldReceipts}} {
				if f.w.s.conn.QueryRowContext(ctx, q.sql).Scan(q.out) != nil {
					t.Fatal(q.sql)
				}
			}
			q := f.q
			q.ExpectedVersion = 1
			plan := CommitPlan{NewRecords: []SignedRecord{replacement, nextPage}, ReuseRecordIDs: []string{original.AdvisoryID}, Next: f.plan.Next}
			plan.Next.LastSourceRecordIDs = []string{replacement.AdvisoryID}
			plan.Next.SessionPageIDs = []PageRef{{0, nextPage.AdvisoryID}}
			got, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return plan, nil })
			var held *Error
			wantCode, wantReason := "privacy_hold_required", "late_erasure_discovery"
			if extra > 996 {
				wantCode = "bulk_confirmation_required"
				wantReason = "bulk_confirmation_required"
			}
			if !errors.As(e, &held) || held.Code != wantCode || !held.OwnerBlocked {
				var barriers int
				f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&barriers)
				snap, readErr := f.w.s.Snapshot(ctx, ReadRequest{IDs: []string{original.AdvisoryID}})
				state := "unknown"
				body := 0
				if readErr == nil && len(snap.Entries) == 1 {
					state = snap.Entries[0].State
					body = len(snap.Entries[0].BodyJCS)
				}
				t.Fatalf("verified late erasure lost on refusal: got code=%s ownerBlocked=%v barriers=%d originalState=%s originalBodyBytes=%d readError=%s", Code(e), held != nil && held.OwnerBlocked, barriers, state, body, Code(readErr))
			}
			if got.Status != "" || got.TransitionID != "" || len(got.ActualRecordRefs) != 0 {
				t.Fatal("refusal exposed candidate receipt")
			}
			var reason, control string
			var generation int64
			if f.w.s.conn.QueryRowContext(ctx, "SELECT reason,control,generation FROM privacy_barrier").Scan(&reason, &control, &generation) != nil || reason != wantReason || control != cause.AdvisoryID || generation != before.Generation+1 {
				t.Fatal("wrong minimal barrier", reason, control, generation)
			}
			for _, q := range []struct {
				sql  string
				want int64
			}{{"SELECT next_seq FROM meta", oldSeq}, {"SELECT count(*) FROM erasure_effect", oldEffects}, {"SELECT count(*) FROM record_body", oldBodies}, {"SELECT count(*) FROM record", oldRecords}, {"SELECT count(*) FROM capture_transition", oldReceipts}} {
				var n int64
				if f.w.s.conn.QueryRowContext(ctx, q.sql).Scan(&n) != nil || n != q.want {
					t.Fatal("candidate or partial deletion leaked", q.sql, n, q.want)
				}
			}
			var n int
			if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record WHERE id IN (?,?)", replacement.AdvisoryID, nextPage.AdvisoryID).Scan(&n) != nil || n != 0 {
				t.Fatal("candidate header persisted")
			}
			if _, e = f.w.s.Snapshot(ctx, ReadRequest{}); e == nil {
				t.Fatal("held owner remains readable")
			}
			inspected, e := f.w.s.InspectCapture(ctx, q.Occurrence)
			if e != nil || !inspected.Suppression.OwnerBlocked || !inspected.Suppression.Suppressed || inspected.Progress.Version != 1 {
				t.Fatal("hold lost progress/pre-open fence", inspected, e)
			}
			replay, e := f.w.s.Capture(ctx, f.q, func(*CaptureTxn) (CommitPlan, error) { t.Fatal("committed retry minted"); return CommitPlan{}, nil })
			if e != nil || replay.Status != "prior_transition_committed" || replay.TransitionID != first.TransitionID {
				t.Fatal("prior receipt lost", replay, e)
			}
			for _, r := range replay.ActualRecordRefs {
				if replay.CurrentAvailability[r.ID] != "owner_blocked" {
					t.Fatal("prior receipt says available")
				}
			}
			scrub, e := f.w.s.Scrub(ctx, cause.AdvisoryID)
			if e != nil || scrub.State != "blocked" {
				t.Fatal("held bodies falsely physically erased", scrub, e)
			}
			f.w.s.Close()
			s, e := Open(ctx, f.w.o)
			if e != nil {
				t.Fatal(e)
			}
			f.w.s = s
			if _, e = s.Snapshot(ctx, ReadRequest{}); e == nil {
				t.Fatal("restart cleared privacy barrier")
			}
			if e = s.Reindex(ctx); e == nil {
				t.Fatal("reindex cleared privacy barrier")
			}
		})
	}
}

func lateProducerPlan(t *testing.T, extra int, availabilityPath bool) (*producerFixture, CaptureRequest, CommitPlan, SignedRecord) {
	t.Helper()
	f := newProducer(t, "late proof original")
	f.commit()
	original, oldPage := f.plan.NewRecords[0], f.plan.NewRecords[1]
	r, e := record.Parse(original.HeaderJCS, original.BodyJCS, original.AdvisoryID)
	if e != nil {
		t.Fatal(e)
	}
	event := r.Body.(*record.ChunkBody).Events[0]
	q := f.q
	q.ExpectedVersion = 1
	settled := int64(0)
	if availabilityPath {
		id, e := record.EventID(f.q.Occurrence.SessionKey, "user_prompt", record.Anchor{NativeItemID: "additional-event"})
		if e != nil {
			t.Fatal(e)
		}
		event = f.event(id, 1, "additional late proof")
		q.EventIDs = append(append([]string(nil), q.EventIDs...), id)
		q.Range.LastExclusive = 2
		settled = 1
	}
	replacement := f.chunk([]record.Event{event}, []string{original.AdvisoryID})
	page := f.page([]string{original.AdvisoryID, replacement.AdvisoryID}, settled, oldPage.AdvisoryID)
	cause := f.w.control(19001, record.KindErasure, replacement.AdvisoryID)
	f.w.append(cause)
	if availabilityPath {
		f.w.append(f.chunk([]record.Event{event}, nil))
	}
	var copies []SignedRecord
	for i := 0; i < extra; i++ {
		copies = append(copies, f.chunk([]record.Event{event}, nil))
	}
	if len(copies) > 0 {
		f.w.seedPending(copies)
	}
	plan := CommitPlan{NewRecords: []SignedRecord{replacement, page}, ReuseRecordIDs: []string{original.AdvisoryID}, Next: f.plan.Next}
	plan.Next.SettledThrough = settled
	plan.Next.Range = q.Range
	plan.Next.LastSourceRecordIDs = []string{replacement.AdvisoryID}
	if availabilityPath {
		plan.Next.LastSourceRecordIDs = []string{original.AdvisoryID, replacement.AdvisoryID}
	}
	plan.Next.SessionPageIDs = []PageRef{{0, page.AdvisoryID}}
	return f, q, plan, cause
}
func TestProducerLateErasureAvailabilityRefusalAlsoHoldsOwner(t *testing.T) {
	f, q, p, cause := lateProducerPlan(t, 0, true)
	ctx := context.Background()
	_, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil })
	var held *Error
	if !errors.As(e, &held) || held.Code != "privacy_hold_required" || !held.OwnerBlocked {
		t.Fatal("availability refusal lost accepted proof", e)
	}
	var reason, control string
	if f.w.s.conn.QueryRowContext(ctx, "SELECT reason,control FROM privacy_barrier").Scan(&reason, &control) != nil || reason != "late_erasure_discovery" || control != cause.AdvisoryID {
		t.Fatal("wrong hold", reason, control)
	}
}
func TestProducerLateErasureInvalidCryptoCannotCreateBarrier(t *testing.T) {
	for _, extra := range []int{0, 1001} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			f, q, p, _ := lateProducerPlan(t, extra, false)
			ctx := context.Background()
			p.NewRecords = append([]SignedRecord(nil), p.NewRecords...)
			p.NewRecords[1].Sigs = append([]record.Signature(nil), p.NewRecords[1].Sigs...)
			p.NewRecords[1].Sigs[0].Value = strings.Repeat("A", 86)
			if _, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil }); Code(e) != "unauthorized_record" {
				t.Fatal("invalid crypto gate", e)
			}
			var n int
			if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&n) != nil || n != 0 {
				t.Fatal("failed crypto created owner barrier")
			}
			if len(find(f.w.snapshot(), f.plan.NewRecords[0].AdvisoryID).BodyJCS) == 0 {
				t.Fatal("failed crypto purged accepted content")
			}
		})
	}
}

func TestProducerLateErasureWithoutPreviouslyLiveBodiesDoesNotCreateBarrier(t *testing.T) {
	f := newProducer(t, "never admitted")
	ctx := context.Background()
	f.w.append(f.w.control(19002, record.KindErasure, f.plan.NewRecords[0].AdvisoryID))
	if _, e := f.w.s.Capture(ctx, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil }); Code(e) != "unavailable_candidate" {
		t.Fatal(e)
	}
	var n int
	if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&n) != nil || n != 0 {
		t.Fatal("new-only refusal froze owner")
	}
	p, e := f.w.s.InspectCapture(ctx, f.q.Occurrence)
	if e != nil || p.Progress.Version != 0 || p.Suppression.OwnerBlocked {
		t.Fatal("new-only refusal progressed", p, e)
	}
}
func TestProducerLateErasureMultipleAcceptedCausesKeepLedgerUnchanged(t *testing.T) {
	f, q, p, c1 := lateProducerPlan(t, 0, false)
	ctx := context.Background()
	unrelated := f.w.task(29001, "unrelated erased body")
	f.w.append(unrelated)
	f.w.append(f.w.control(29002, record.KindErasure, unrelated.AdvisoryID))
	c2 := f.w.control(19003, record.KindErasure, p.NewRecords[0].AdvisoryID)
	f.w.append(c2)
	if _, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil }); Code(e) != "privacy_hold_required" {
		t.Fatal(e)
	}
	var chosen string
	if f.w.s.conn.QueryRowContext(ctx, "SELECT control FROM privacy_barrier").Scan(&chosen) != nil || chosen != c1.AdvisoryID && chosen != c2.AdvisoryID {
		t.Fatal("invented barrier cause")
	}
	var n int
	if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM tomb WHERE target=? AND kind='erased'", p.NewRecords[0].AdvisoryID).Scan(&n) != nil || n != 2 {
		t.Fatal("lost accepted cause")
	}
	if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect").Scan(&n) != nil || n != 1 {
		t.Fatal("partial charge or quota refund")
	}
}
func TestProducerLateErasureBarrierWriteAndCommitFaultsNeverClaimDurability(t *testing.T) {
	for _, phase := range []string{"insert", "generation", "jobs", "commit"} {
		t.Run(phase, func(t *testing.T) {
			f, q, p, _ := lateProducerPlan(t, 0, false)
			ctx := context.Background()
			before := f.w.snapshot()
			var setup []string
			switch phase {
			case "insert":
				setup = []string{"CREATE TRIGGER late_fault BEFORE INSERT ON privacy_barrier BEGIN SELECT RAISE(ABORT,'private barrier fault'); END"}
			case "generation":
				setup = []string{"CREATE TRIGGER late_fault BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT,'private barrier fault'); END"}
			case "jobs":
				setup = []string{"CREATE TRIGGER late_fault BEFORE DELETE ON projection_job BEGIN SELECT RAISE(ABORT,'private barrier fault'); END"}
			case "commit":
				setup = []string{"CREATE TABLE late_parent(id INTEGER PRIMARY KEY)", "CREATE TABLE late_child(id INTEGER REFERENCES late_parent(id) DEFERRABLE INITIALLY DEFERRED)", "CREATE TRIGGER late_fault AFTER INSERT ON privacy_barrier BEGIN INSERT INTO late_child VALUES(999); END"}
			}
			for _, sql := range setup {
				if _, e := f.w.s.conn.ExecContext(ctx, sql); e != nil {
					t.Fatal(e)
				}
			}
			got, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil })
			if e == nil || got.Status != "" {
				t.Fatal("failed hold acknowledged")
			}
			var held *Error
			if errors.As(e, &held) && held.OwnerBlocked {
				t.Fatal("uncommitted barrier claimed durable", held)
			}
			if phase == "commit" && Code(e) != "outcome_unknown" {
				t.Fatal("COMMIT failure was ordinary rollback", e)
			}
			var barriers, gen, receipts int64
			if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&barriers) != nil || barriers != 0 {
				t.Fatal("fault left barrier")
			}
			if f.w.s.conn.QueryRowContext(ctx, "SELECT generation FROM meta").Scan(&gen) != nil || gen != before.Generation {
				t.Fatal("fault changed generation")
			}
			if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM capture_transition").Scan(&receipts) != nil || receipts != 1 {
				t.Fatal("fault wrote receipt")
			}
			if _, e = f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { t.Fatal("poisoned handle minted"); return p, nil }); Code(e) != "outcome_unknown" {
				t.Fatal("fault did not poison producer", e)
			}
		})
	}
}
func TestProducerLateErasureLostRefusalAckIsStillBlockedAfterRecovery(t *testing.T) {
	f, q, p, _ := lateProducerPlan(t, 0, false)
	ctx := context.Background()
	// Intentionally discard the committed refusal ACK, then use normal recovery.
	_, _ = f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil })
	f.w.s.Close()
	s, e := Open(ctx, f.w.o)
	if e != nil {
		t.Fatal(e)
	}
	f.w.s = s
	if _, e = s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { t.Fatal("lost refusal ACK resealed"); return p, nil }); e == nil {
		t.Fatal("recovered owner hold lost")
	}
	inspected, e := s.InspectCapture(ctx, q.Occurrence)
	if e != nil || !inspected.Suppression.OwnerBlocked || inspected.Progress.Version != 1 {
		t.Fatal("lost refusal changed progress", inspected, e)
	}
}
