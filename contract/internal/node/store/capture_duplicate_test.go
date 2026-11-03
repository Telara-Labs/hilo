package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
)

func duplicateLatePlan(t *testing.T, extra int) (*producerFixture, CaptureRequest, CommitPlan) {
	t.Helper()
	f, q, p, _ := lateProducerPlan(t, extra, false)
	r, e := record.Parse(f.plan.NewRecords[0].HeaderJCS, f.plan.NewRecords[0].BodyJCS, "")
	if e != nil {
		t.Fatal(e)
	}
	u := f.chunk(r.Body.(*record.ChunkBody).Events, nil)
	f.w.append(u)
	page := f.page([]string{f.plan.NewRecords[0].AdvisoryID, p.NewRecords[0].AdvisoryID, u.AdvisoryID}, 0, f.plan.NewRecords[1].AdvisoryID)
	p.NewRecords[1] = page
	p.NewRecords = append(p.NewRecords, u)
	p.Next.SessionPageIDs = []PageRef{{0, page.AdvisoryID}}
	return f, q, p
}
func TestProducerExistingNewDeclarationCannotDiscardLateErasure(t *testing.T) {
	for _, extra := range []int{0, 1001} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			f, q, p := duplicateLatePlan(t, extra)
			ctx := context.Background()
			before := f.w.snapshot()
			var count, seq, body, effects int64
			for _, x := range []struct {
				q string
				p *int64
			}{{"SELECT count(*) FROM record", &count}, {"SELECT next_seq FROM meta", &seq}, {"SELECT count(*) FROM record_body", &body}, {"SELECT count(*) FROM erasure_effect", &effects}} {
				if f.w.s.conn.QueryRowContext(ctx, x.q).Scan(x.p) != nil {
					t.Fatal(x.q)
				}
			}
			got, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil })
			var held *Error
			want := "privacy_hold_required"
			if extra > 0 {
				want = "bulk_confirmation_required"
			}
			if !errors.As(e, &held) || held.Code != want || !held.OwnerBlocked {
				var n int
				f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&n)
				snapshot, read := f.w.s.Snapshot(ctx, ReadRequest{IDs: []string{f.plan.NewRecords[0].AdvisoryID}})
				state := "unknown"
				bodyBytes := 0
				if read == nil && len(snapshot.Entries) == 1 {
					state = snapshot.Entries[0].State
					bodyBytes = len(snapshot.Entries[0].BodyJCS)
				}
				t.Fatalf("existing New declaration lost trusted proof: code=%s barriers=%d originalState=%s bodyBytes=%d", Code(e), n, state, bodyBytes)
			}
			if got.Status != "" || len(got.ActualRecordRefs) != 0 {
				t.Fatal("duplicate refusal acknowledged records")
			}
			for _, x := range []struct {
				q    string
				want int64
			}{{"SELECT count(*) FROM record", count}, {"SELECT next_seq FROM meta", seq}, {"SELECT count(*) FROM record_body", body}, {"SELECT count(*) FROM erasure_effect", effects}, {"SELECT generation FROM meta", before.Generation + 1}, {"SELECT count(*) FROM capture_transition", 1}} {
				var n int64
				if f.w.s.conn.QueryRowContext(ctx, x.q).Scan(&n) != nil || n != x.want {
					t.Fatal("duplicate refusal changed SQL truth", x.q, n, x.want)
				}
			}
		})
	}
}
func TestProducerDuplicateBodylessCandidateSuppliesTransientPrivacyFacts(t *testing.T) {
	f := newProducer(t, "bodyless dependency observation")
	ctx := context.Background()
	originalQuery := f.q
	foreignSession, e := record.SessionKey("claude-code", "local", record.NativeGlobal, "33333333-3333-4333-8333-333333333333", testMachine)
	if e != nil {
		t.Fatal(e)
	}
	foreignID, e := record.EventID(foreignSession, "user_prompt", record.Anchor{NativeItemID: "foreign-prior"})
	if e != nil {
		t.Fatal(e)
	}
	foreignEvent := f.event(foreignID, 0, "erasable other-session observation")
	f.q.Occurrence.SessionKey = foreignSession
	f.q.Occurrence.Source = record.H("foreign-source")
	foreign := f.chunk([]record.Event{foreignEvent}, nil)
	f.w.append(foreign)
	f.q = originalQuery
	unknown := f.build(record.KindSession, record.SessionLID(f.q.Occurrence.SessionKey, testMachine, 0), &record.SessionBody{NativeID: "22222222-2222-4222-8222-222222222222", NativeIDKind: record.NativeGlobal, Chunks: []string{foreign.AdvisoryID}, Reader: &f.q.Reader}, record.Links{})
	headerOnly := unknown
	headerOnly.BodyJCS = nil
	f.w.append(headerOnly)
	old, e := record.Parse(f.plan.NewRecords[0].HeaderJCS, f.plan.NewRecords[0].BodyJCS, "")
	if e != nil {
		t.Fatal(e)
	}
	baseline := f.chunk(old.Body.(*record.ChunkBody).Events, []string{unknown.AdvisoryID})
	f.w.append(baseline)
	page := f.page([]string{baseline.AdvisoryID}, 0, unknown.AdvisoryID)
	f.w.append(page)
	f.plan = CommitPlan{ReuseRecordIDs: []string{baseline.AdvisoryID, page.AdvisoryID}, Next: CaptureNext{SettledThrough: 0, LastSourceRecordIDs: []string{baseline.AdvisoryID}, SessionPageIDs: []PageRef{{0, page.AdvisoryID}}, Reader: f.q.Reader, RulesetFingerprint: f.q.RulesetFingerprint, Range: f.q.Range}}
	f.commit()
	f.w.append(f.w.control(32001, record.KindErasure, foreign.AdvisoryID))
	if len(find(f.w.snapshot(), baseline.AdvisoryID).BodyJCS) == 0 {
		t.Fatal("baseline was not previously eligible")
	}
	q := f.q
	q.ExpectedVersion = 1
	plan := f.plan
	plan.NewRecords = []SignedRecord{unknown}
	_, e = f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return plan, nil })
	var held *Error
	if !errors.As(e, &held) || held.Code != "privacy_hold_required" || !held.OwnerBlocked {
		var n int
		f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&n)
		t.Fatalf("valid duplicate unknown body facts were ignored: code=%s barriers=%d", Code(e), n)
	}
	var n int
	if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_body WHERE id=?", unknown.AdvisoryID).Scan(&n) != nil || n != 0 {
		t.Fatal("duplicate body was refilled")
	}
	if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM body_seen WHERE id=?", unknown.AdvisoryID).Scan(&n) != nil || n != 0 {
		t.Fatal("transient proof persisted body admission")
	}
	if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM dep WHERE id=? AND parent=?", unknown.AdvisoryID, foreign.AdvisoryID).Scan(&n) != nil || n != 0 {
		t.Fatal("transient body facts persisted")
	}
}
func TestProducerExistingNewBadCryptoCannotSupplyPrivacyProof(t *testing.T) {
	f, q, p := duplicateLatePlan(t, 0)
	ctx := context.Background()
	p.NewRecords = append([]SignedRecord(nil), p.NewRecords...)
	p.NewRecords[2].Sigs = append([]record.Signature(nil), p.NewRecords[2].Sigs...)
	p.NewRecords[2].Sigs[0].Value = strings.Repeat("A", 86)
	if _, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil }); Code(e) != "unauthorized_record" {
		t.Fatal("invalid duplicate crypto was not rejected", Code(e))
	}
	var n int
	if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&n) != nil || n != 0 {
		t.Fatal("invalid duplicate crypto froze owner")
	}
}

func TestProducerExistingNewWithoutLateProofIsNeverAdmittedOrRefilled(t *testing.T) {
	f := newProducer(t, "ordinary existing declaration")
	f.commit()
	ctx := context.Background()
	before := f.w.snapshot()
	q := f.q
	q.ExpectedVersion = 1
	p := CommitPlan{NewRecords: []SignedRecord{f.plan.NewRecords[0]}, ReuseRecordIDs: []string{f.plan.NewRecords[1].AdvisoryID}, Next: f.plan.Next}
	if _, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil }); Code(e) != "invalid_plan" {
		t.Fatal("duplicate declaration was admitted", Code(e))
	}
	after := f.w.snapshot()
	if len(after.Entries) != len(before.Entries) || after.Generation != before.Generation {
		t.Fatal("ordinary duplicate changed records")
	}
	i, e := f.w.s.InspectCapture(ctx, q.Occurrence)
	if e != nil || i.Progress.Version != 1 || i.Suppression.OwnerBlocked {
		t.Fatal("ordinary duplicate progressed or froze owner")
	}
}
