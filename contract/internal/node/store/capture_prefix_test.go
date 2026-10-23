package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

func shortenedProducerPlan(t *testing.T, extra int, erase bool) (*producerFixture, CaptureRequest, CommitPlan) {
	t.Helper()
	f := newProducer(t, "prefix first observation")
	id, e := record.EventID(f.q.Occurrence.SessionKey, "user_prompt", record.Anchor{NativeItemID: "prefix-second"})
	if e != nil {
		t.Fatal(e)
	}
	old, e := record.Parse(f.plan.NewRecords[0].HeaderJCS, f.plan.NewRecords[0].BodyJCS, "")
	if e != nil {
		t.Fatal(e)
	}
	first := old.Body.(*record.ChunkBody).Events[0]
	second := f.event(id, 1, "prefix second observation")
	f.q.EventIDs = append(append([]string(nil), f.q.EventIDs...), id)
	f.q.Range.LastExclusive = 2
	initial := f.chunk([]record.Event{first, second}, nil)
	initialPage := f.page([]string{initial.AdvisoryID}, 1, "")
	f.plan = CommitPlan{NewRecords: []SignedRecord{initial, initialPage}, Next: CaptureNext{SettledThrough: 1, LastSourceRecordIDs: []string{initial.AdvisoryID}, SessionPageIDs: []PageRef{{0, initialPage.AdvisoryID}}, Reader: f.q.Reader, RulesetFingerprint: f.q.RulesetFingerprint, Range: f.q.Range}}
	f.commit()
	replacement := f.chunk([]record.Event{first}, []string{initial.AdvisoryID})
	nextPage := f.page([]string{initial.AdvisoryID, replacement.AdvisoryID}, 0, initialPage.AdvisoryID)
	if erase {
		f.w.append(f.w.control(31001, record.KindErasure, replacement.AdvisoryID))
	}
	var copies []SignedRecord
	for i := 0; i < extra; i++ {
		copies = append(copies, f.chunk([]record.Event{first}, nil))
	}
	if len(copies) > 0 {
		f.w.seedPending(copies)
	}
	q := f.q
	q.ExpectedVersion = 1
	q.Range.LastExclusive = 1
	q.EventIDs = []string{first.ID}
	plan := CommitPlan{NewRecords: []SignedRecord{replacement, nextPage}, ReuseRecordIDs: []string{initial.AdvisoryID}, Next: CaptureNext{SettledThrough: 0, LastSourceRecordIDs: []string{replacement.AdvisoryID}, SessionPageIDs: []PageRef{{0, nextPage.AdvisoryID}}, Reader: q.Reader, RulesetFingerprint: q.RulesetFingerprint, Range: q.Range}}
	return f, q, plan
}
func TestProducerShortenedPrefixCannotDiscardVerifiedLateErasure(t *testing.T) {
	for _, extra := range []int{0, 1001} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			f, q, p := shortenedProducerPlan(t, extra, true)
			ctx := context.Background()
			var seq, gen, records, effects, bodies int64
			for _, v := range []struct {
				q string
				p *int64
			}{{"SELECT next_seq FROM meta", &seq}, {"SELECT generation FROM meta", &gen}, {"SELECT count(*) FROM record", &records}, {"SELECT count(*) FROM erasure_effect", &effects}, {"SELECT count(*) FROM record_body", &bodies}} {
				if f.w.s.conn.QueryRowContext(ctx, v.q).Scan(v.p) != nil {
					t.Fatal(v.q)
				}
			}
			result, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil })
			want := "privacy_hold_required"
			if extra > 0 {
				want = "bulk_confirmation_required"
			}
			var held *Error
			if !errors.As(e, &held) || held.Code != want || !held.OwnerBlocked {
				var n int
				f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&n)
				snapshot, read := f.w.s.Snapshot(ctx, ReadRequest{IDs: []string{f.plan.NewRecords[0].AdvisoryID}})
				state := "unknown"
				body := 0
				if read == nil && len(snapshot.Entries) == 1 {
					state = snapshot.Entries[0].State
					body = len(snapshot.Entries[0].BodyJCS)
				}
				t.Fatalf("shortened prefix discarded verified proof: code=%s barriers=%d originalState=%s bodyBytes=%d", Code(e), n, state, body)
			}
			if result.Status != "" || len(result.ActualRecordRefs) != 0 {
				t.Fatal("refusal exposed candidate facts")
			}
			for _, v := range []struct {
				q    string
				want int64
			}{{"SELECT next_seq FROM meta", seq}, {"SELECT generation FROM meta", gen + 1}, {"SELECT count(*) FROM record", records}, {"SELECT count(*) FROM erasure_effect", effects}, {"SELECT count(*) FROM record_body", bodies}, {"SELECT count(*) FROM capture_transition", 1}, {"SELECT count(*) FROM capture_progress WHERE version=1 AND settled=1", 1}} {
				var n int64
				if f.w.s.conn.QueryRowContext(ctx, v.q).Scan(&n) != nil || n != v.want {
					t.Fatal("nonminimal shortened-prefix refusal", v.q, n, v.want)
				}
			}
		})
	}
}
func TestProducerShortenedPrefixBadCryptoAndNoLateProofRemainRollback(t *testing.T) {
	for _, badCrypto := range []bool{false, true} {
		t.Run(fmt.Sprint(badCrypto), func(t *testing.T) {
			f, q, p := shortenedProducerPlan(t, 0, badCrypto)
			ctx := context.Background()
			want := "invalid_plan"
			if badCrypto {
				p.NewRecords = append([]SignedRecord(nil), p.NewRecords...)
				p.NewRecords[1].Sigs = append([]record.Signature(nil), p.NewRecords[1].Sigs...)
				p.NewRecords[1].Sigs[0].Value = strings.Repeat("A", 86)
				want = "unauthorized_record"
			}
			if _, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil }); Code(e) != want {
				t.Fatal("prefix negative gate", Code(e))
			}
			var n int
			if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&n) != nil || n != 0 {
				t.Fatal("untrusted or unneeded prefix refusal froze owner")
			}
			i, e := f.w.s.InspectCapture(ctx, q.Occurrence)
			if e != nil || i.Progress.Version != 1 || i.Progress.SettledThrough != 1 || i.Suppression.OwnerBlocked {
				t.Fatal("ordinary prefix refusal advanced", i, e)
			}
		})
	}
}
