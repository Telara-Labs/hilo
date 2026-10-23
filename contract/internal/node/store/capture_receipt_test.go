package store

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

func TestProducerMaximumReceiptRefsSurviveReopenAndErasure(t *testing.T) {
	for _, newChunks := range []int{33, 48} {
		t.Run(fmt.Sprintf("refs%d", newChunks+16+80), func(t *testing.T) {
			f := newProducer(t, "receipt seed")
			ctx := context.Background()
			var events []record.Event
			f.q.EventIDs = nil
			f.q.Range.LastExclusive = 64
			for i := 0; i < 64; i++ {
				id, e := record.EventID(f.q.Occurrence.SessionKey, "user_prompt", record.Anchor{NativeItemID: fmt.Sprintf("receipt-event-%d", i)})
				if e != nil {
					t.Fatal(e)
				}
				f.q.EventIDs = append(f.q.EventIDs, id)
				events = append(events, f.event(id, int64(i), fmt.Sprintf("protected observation %d", i)))
			}
			page := func(index int, ids []string, prev string) SignedRecord {
				l := record.Links{Prev: prev}
				if prev != "" {
					l.Supersedes = []string{prev}
				}
				return f.build(record.KindSession, record.SessionLID(f.q.Occurrence.SessionKey, testMachine, int64(index)), &record.SessionBody{NativeID: "22222222-2222-4222-8222-222222222222", NativeIDKind: record.NativeGlobal, Page: int64(index), Chunks: ids, SettledThrough: 63, Reader: &f.q.Reader}, l)
			}
			baseline := f.chunk(events, nil)
			var initialPages []SignedRecord
			initial := CommitPlan{NewRecords: []SignedRecord{baseline}, Next: CaptureNext{SettledThrough: 63, LastSourceRecordIDs: []string{baseline.AdvisoryID}, Reader: f.q.Reader, RulesetFingerprint: f.q.RulesetFingerprint, Range: f.q.Range}}
			for i := 0; i < 16; i++ {
				var chunks []string
				if i == 0 {
					chunks = []string{baseline.AdvisoryID}
				}
				p := page(i, chunks, "")
				initialPages = append(initialPages, p)
				initial.NewRecords = append(initial.NewRecords, p)
				initial.Next.SessionPageIDs = append(initial.Next.SessionPageIDs, PageRef{int64(i), p.AdvisoryID})
			}
			f.plan = initial
			f.commit()
			// Valid signed historical wrappers, verified by the existing bulk fixture
			// helper against real SQLite, let the plan exercise all80 reuse references.
			type member struct {
				r   SignedRecord
				seq int64
			}
			var old []member
			for i := 0; i < 80; i++ {
				ev := events[i%64]
				old = append(old, member{f.chunk([]record.Event{ev}, []string{baseline.AdvisoryID}), ev.Seq})
			}
			sort.Slice(old, func(i, j int) bool {
				if old[i].seq != old[j].seq {
					return old[i].seq < old[j].seq
				}
				return old[i].r.AdvisoryID < old[j].r.AdvisoryID
			})
			var seeded []SignedRecord
			for _, m := range old {
				seeded = append(seeded, m.r)
			}
			var oldPages []SignedRecord
			oldIDs := make([][]string, 16)
			for i := 0; i < 16; i++ {
				for _, m := range old[i*5 : (i+1)*5] {
					oldIDs[i] = append(oldIDs[i], m.r.AdvisoryID)
				}
				p := page(i, oldIDs[i], initialPages[i].AdvisoryID)
				oldPages = append(oldPages, p)
				seeded = append(seeded, p)
			}
			f.w.seedPending(seeded)
			plan := CommitPlan{Next: CaptureNext{SettledThrough: 63, Reader: f.q.Reader, RulesetFingerprint: f.q.RulesetFingerprint, Range: f.q.Range}}
			for _, m := range old {
				plan.ReuseRecordIDs = append(plan.ReuseRecordIDs, m.r.AdvisoryID)
			}
			pages := make([][]member, 16)
			for i := range pages {
				pages[i] = append(pages[i], old[i*5:(i+1)*5]...)
			}
			at := 0
			for i := 0; i < newChunks; i++ {
				n := 1
				if i < 64-newChunks {
					n = 2
				}
				chunk := f.chunk(events[at:at+n], []string{baseline.AdvisoryID})
				plan.NewRecords = append(plan.NewRecords, chunk)
				plan.Next.LastSourceRecordIDs = append(plan.Next.LastSourceRecordIDs, chunk.AdvisoryID)
				dest := 15
				for j := 0; j < 16; j++ {
					if events[at].Seq <= old[(j+1)*5-1].seq {
						dest = j
						break
					}
				}
				pages[dest] = append(pages[dest], member{chunk, events[at].Seq})
				at += n
			}
			for i := 0; i < 16; i++ {
				sort.Slice(pages[i], func(a, b int) bool {
					if pages[i][a].seq != pages[i][b].seq {
						return pages[i][a].seq < pages[i][b].seq
					}
					return pages[i][a].r.AdvisoryID < pages[i][b].r.AdvisoryID
				})
				var ids []string
				for _, m := range pages[i] {
					ids = append(ids, m.r.AdvisoryID)
				}
				p := page(i, ids, oldPages[i].AdvisoryID)
				plan.NewRecords = append(plan.NewRecords, p)
				plan.Next.SessionPageIDs = append(plan.Next.SessionPageIDs, PageRef{int64(i), p.AdvisoryID})
			}
			q := f.q
			q.ExpectedVersion = 1
			first, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return plan, nil })
			want := newChunks + 16 + 80
			if e != nil || first.Status != "committed" || len(first.ActualRecordRefs) != want {
				t.Fatal("large valid plan", want, len(first.ActualRecordRefs), e)
			}
			reopen := func() {
				f.w.s.Close()
				s, e := Open(ctx, f.w.o)
				if e != nil {
					t.Fatal(e)
				}
				f.w.s = s
			}
			reopen()
			replay, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) {
				t.Fatal("large receipt replay minted")
				return CommitPlan{}, nil
			})
			if e != nil || replay.Status != "prior_transition_committed" || len(replay.ActualRecordRefs) != want || replay.TransitionID != first.TransitionID {
				t.Fatal("large committed receipt lost after recovery", len(replay.ActualRecordRefs), e)
			}
			if newChunks == 48 {
				bad := plan
				bad.NewRecords = append(append([]SignedRecord(nil), plan.NewRecords...), plan.NewRecords[0])
				request := q
				request.ExpectedVersion = 2
				got, e := f.w.s.Capture(ctx, request, func(*CaptureTxn) (CommitPlan, error) { return bad, nil })
				if Code(e) != "invalid_plan" || got.Status != "" {
					t.Fatal("145reference plan accepted", got, e)
				}
				inspection, e := f.w.s.InspectCapture(ctx, q.Occurrence)
				if e != nil || inspection.Progress.Version != 2 {
					t.Fatal("145refusal progressed", inspection, e)
				}
			}
			f.w.append(f.w.control(18001, record.KindErasure, plan.NewRecords[0].AdvisoryID))
			reopen()
			replay, e = f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) {
				t.Fatal("erased large receipt replay minted")
				return CommitPlan{}, nil
			})
			if e != nil || len(replay.ActualRecordRefs) != want || replay.ResultingProgress.Version != 2 {
				t.Fatal("erasure lost large receipt", len(replay.ActualRecordRefs), e)
			}
			if replay.CurrentAvailability[plan.NewRecords[0].AdvisoryID] == "available" {
				t.Fatal("erased large receipt lies about body")
			}
		})
	}
}
