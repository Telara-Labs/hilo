package store

import (
	"bytes"
	"context"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"testing"
)

func TestDisclosureAdmissionFencePreservesAncestorsAndPreexistingHeader(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	ancestor := k.task(300, "pre-exposure ancestor")
	k.append(ancestor)
	root := k.task(301, "root", ancestor.AdvisoryID)
	k.append(root)
	full := k.task(302, "body learned after fence")
	header := full
	header.BodyJCS = nil
	original := k.append(header)
	reply := k.execute("lookup-fence", "local.lookup_record", map[string]any{"record_id": root.AdvisoryID})
	k.release(reply)
	var fence int64
	k.s.conn.QueryRowContext(ctx, "SELECT max(fence) FROM exposure WHERE root=?", root.AdvisoryID).Scan(&fence)
	if original.Sequence > fence {
		t.Fatal("fixture not pre-fence")
	}
	enriched := k.append(full)
	if !enriched.Duplicate || enriched.Sequence != original.Sequence {
		t.Fatal("enrichment changed first admission")
	}
	var n int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM exposure_affect WHERE target IN(?,?,?)", root.AdvisoryID, ancestor.AdvisoryID, full.AdvisoryID).Scan(&n)
	if n != 0 {
		t.Fatal("new self/ancestor/preexisting-header edge", n)
	}
	// Observation wall time is older. Durable first admission is still after F.
	f := producerFor(k.world, "delayed capture")
	for i, in := range f.plan.NewRecords {
		r, err := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
		if err != nil {
			t.Fatal(err)
		}
		h := r.Header
		h.At = 1
		rr, err := record.Build(h, r.Body, bytes.Repeat([]byte{18}, 32))
		if err != nil {
			t.Fatal(err)
		}
		sg, err := sig.SignRecord(k.key, rr.ID)
		if err != nil {
			t.Fatal(err)
		}
		f.plan.NewRecords[i] = wire(rr, []record.Signature{sg})
	}
	// Rebuild exact page membership after changing the signed chunk identity.
	cr, err := record.Parse(f.plan.NewRecords[0].HeaderJCS, f.plan.NewRecords[0].BodyJCS, "")
	if err != nil {
		t.Fatal(err)
	}
	page := f.page([]string{cr.ID}, 0, "")
	f.plan.NewRecords[1] = page
	f.plan.Next.LastSourceRecordIDs = []string{cr.ID}
	f.plan.Next.SessionPageIDs = []PageRef{{0, page.AdvisoryID}}
	receipt := f.commit()
	for _, ref := range receipt.ActualRecordRefs {
		if ref.Sequence <= fence {
			t.Fatal("delayed record reused pre-fence ordinal")
		}
	}
	k.append(k.control(303, record.KindErasure, root.AdvisoryID))
	for _, id := range []string{ancestor.AdvisoryID, full.AdvisoryID} {
		v := find(k.snapshot(), id)
		if v.State != "live" || len(v.BodyJCS) == 0 {
			t.Fatal("erasure crossed first-admission fence", id, v.State)
		}
	}
	for _, ref := range receipt.ActualRecordRefs {
		var state string
		k.s.conn.QueryRowContext(ctx, "SELECT state FROM record WHERE id=?", ref.ID).Scan(&state)
		if state != "lineage-hold" {
			t.Fatal("delayed capture bypassed exposure", state)
		}
	}
}
func TestDisclosureSameTransactionOutputCannotBecomeOwnExposureAncestor(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	r := k.execute("same-tx", "local.create_task", map[string]any{"goal": "one atomic task"})
	var root, call string
	var rootSeq, callSeq, fence int64
	k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=?", r.op).Scan(&root)
	k.s.conn.QueryRowContext(ctx, "SELECT call_id FROM operation WHERE op=?", r.op).Scan(&call)
	k.s.conn.QueryRowContext(ctx, "SELECT seq FROM record WHERE id=?", root).Scan(&rootSeq)
	k.s.conn.QueryRowContext(ctx, "SELECT seq FROM record WHERE id=?", call).Scan(&callSeq)
	k.s.conn.QueryRowContext(ctx, "SELECT min(fence) FROM exposure WHERE root=?", root).Scan(&fence)
	if fence < rootSeq || fence < callSeq {
		t.Fatal("fence ignored staged output", fence, rootSeq, callSeq)
	}
	var n int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM exposure_affect WHERE target IN(?,?)", root, call).Scan(&n)
	if n != 0 {
		t.Fatal("same transaction created semantic cycle")
	}
}
func TestDisclosureSemanticErasureBudgetExactUnionAndNoRefund(t *testing.T) {
	for _, total := range []int{999, 1000, 1001} {
		t.Run(fmt.Sprint(total), func(t *testing.T) {
			k := newKernel(t)
			ctx := context.Background()
			root := k.task(7000, "budget root")
			k.append(root)
			r := k.execute("budget-lookup", "local.lookup_record", map[string]any{"record_id": root.AdvisoryID})
			k.release(r)
			var inputs []SignedRecord
			for i := 0; i < total-1; i++ {
				var deps []string
				if i == 0 {
					deps = []string{root.AdvisoryID}
				}
				inputs = append(inputs, k.task(7100+i, "future output", deps...))
			}
			k.seedPending(inputs)
			before := k.snapshot()
			control := k.control(8000, record.KindErasure, root.AdvisoryID)
			_, err := k.s.Append(ctx, control)
			if total > 1000 {
				if Code(err) != "bulk_confirmation_required" {
					t.Fatal(err)
				}
				var n int
				k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&n)
				if n != 0 {
					t.Fatal("unaccepted oversized control froze owner")
				}
				after := k.snapshot()
				if before.Generation != after.Generation || len(before.Entries) != len(after.Entries) {
					t.Fatal("oversized control partially committed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var n int
			k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect WHERE control=?", control.AdvisoryID).Scan(&n)
			if n != total {
				t.Fatal("hold+tomb union not charged exactly once", n, total)
			}
			copied := inputs[0].AdvisoryID
			k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect WHERE control=? AND target=?", control.AdvisoryID, copied).Scan(&n)
			if n != 1 {
				t.Fatal("tomb and hold double charged")
			}
			for _, in := range inputs[1:] {
				var state string
				k.s.conn.QueryRowContext(ctx, "SELECT state FROM record WHERE id=?", in.AdvisoryID).Scan(&state)
				if state != "lineage-hold" {
					t.Fatal("future output not held", state)
				}
			}
			if err = k.s.Reindex(ctx); err != nil {
				t.Fatal(err)
			}
			k.s.Close()
			st, err := Open(ctx, k.o)
			if err != nil {
				t.Fatal(err)
			}
			k.s = st
			if _, err = k.s.Append(ctx, control); err != nil {
				t.Fatal("duplicate control changed budget", err)
			}
			if total == 999 {
				next := k.control(8001, record.KindErasure, inputs[1].AdvisoryID)
				if _, err = k.s.Append(ctx, next); err != nil {
					t.Fatal("exact1000 second cause refused", err)
				}
				k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect WHERE target=?", inputs[1].AdvisoryID).Scan(&n)
				if n != 2 {
					t.Fatal("different causes collapsed", n)
				}
			}
			if _, err = k.s.Append(ctx, k.control(8002, record.KindErasure, inputs[2].AdvisoryID)); Code(err) != "bulk_confirmation_required" {
				t.Fatal("lifetime counter refunded after hold/erase/reopen", err)
			}
		})
	}
}
func TestDisclosureLateSemanticProofBudgetBarrierHasNoCandidateBytes(t *testing.T) {
	// A post-fence source arrives with a copied dependency on an erased root. Its
	// semantic downstream copies were already live under older independent IDs.
	// The existing producer late-proof fixture exercises closure refusal; adding
	// an actual durable disclosure root tests the shared hold/tomb budget path.
	for _, extra := range []int{0, 1001} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			f, q, p, _ := lateProducerPlan(t, extra, false)
			k := newKernelForWorld(f.w)
			ctx := context.Background()
			r := k.execute("expose-existing-copy", "local.lookup_record", map[string]any{"record_id": f.plan.NewRecords[0].AdvisoryID})
			k.release(r)
			var beforeRecords, beforeEffects, beforeSeq int
			k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record").Scan(&beforeRecords)
			k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect").Scan(&beforeEffects)
			k.s.conn.QueryRowContext(ctx, "SELECT next_seq FROM meta").Scan(&beforeSeq)
			_, err := k.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil })
			held, ok := err.(*Error)
			if !ok || !held.OwnerBlocked {
				t.Fatal("trusted late proof lost after durable exposure", err)
			}
			for _, row := range []struct {
				q    string
				want int
			}{{"SELECT count(*) FROM record", beforeRecords}, {"SELECT count(*) FROM erasure_effect", beforeEffects}, {"SELECT next_seq FROM meta", beforeSeq}} {
				var got int
				k.s.conn.QueryRowContext(ctx, row.q).Scan(&got)
				if got != row.want {
					t.Fatal("partial semantic proof persisted", row.q, got, row.want)
				}
			}
			for _, in := range p.NewRecords {
				var n int
				k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record WHERE id=?", in.AdvisoryID).Scan(&n)
				if n != 0 {
					t.Fatal("refused proof header persisted")
				}
			}
			var body []byte
			k.s.conn.QueryRowContext(ctx, "SELECT body FROM record_body WHERE id=?", p.NewRecords[0].AdvisoryID).Scan(&body)
			if len(body) != 0 {
				t.Fatal("candidate body retained")
			}
			if bytes.Contains(body, []byte("canary")) {
				t.Fatal("canary retained")
			}
		})
	}
}
