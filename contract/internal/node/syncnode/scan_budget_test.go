package syncnode

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// fillerErasure erases an id that no device holds; it is a valid control
// that completes at once and occupies one page at page size one.
func fillerErasure(w *world, n int) record.Envelope {
	w.t.Helper()
	return w.control(1000+n, record.KindErasure, record.H("filler", fmt.Sprint(n)))
}

// With page size one, 256 valid controls fill one round's page budget and an
// erasure of restored data sits on page 257. The first round enforces and
// acknowledges exactly the fetched prefix but keeps the restore fence, data
// pull and push: the HELLO snapshot is not fully scanned. A restart resumes
// from the durable pending state; only the round that reaches the head and
// enforces the erasure releases the fence, and the restored record is never
// served before its erasure.
func TestPartialControlScanKeepsRestoreAndDataFences(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.hosted.pageLimit = 1
	task := w.task(1, repoA, "active")
	p := w.enroll()
	sel, err := w.st.SelectBundle(ctx, []string{task.ID})
	if err != nil || len(sel.Data) != 1 {
		t.Fatal(sel, err)
	}
	if report, err := w.st.ImportBundle(ctx, store.BundleImport{LocalKeyID: w.genesis, Keyring: sel.Keyring, Data: sel.Data}); err != nil || !report.Fenced {
		t.Fatal("restore not fenced", report, err)
	}
	var last int64
	for i := 0; i < maxPages; i++ {
		last = w.hosted.addControl(fillerErasure(w, i))
	}
	he := w.hosted.addControl(w.control(1, record.KindErasure, task.ID))
	hd := w.hosted.addData(w.foreignData(1))

	wk := w.worker()
	w.selectRepo(wk, repoA)
	if err := wk.Round(ctx); !errors.Is(err, ErrControlScanIncomplete) {
		t.Fatalf("budget-limited round: %v", err)
	}
	c := cursorsOf(t, wk, p)
	if c.Ctl != last || c.Data != 0 {
		t.Fatalf("partial round cursors %+v, want ctl %d data 0", c, last)
	}
	if acks := w.hosted.ackList(); len(acks) == 0 || acks[len(acks)-1].CtlEnforcedThrough != last {
		t.Fatalf("partial round ack %+v", acks)
	}
	if fenced, err := w.st.RestorePending(ctx); err != nil || !fenced {
		t.Fatalf("restore fence released by a partial scan: %v %v", fenced, err)
	}
	if state, _ := entryState(t, w.st, task.ID); state == "invalidated" {
		t.Fatal("fixture: erasure enforced before it was fetched")
	}

	wk = w.restart(wk)
	if err := wk.Round(ctx); err != nil {
		t.Fatalf("completing round: %v", err)
	}
	c = cursorsOf(t, wk, p)
	if c.Ctl != he || c.Data != hd {
		t.Fatalf("completing round cursors %+v, want ctl %d data %d", c, he, hd)
	}
	if fenced, err := w.st.RestorePending(ctx); err != nil || fenced {
		t.Fatalf("restore fence not released by the complete scan: %v %v", fenced, err)
	}
	if state, body := entryState(t, w.st, task.ID); state != "invalidated" || body {
		t.Fatalf("restored record survived its erasure: %s body=%v", state, body)
	}
}

// B's id-only erasure c1 is coverage-pending on A at page 1, and the
// supplement c2 lies beyond one round's page budget behind 256 further valid
// controls. Each round must resume after what it already holds, across a
// restart, rather than rescan the same capped prefix from below c1 forever;
// the late supplement then completes c1 and the ACK crosses it only after.
func TestLateSupplementBeyondThePageBudget(t *testing.T) {
	x := newX2Pair(t)
	a, b, h := x.a, x.b, x.h
	sk := x2SessionKey(t)
	const canary = "late_supplement_budget_canary_6f30"
	k, _, event := a.chunk(sk, canary, "late-budget")
	b.at = a.at + 10
	hc1 := h.addControl(erasureBy(t, b.key, b.machine, "late-c1", b.at, record.Selectors{IDs: []string{k.ID}}))
	for i := 0; i < maxPages; i++ {
		b.at++
		h.addControl(erasureBy(t, b.key, b.machine, fmt.Sprintf("late-filler-%d", i), b.at, record.Selectors{IDs: []string{record.H("filler", fmt.Sprint(i))}}))
	}
	b.at++
	hc2 := h.addControl(erasureBy(t, b.key, b.machine, "late-c2", b.at, record.Selectors{Events: []record.EventSelector{{Owner: a.genesis, SessionKey: sk, EventID: event}}}))

	wa := a.worker()
	x2Round(t, wa, ErrControlBlocked)
	x.heldBelow(t, wa, "first budget", 0, hc1)
	wa = a.restart(wa)
	x2Round(t, wa, nil)
	if c := cursorsOf(t, wa, x.pa); c.Ctl != hc2 || c.BarrierHSeq != 0 {
		t.Fatalf("late supplement never reached: %+v", c)
	}
	if ack := x.lastAck(t); ack.CtlEnforcedThrough != hc2 {
		t.Fatalf("final ack %+v", ack)
	}
	if n := erasurePending(t, a.dir); n != 0 {
		t.Fatalf("c1 still pending: %d", n)
	}
	assertNoCanary(t, a.dir, canary)
}
