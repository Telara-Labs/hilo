package syncnode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

func TestDisabledByDefaultSendsNothing(t *testing.T) {
	w := newWorld(t)
	w.task(1, repoA, "active")
	wk := w.worker()
	w.selectRepo(wk, repoA)
	if err := wk.Round(context.Background()); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("missing profile: %v", err)
	}
	p := w.enroll()
	if err := SetEnabled(w.dir, false); err != nil {
		t.Fatal(err)
	}
	if err := wk.Round(context.Background()); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("disabled profile: %v", err)
	}
	if n := len(w.hosted.imports()); n != 0 || w.hosted.mints != 0 || len(w.hosted.ackList()) != 0 {
		t.Fatalf("disabled sync contacted hosted: imports=%d mints=%d", n, w.hosted.mints)
	}
	if len(rows(t, wk, p)) != 0 {
		t.Fatal("disabled sync queued rows")
	}
}

// B11 default exact allowlist: only selected, granted task/session heads leave
// as push-metadata variants with {salt,status}; no source body or text.
func TestPushesOnlyMetadataVariantsWithVerifiedReceipts(t *testing.T) {
	w := newWorld(t)
	selected := w.task(1, repoA, "active")
	other := w.task(2, repoB, "active") // not selected and not granted
	p := w.enroll()
	wk := w.worker()
	w.selectRepo(wk, repoA)
	if err := wk.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	bodies := w.hosted.imports()
	if len(bodies) != 1 {
		t.Fatalf("imports %d", len(bodies))
	}
	if bytes.Contains(bodies[0], []byte("private")) {
		t.Fatal("source text left the node")
	}
	var req struct {
		OpID      string            `json:"op_id"`
		Envelopes []record.Envelope `json:"envelopes"`
	}
	if err := json.Unmarshal(bodies[0], &req); err != nil || len(req.Envelopes) != 1 {
		t.Fatalf("request %v %d", err, len(req.Envelopes))
	}
	rec, err := decodeEnvelope(req.Envelopes[0])
	if err != nil {
		t.Fatal(err)
	}
	h := rec.Header
	if h.Type != record.KindTask || h.Red.Profile != record.ProfilePushMetadata || h.Prov != record.ProvDerived || h.Links.Origin != selected.ID || h.LID != selected.Header.LID || h.Subj.RepoID != repoA {
		t.Fatalf("variant header %+v", h)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.BodyJCS, &body); err != nil || len(body) != 2 || body["status"] != "active" || body["salt"] == nil {
		t.Fatalf("variant body %s", rec.BodyJCS)
	}
	got := rows(t, wk, p)
	if got[selected.ID] != stateComplete || got[other.ID] != "" || len(got) != 1 {
		t.Fatalf("rows %v", got)
	}
	if n := count(t, wk, "SELECT count(*) FROM delivery_receipt WHERE destination=? AND record_id=?", destination(p.Scope()), rec.ID); n != 1 {
		t.Fatalf("receipts %d", n)
	}
	// Push results do not move data_cursor; HELLO's head predates the push.
	c := cursorsOf(t, wk, p)
	if c.Data != 0 || c.Ctl != 0 {
		t.Fatalf("cursor moved by push: %+v", c)
	}
	// The next round's own-only data tail advances the scan watermark with
	// nothing applied, and the ACK reports exactly the durable cursors.
	if err := wk.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	c = cursorsOf(t, wk, p)
	if c.Data != 1 || count(t, wk, "SELECT count(*) FROM data_quarantine") != 0 {
		t.Fatalf("own-only tail: %+v", c)
	}
	acks := w.hosted.ackList()
	if len(acks) != 2 || acks[0] != (transport.Ack{}) || acks[1] != (transport.Ack{CtlEnforcedThrough: 0, DataAppliedThrough: 1}) {
		t.Fatalf("acks %+v", acks)
	}
	if len(w.hosted.imports()) != 1 {
		t.Fatal("completed export was sent again")
	}
}

// V16: removing or editing a rule after queueing cancels its rows, and the
// cancelled rows are never sent.
func TestV16RuleRemovedOrEditedAfterQueueCancels(t *testing.T) {
	for _, edit := range []bool{false, true} {
		w := newWorld(t)
		task := w.task(1, repoA, "active")
		p := w.enroll()
		wk := w.worker()
		w.selectRepo(wk, repoA)
		ob := newOutbox(wk.state, w.st, p.Scope())
		if n, err := wk.export(context.Background(), p, ob); err != nil || n != 1 {
			t.Fatalf("export %d %v", n, err)
		}
		if edit {
			if _, err := wk.state.PutRule(context.Background(), "default", []string{repoA, repoB}, []string{"task"}, true); err != nil {
				t.Fatal(err)
			}
		} else if err := wk.state.RemoveRule(context.Background(), "default"); err != nil {
			t.Fatal(err)
		}
		if got := rows(t, wk, p)[task.ID]; got != stateCancelled {
			t.Fatalf("edit=%v row %s", edit, got)
		}
		if n := count(t, wk, "SELECT count(*) FROM outbox WHERE body IS NOT NULL AND state=?", stateCancelled); n != 0 {
			t.Fatal("cancelled row kept its metadata copy")
		}
		if err := wk.Round(context.Background()); err != nil {
			t.Fatal(err)
		}
		bodies := w.hosted.imports()
		if !edit && len(bodies) != 0 {
			t.Fatal("removed rule still sent")
		}
		if edit {
			// The edited rule re-exports with a fresh seal under its new version.
			if len(bodies) != 1 {
				t.Fatalf("edited rule imports %d", len(bodies))
			}
			if n := count(t, wk, "SELECT count(*) FROM outbox WHERE authority=? AND state=?", "rule:default@2", stateComplete); n != 1 {
				t.Fatal("new authority not recorded")
			}
		}
	}
}

// V16 and section 8.5: a rule changed between queueing and send, a source
// retracted or erased after queueing, and a policy-invalidated row are all
// cancelled at the pre-send revalidation, never transmitted.
func TestRevalidationBeforeSendCancels(t *testing.T) {
	for _, kind := range []record.Kind{record.KindRetraction, record.KindErasure} {
		w := newWorld(t)
		task := w.task(1, repoA, "active")
		p := w.enroll()
		wk := w.worker()
		w.selectRepo(wk, repoA)
		ob := newOutbox(wk.state, w.st, p.Scope())
		if _, err := wk.export(context.Background(), p, ob); err != nil {
			t.Fatal(err)
		}
		env := w.control(1, kind, task.ID)
		rec, err := decodeEnvelope(env)
		if err != nil {
			t.Fatal(err)
		}
		w.append(rec, env.Sigs)
		op, err := ob.Next(context.Background(), p.Scope(), nodesync.Limits{Records: 64, WireBytes: 1, DecodedBytes: 1})
		if err != nil || op == nil {
			t.Fatal(err)
		}
		ok, err := ob.Authorize(context.Background(), p.Scope(), op.OpID(), op.Digest())
		if err != nil || ok {
			t.Fatalf("%s: authorize %v %v", kind, ok, err)
		}
		if rows(t, wk, p)[task.ID] != stateCancelled {
			t.Fatal("not cancelled")
		}
		if err := wk.Round(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(w.hosted.imports()) != 0 {
			t.Fatalf("%s: invalidated source was sent", kind)
		}
	}
	// A rule row changed without the cancelling API is still caught at send.
	w := newWorld(t)
	task := w.task(1, repoA, "active")
	p := w.enroll()
	wk := w.worker()
	w.selectRepo(wk, repoA)
	ob := newOutbox(wk.state, w.st, p.Scope())
	if _, err := wk.export(context.Background(), p, ob); err != nil {
		t.Fatal(err)
	}
	if err := wk.state.tx(context.Background(), func(q querier) error {
		_, err := q.ExecContext(context.Background(), "UPDATE selection_rule SET kinds='[\"session\"]'")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := wk.push(context.Background(), p, mustClient(t, wk, p), ob); err != nil {
		t.Fatal(err)
	}
	if rows(t, wk, p)[task.ID] != stateCancelled || len(w.hosted.imports()) != 0 {
		t.Fatal("changed rule not revalidated before send")
	}
}

func mustClient(t *testing.T, wk *Worker, p Profile) *nodesync.Client {
	t.Helper()
	c, _, err := wk.clientFor(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// V17: interleaved d1,c2,d3,c4 with page size one skips nothing, and a crash
// after each page resumes from durable cursors without loss or early ACK.
func TestV17InterleavedCursorsPageSizeOneAndCrash(t *testing.T) {
	for crashAfter := 0; crashAfter <= 6; crashAfter++ {
		w := newWorld(t)
		victim := w.task(1, repoB, "active")
		keep := w.task(2, repoB, "active")
		d1 := w.hosted.addData(w.foreignData(1))
		c2 := w.hosted.addControl(w.control(2, record.KindRetraction, victim.ID))
		d3 := w.hosted.addData(w.foreignData(3))
		c4 := w.hosted.addControl(w.control(4, record.KindErasure, keep.ID))
		w.hosted.pageLimit = 1
		p := w.enroll()
		wk := w.worker()
		if crashAfter > 0 {
			ctx, cancel := context.WithCancel(context.Background())
			w.hosted.mu.Lock()
			w.hosted.onLog = func(n int) {
				if n == crashAfter {
					cancel()
				}
			}
			w.hosted.mu.Unlock()
			_ = wk.Round(ctx)
			cancel()
			w.hosted.mu.Lock()
			w.hosted.onLog = nil
			w.hosted.mu.Unlock()
			// Restart: a new worker over the same durable database.
			_ = wk.state.Close()
			wk = w.worker()
			c := cursorsOf(t, wk, p)
			for _, a := range w.hosted.ackList() {
				if a.CtlEnforcedThrough > c.Ctl || a.DataAppliedThrough > c.Data {
					t.Fatalf("ack %+v ahead of durable %+v", a, c)
				}
			}
		}
		if err := wk.Round(context.Background()); err != nil {
			t.Fatalf("crash %d: %v", crashAfter, err)
		}
		c := cursorsOf(t, wk, p)
		if c.Ctl != c4 || c.Data != d3 {
			t.Fatalf("crash %d: cursors %+v want ctl=%d data=%d", crashAfter, c, c4, d3)
		}
		if n := count(t, wk, "SELECT count(*) FROM data_quarantine WHERE hseq IN (?,?)", d1, d3); n != 2 {
			t.Fatalf("crash %d: data skipped, quarantined %d", crashAfter, n)
		}
		if n := count(t, wk, "SELECT count(*) FROM ctl_pending"); n != 0 {
			t.Fatalf("crash %d: pending controls %d", crashAfter, n)
		}
		snap, err := w.st.Snapshot(context.Background(), storeRead(victim.ID, keep.ID))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range snap.Entries {
			if e.State == "live" {
				t.Fatalf("crash %d: control %s not enforced", crashAfter, e.ID)
			}
		}
		acks := w.hosted.ackList()
		if last := acks[len(acks)-1]; last != (transport.Ack{CtlEnforcedThrough: c4, DataAppliedThrough: d3}) {
			t.Fatalf("crash %d: ack %+v", crashAfter, last)
		}
		_ = c2
	}
}

// V17: an unknown or higher-version control at c2 halts ENFORCE, PUSH and
// PULL(data), holds ctl_cursor below it, and survives restart. The scan still
// reaches later controls without a third durable cursor.
func TestV17UnknownControlBlocksPushAndDataPull(t *testing.T) {
	for _, mode := range []string{"higher-version", "unknown-kind"} {
		w := newWorld(t)
		w.task(1, repoA, "active")
		d1 := w.hosted.addData(w.foreignData(1))
		bad := w.control(2, record.KindRetraction, strings.Repeat("f", 64))
		if mode == "higher-version" {
			bad.V = record.Version + 1
		} else {
			bad.Header = "eyJ0eXBlIjoibm90LWEta2luZCJ9"
		}
		c2 := w.hosted.addControl(bad)
		w.hosted.addData(w.foreignData(3))
		w.hosted.addControl(w.control(4, record.KindRetraction, strings.Repeat("e", 64)))
		w.hosted.pageLimit = 1
		p := w.enroll()
		wk := w.worker()
		w.selectRepo(wk, repoA)
		for restart := 0; restart < 2; restart++ {
			if err := wk.Round(context.Background()); !errors.Is(err, ErrControlBlocked) {
				t.Fatalf("%s: %v", mode, err)
			}
			c := cursorsOf(t, wk, p)
			if c.Ctl != 0 || c.Data != 0 || c.BarrierHSeq != c2 {
				t.Fatalf("%s: cursors %+v", mode, c)
			}
			if n := count(t, wk, "SELECT count(*) FROM ctl_pending"); n != 2 {
				t.Fatalf("%s: scan did not reach later control: %d", mode, n)
			}
			if len(w.hosted.imports()) != 0 || count(t, wk, "SELECT count(*) FROM outbox") != 0 {
				t.Fatalf("%s: push ran past an unenforced control", mode)
			}
			if count(t, wk, "SELECT count(*) FROM data_quarantine WHERE hseq=?", d1) != 0 {
				t.Fatalf("%s: data pulled past an unenforced control", mode)
			}
			for _, a := range w.hosted.ackList() {
				if a != (transport.Ack{}) {
					t.Fatalf("%s: ack crossed barrier %+v", mode, a)
				}
			}
			_ = wk.state.Close()
			wk = w.worker()
		}
	}
}

// ACK truth: a row completes only with a verified receipt for exactly that id.
// A forged receipt completes nothing; unavailable is terminal with no receipt.
func TestCompletionOnlyFromVerifiedReceipts(t *testing.T) {
	w := newWorld(t)
	a := w.task(1, repoA, "active")
	b := w.task(2, repoA, "completed")
	p := w.enroll()
	wk := w.worker()
	w.selectRepo(wk, repoA)
	w.hosted.mu.Lock()
	w.hosted.badReceipt = 1
	w.hosted.mu.Unlock()
	if err := wk.Round(context.Background()); !errors.Is(err, nodesync.ErrReceipt) {
		t.Fatalf("forged receipt: %v", err)
	}
	got := rows(t, wk, p)
	if got[a.ID] != statePending || got[b.ID] != statePending || count(t, wk, "SELECT count(*) FROM delivery_receipt") != 0 {
		t.Fatalf("forged receipt completed rows %v", got)
	}
	// Mark one exported id unavailable at hosted; retry sends identical bytes.
	first := w.hosted.imports()[0]
	var req struct {
		Envelopes []record.Envelope `json:"envelopes"`
	}
	_ = json.Unmarshal(first, &req)
	w.hosted.mu.Lock()
	unavailable := req.Envelopes[1].ID
	delete(w.hosted.receipts, unavailable)
	w.hosted.unavailable[unavailable] = true
	w.hosted.mu.Unlock()
	if err := wk.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	bodies := w.hosted.imports()
	if !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("retry changed operation bytes")
	}
	states := map[string]int{}
	for _, s := range rows(t, wk, p) {
		states[s]++
	}
	if states[stateComplete] != 1 || states[stateUnavailable] != 1 || count(t, wk, "SELECT count(*) FROM delivery_receipt") != 1 {
		t.Fatalf("states %v", states)
	}
	if count(t, wk, "SELECT count(*) FROM delivery_receipt WHERE record_id=?", unavailable) != 0 {
		t.Fatal("unavailable id has a receipt")
	}
}

// V24 for the push path: a lost reply is recovered by an idempotent retry of
// the same op bytes across restart; hosted admits each record once and the
// node completes from the stored receipt.
func TestV24LostReplyRetriesSameBytesAcrossRestart(t *testing.T) {
	w := newWorld(t)
	w.task(1, repoA, "active")
	p := w.enroll()
	wk := w.worker()
	w.selectRepo(wk, repoA)
	w.hosted.mu.Lock()
	w.hosted.lostReply = 2 // first send and its one in-call retry both lose the reply
	w.hosted.mu.Unlock()
	err := wk.Round(context.Background())
	var retry *nodesync.RetryError
	if !errors.As(err, &retry) {
		t.Fatalf("lost reply: %v", err)
	}
	if n := count(t, wk, "SELECT count(*) FROM operation WHERE state=? AND attempt>0 AND not_before>0", statePending); n != 1 {
		t.Fatal("retry deadline not persisted")
	}
	// The persisted deadline is honored after restart; then the same bytes go.
	_ = wk.state.Close()
	wk = w.worker()
	wk.state.now = func() time.Time { return time.Now().Add(MaxBackoff + time.Minute) }
	if err := wk.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	bodies := w.hosted.imports()
	if len(bodies) != 3 || !bytes.Equal(bodies[0], bodies[2]) || !bytes.Equal(bodies[1], bodies[2]) {
		t.Fatalf("retries %d or bytes changed", len(bodies))
	}
	w.hosted.mu.Lock()
	admitted := len(w.hosted.receipts)
	w.hosted.mu.Unlock()
	if admitted != 1 {
		t.Fatalf("hosted admitted %d", admitted)
	}
	for _, s := range rows(t, wk, p) {
		if s != stateComplete {
			t.Fatalf("state %s", s)
		}
	}
	// A completed export is not re-exported or re-sent with a new seal.
	if err := wk.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(w.hosted.imports()) != 3 {
		t.Fatal("completed record sent again")
	}
}

// A hosted refusal marks the operation rejected, never complete, and the
// rejected source is not re-exported in a loop.
func TestHostedRefusalIsRejectedNotRetried(t *testing.T) {
	w := newWorld(t)
	task := w.task(1, repoA, "active")
	p := w.enroll()
	wk := w.worker()
	w.selectRepo(wk, repoA)
	w.hosted.mu.Lock()
	w.hosted.importStatuses = []int{400}
	w.hosted.mu.Unlock()
	if err := wk.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rows(t, wk, p)[task.ID] != stateRejected || count(t, wk, "SELECT count(*) FROM delivery_receipt") != 0 {
		t.Fatal("refusal not recorded as rejected")
	}
	if err := wk.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(w.hosted.imports()) != 1 {
		t.Fatal("rejected source re-sent")
	}
}

// Shutdown cancels an in-flight send; the operation stays pending with the
// same bytes and completes after restart.
func TestShutdownCancelsInFlightSend(t *testing.T) {
	w := newWorld(t)
	w.task(1, repoA, "active")
	p := w.enroll()
	wk := w.worker()
	w.selectRepo(wk, repoA)
	block := make(chan struct{})
	w.hosted.mu.Lock()
	w.hosted.blockImport = block
	w.hosted.mu.Unlock()
	wk.Start(context.Background())
	deadline := time.Now().Add(10 * time.Second)
	for count(t, wk, "SELECT count(*) FROM operation WHERE state=?", statePending) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no operation queued")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	stopped := make(chan error, 1)
	go func() { stopped <- wk.Stop() }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("stop did not cancel the in-flight round")
	}
	w.hosted.mu.Lock()
	w.hosted.blockImport = nil
	w.hosted.mu.Unlock()
	close(block)
	wk = w.worker()
	if n := count(t, wk, "SELECT count(*) FROM outbox WHERE state=?", statePending); n != 1 {
		t.Fatalf("pending after shutdown %d", n)
	}
	if err := wk.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, s := range rows(t, wk, p) {
		if s != stateComplete {
			t.Fatalf("state %s", s)
		}
	}
}

// A hosted endpoint without the control log never receives a push: control
// reconciliation precedes every push.
func TestNoPushWithoutControlLog(t *testing.T) {
	w := newWorld(t)
	w.task(1, repoA, "active")
	w.enroll()
	wk := w.worker()
	w.selectRepo(wk, repoA)
	w.hosted.helloStatus = 404
	if err := wk.Round(context.Background()); !errors.Is(err, ErrHostedLog) {
		t.Fatalf("missing log: %v", err)
	}
	if len(w.hosted.imports()) != 0 {
		t.Fatal("pushed without control reconciliation")
	}
}
