package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/transport"
)

func TestSpoolObserveDurableExactHintAndFinalize(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "pending source canary")
	h := spoolTestHint()
	before := f.w.snapshot()
	if err := f.w.s.ObserveSignal(ctx, h, spoolTestID); err != nil {
		t.Fatal(err)
	}
	spoolReopen(t, f.w)
	if err := f.w.s.ObserveSignal(ctx, h, spoolTestID); err != nil {
		t.Fatal(err)
	}
	if done, err := f.w.s.SignalDone(ctx, h.Client, spoolTestID); err != nil || done {
		t.Fatal("observation acknowledged", done, err)
	}
	if !reflect.DeepEqual(before, f.w.snapshot()) || spoolCount(t, f.w.s, "capture_progress") != 0 || spoolCount(t, f.w.s, "spool_done") != 0 {
		t.Fatal("observation changed capture or authority")
	}
	var got transport.HookSignal
	got.V = 3
	if err := f.w.s.conn.QueryRowContext(ctx, `SELECT at,client,client_version,event,native_session,transcript_path,cwd,prompt_id,source,reason,status,hook_pid FROM spool_announcement WHERE ulid=?`, spoolTestID).Scan(&got.At, &got.Client, &got.ClientVersion, &got.Event, &got.NativeSession, &got.TranscriptPath, &got.Cwd, &got.PromptID, &got.Source, &got.Reason, &got.Status, &got.HookPID); err != nil {
		t.Fatal(err)
	}
	var p transport.Proc
	if err := f.w.s.conn.QueryRowContext(ctx, "SELECT pid,start_ms,argv0 FROM spool_process WHERE ulid=? AND position=0", spoolTestID).Scan(&p.PID, &p.StartMS, &p.Argv0); err != nil {
		t.Fatal(err)
	}
	got.Ancestry = []transport.Proc{p}
	if !reflect.DeepEqual(h, got) {
		t.Fatal("hint rewritten", got)
	}
	// Different valid hints under the same immutable identity must fail before a producer.
	for _, change := range []func(*transport.HookSignal){
		func(h *transport.HookSignal) { h.At++ },
		func(h *transport.HookSignal) { h.Event = "SessionEnd" },
		func(h *transport.HookSignal) { h.TranscriptPath = "/synthetic/other.jsonl" },
		func(h *transport.HookSignal) { h.Ancestry[0].StartMS++ },
		func(h *transport.HookSignal) { h.HookPID++ },
	} {
		bad := h
		bad.Ancestry = append([]transport.Proc(nil), h.Ancestry...)
		change(&bad)
		if err := f.w.s.ObserveSignal(ctx, bad, spoolTestID); Code(err) != "signal_conflict" {
			t.Fatal("observation replaced", err)
		}
		if _, err := f.w.s.CaptureSignal(ctx, bad, spoolTestID, f.q, spoolNoCallback(t)); Code(err) != "signal_conflict" {
			t.Fatal("conflicting finalization", err)
		}
	}
	r, err := f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil })
	if err != nil || r.Status != "committed" {
		t.Fatal(r, err)
	}
	spoolReopen(t, f.w)
	if err = f.w.s.ObserveSignal(ctx, h, spoolTestID); err != nil {
		t.Fatal("completed observation replay", err)
	}
	if _, err = f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, spoolNoCallback(t)); err != nil {
		t.Fatal(err)
	}
	q := f.q
	q.ExpectedVersion++
	if _, err = f.w.s.CaptureSignal(ctx, h, spoolTestID, q, spoolNoCallback(t)); Code(err) != "signal_conflict" {
		t.Fatal("completed request replaced", err)
	}
	if spoolCount(t, f.w.s, "spool_announcement") != 1 || spoolCount(t, f.w.s, "spool_process") != 1 || spoolCount(t, f.w.s, "spool_done") != 1 {
		t.Fatal("duplicate announcement/receipt")
	}
	f.w.append(f.w.control(18102, record.KindErasure, f.plan.NewRecords[0].AdvisoryID))
	spoolReopen(t, f.w)
	if done, err := f.w.s.SignalDone(ctx, h.Client, spoolTestID); err != nil || !done {
		t.Fatal("erasure lost completion", done, err)
	}
}

func TestSpoolObserveFailuresNeverAcknowledge(t *testing.T) {
	ctx := context.Background()
	for _, table := range []string{"spool_announcement", "spool_process"} {
		t.Run(table, func(t *testing.T) {
			f := newProducer(t, "observation rollback")
			if _, err := f.w.s.conn.ExecContext(ctx, "CREATE TRIGGER observe_fault BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(ABORT,'private observation failure'); END"); err != nil {
				t.Fatal(err)
			}
			if err := f.w.s.ObserveSignal(ctx, spoolTestHint(), spoolTestID); Code(err) != "storage_error" || err.Error() != "storage_error" {
				t.Fatal(err)
			}
			for _, table := range []string{"spool_announcement", "spool_process", "spool_done", "capture_progress"} {
				if spoolCount(t, f.w.s, table) != 0 {
					t.Fatal("partial observation", table)
				}
			}
		})
	}
	f := newProducer(t, "pending rollback")
	h := spoolTestHint()
	if err := f.w.s.ObserveSignal(ctx, h, spoolTestID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { return CommitPlan{}, errors.New("private producer error") }); Code(err) != "producer_refused" {
		t.Fatal(err)
	}
	if _, err := f.w.s.conn.ExecContext(ctx, "CREATE TRIGGER completion_fault BEFORE INSERT ON spool_done BEGIN SELECT RAISE(ABORT,'private receipt failure'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil }); Code(err) != "storage_error" {
		t.Fatal(err)
	}
	spoolReopen(t, f.w)
	if err := f.w.s.ObserveSignal(ctx, h, spoolTestID); err != nil {
		t.Fatal("rollback lost pending binding", err)
	}
	if spoolCount(t, f.w.s, "spool_done") != 0 || spoolCount(t, f.w.s, "capture_transition") != 0 || spoolCount(t, f.w.s, "capture_progress") != 0 {
		t.Fatal("partial finalization")
	}
	if _, err := f.w.s.conn.ExecContext(ctx, "DROP TRIGGER completion_fault"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil }); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolObserveNoChangeRecoveredAndIdentity(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "existing output")
	original := f.commit()
	h := spoolTestHint()
	if err := f.w.s.ObserveSignal(ctx, h, spoolTestID); err != nil {
		t.Fatal(err)
	}
	r, err := f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, spoolNoCallback(t))
	if err != nil || r.TransitionID != original.TransitionID || r.Status != "prior_transition_committed" {
		t.Fatal(r, err)
	}
	q := f.q
	q.ExpectedVersion = 1
	plan := CommitPlan{Next: f.plan.Next}
	for _, r := range f.plan.NewRecords {
		plan.ReuseRecordIDs = append(plan.ReuseRecordIDs, r.AdvisoryID)
	}
	id := "01K00000000000000000000001"
	if err = f.w.s.ObserveSignal(ctx, h, id); err != nil {
		t.Fatal(err)
	}
	r, err = f.w.s.CaptureSignal(ctx, h, id, q, func(*CaptureTxn) (CommitPlan, error) { return plan, nil })
	if err != nil || r.Status != "no_change" {
		t.Fatal(r, err)
	}
	h.TranscriptPath = ""
	id = "01K00000000000000000000002"
	if err = f.w.s.ObserveSignal(ctx, h, id); err != nil {
		t.Fatal(err)
	}
	if err = f.w.s.AdmitSignal(ctx, h, id); err != nil {
		t.Fatal(err)
	}
	if err = f.w.s.ObserveSignal(ctx, h, id); err != nil {
		t.Fatal(err)
	}
	if spoolCount(t, f.w.s, "spool_done") != 3 || spoolCount(t, f.w.s, "capture_transition") != 1 {
		t.Fatal("pending completion lost")
	}
}

func TestSpoolObserveValidationAndUncertainCommit(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "uncertain observation")
	for _, change := range []func(*transport.HookSignal){func(h *transport.HookSignal) { h.V = 2 }, func(h *transport.HookSignal) { h.NativeSession = "secret prose" }, func(h *transport.HookSignal) { h.Ancestry = make([]transport.Proc, 7) }, func(h *transport.HookSignal) { h.Cwd = strings.Repeat("x", 4097) }} {
		h := spoolTestHint()
		change(&h)
		if err := f.w.s.ObserveSignal(ctx, h, spoolTestID); Code(err) != "invalid_signal" {
			t.Fatal(err)
		}
	}
	if err := f.w.s.ObserveSignal(ctx, spoolTestHint(), "bad-id"); Code(err) != "invalid_signal" {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.w.s.ObserveSignal(cancelled, spoolTestHint(), spoolTestID); Code(err) != "cancelled" {
		t.Fatal(err)
	}
	if err := f.w.s.ObserveSignal(nil, spoolTestHint(), spoolTestID); Code(err) != "cancelled" {
		t.Fatal(err)
	}
	for _, sql := range []string{"CREATE TABLE observe_parent(id INTEGER PRIMARY KEY)", "CREATE TABLE observe_child(id INTEGER REFERENCES observe_parent(id) DEFERRABLE INITIALLY DEFERRED)", "CREATE TRIGGER observe_commit_fault AFTER INSERT ON spool_announcement BEGIN INSERT INTO observe_child VALUES(999); END"} {
		if _, err := f.w.s.conn.ExecContext(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.w.s.ObserveSignal(ctx, spoolTestHint(), spoolTestID); Code(err) != "outcome_unknown" {
		t.Fatal(err)
	}
	if done, err := f.w.s.SignalDone(ctx, "claude", spoolTestID); Code(err) != "outcome_unknown" || done {
		t.Fatal("uncertainty acknowledged", done, err)
	}
	spoolReopen(t, f.w)
	if spoolCount(t, f.w.s, "spool_announcement") != 0 || spoolCount(t, f.w.s, "spool_done") != 0 {
		t.Fatal("failed commit persisted")
	}
	if _, err := f.w.s.conn.ExecContext(ctx, "DROP TRIGGER observe_commit_fault"); err != nil {
		t.Fatal(err)
	}
	if err := f.w.s.ObserveSignal(ctx, spoolTestHint(), spoolTestID); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolObserveConcurrentWithCompletion(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "concurrent observation")
	other, err := Open(ctx, f.w.o)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	errs := make(chan error, 2)
	go func() { errs <- other.ObserveSignal(ctx, spoolTestHint(), spoolTestID) }()
	go func() {
		_, err := f.w.s.CaptureSignal(ctx, spoolTestHint(), spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil })
		errs <- err
	}()
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if spoolCount(t, f.w.s, "spool_done") != 1 || spoolCount(t, f.w.s, "spool_process") != 1 {
		t.Fatal("concurrent split")
	}
}

func TestSpoolLegacyCompletionReplayAndPendingCorruption(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "legacy completion")
	h := spoolTestHint()
	if _, err := f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil }); err != nil {
		t.Fatal(err)
	}
	a, err := f.w.s.prepareSpool(h, spoolTestID, "capture", &f.q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.w.s.conn.ExecContext(ctx, "UPDATE spool_announcement SET binding=?", a.binding); err != nil {
		t.Fatal(err)
	}
	spoolReopen(t, f.w)
	if _, err = f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, spoolNoCallback(t)); err != nil {
		t.Fatal("legacy replay failed", err)
	}
	if err = f.w.s.ObserveSignal(ctx, h, spoolTestID); Code(err) != "signal_conflict" {
		t.Fatal("legacy binding falsely proves hint", err)
	}
	// A completion binding without its receipt is not an admissible pending hint.
	if _, err = f.w.s.conn.ExecContext(ctx, "DELETE FROM spool_done"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, spoolNoCallback(t)); Code(err) != "signal_conflict" {
		t.Fatal("lost receipt accepted", err)
	}
}
