package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

const spoolTestID = "01K00000000000000000000000"

func spoolTestHint() transport.HookSignal {
	return transport.HookSignal{V: 3, At: 1761150000000, Client: "claude", Event: "Stop", NativeSession: "22222222-2222-4222-8222-222222222222", TranscriptPath: filepath.Join(os.TempDir(), "synthetic", "22222222-2222-4222-8222-222222222222.jsonl"), HookPID: 12, Ancestry: []transport.Proc{{PID: 11, StartMS: 1761149999000, Argv0: "claude"}}}
}
func spoolCount(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func spoolReopen(t *testing.T, w *world) {
	t.Helper()
	if err := w.s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), w.o)
	if err != nil {
		t.Fatal(err)
	}
	w.s = s
}
func spoolNoCallback(t *testing.T) func(*CaptureTxn) (CommitPlan, error) {
	return func(*CaptureTxn) (CommitPlan, error) {
		t.Error("receipt replay invoked producer")
		return CommitPlan{}, errors.New("unexpected callback")
	}
}
func TestSpoolCaptureCommitReplayErasureAndConflicts(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "spool source text must never enter receipts")
	h := spoolTestHint()
	first, err := f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil })
	if err != nil || first.Status != "committed" {
		t.Fatal(first, err)
	}
	if spoolCount(t, f.w.s, "spool_announcement") != 1 || spoolCount(t, f.w.s, "spool_process") != 1 || spoolCount(t, f.w.s, "spool_done") != 1 {
		t.Fatal("split admission")
	}
	spoolReopen(t, f.w)
	replay, err := f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, spoolNoCallback(t))
	first.Status = "prior_transition_committed"
	if err != nil || !reflect.DeepEqual(first, replay) {
		t.Fatal("unstable replay", replay, err)
	}
	for _, change := range []func(*transport.HookSignal){func(h *transport.HookSignal) { h.At++ }, func(h *transport.HookSignal) {
		h.Ancestry = append([]transport.Proc(nil), h.Ancestry...)
		h.Ancestry[0].StartMS++
	}, func(h *transport.HookSignal) { h.Event = "SessionEnd" }} {
		bad := h
		change(&bad)
		if _, err = f.w.s.CaptureSignal(ctx, bad, spoolTestID, f.q, spoolNoCallback(t)); Code(err) != "signal_conflict" {
			t.Fatal("conflicting hint admitted", err)
		}
	}
	q := f.q
	q.ExpectedVersion++
	if _, err = f.w.s.CaptureSignal(ctx, h, spoolTestID, q, spoolNoCallback(t)); Code(err) != "signal_conflict" {
		t.Fatal("conflicting request admitted", err)
	}
	identity := h
	identity.TranscriptPath = ""
	if err = f.w.s.AdmitSignal(ctx, identity, spoolTestID); Code(err) != "signal_conflict" {
		t.Fatal("cross-mode reuse", err)
	}
	f.w.append(f.w.control(18101, record.KindErasure, f.plan.NewRecords[0].AdvisoryID))
	spoolReopen(t, f.w)
	done, err := f.w.s.SignalDone(ctx, h.Client, spoolTestID)
	if err != nil || !done {
		t.Fatal("erasure lost done", done, err)
	}
	replay, err = f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, spoolNoCallback(t))
	if err != nil || replay.CurrentAvailability[f.plan.NewRecords[0].AdvisoryID] == "available" {
		t.Fatal("erasure replay stale", replay, err)
	}
	var raw []byte
	if err = f.w.s.conn.QueryRowContext(ctx, "SELECT receipt FROM spool_done").Scan(&raw); err != nil || strings.Contains(string(raw), "spool source text") {
		t.Fatal("source leaked into receipt", err)
	}
	// Receipt-only lookup must not depend on successful body/projection loading.
	if _, err = f.w.s.conn.ExecContext(ctx, "UPDATE record_body SET body=x'00'"); err != nil {
		t.Fatal(err)
	}
	done, err = f.w.s.SignalDone(ctx, h.Client, spoolTestID)
	if err != nil || !done {
		t.Fatal("receipt lookup loaded source", done, err)
	}
}
func TestSpoolNoChangeAndRecoveredTransition(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "unchanged source")
	original := f.commit()
	h := spoolTestHint()
	recovered, err := f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, spoolNoCallback(t))
	if err != nil || recovered.Status != "prior_transition_committed" || recovered.TransitionID != original.TransitionID {
		t.Fatal(recovered, err)
	}
	q := f.q
	q.ExpectedVersion = 1
	plan := CommitPlan{Next: f.plan.Next}
	for _, r := range f.plan.NewRecords {
		plan.ReuseRecordIDs = append(plan.ReuseRecordIDs, r.AdvisoryID)
	}
	secondID := "01K00000000000000000000001"
	unchanged, err := f.w.s.CaptureSignal(ctx, h, secondID, q, func(*CaptureTxn) (CommitPlan, error) { return plan, nil })
	if err != nil || unchanged.Status != "no_change" || unchanged.ResultingProgress.Version != 1 {
		t.Fatal(unchanged, err)
	}
	spoolReopen(t, f.w)
	replay, err := f.w.s.CaptureSignal(ctx, h, secondID, q, spoolNoCallback(t))
	if err != nil || !reflect.DeepEqual(unchanged, replay) {
		t.Fatal("no-change replay", replay, err)
	}
	if spoolCount(t, f.w.s, "capture_transition") != 1 || spoolCount(t, f.w.s, "spool_done") != 2 {
		t.Fatal("no-change minted or lost receipt")
	}
}
func TestSpoolIdentityAdmissionAndRollback(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	h := spoolTestHint()
	h.TranscriptPath = ""
	before := w.snapshot()
	for _, table := range []string{"spool_announcement", "spool_process", "spool_done"} {
		if _, err := w.s.conn.ExecContext(ctx, "CREATE TRIGGER spool_fault BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(ABORT,'private failure prose'); END"); err != nil {
			t.Fatal(err)
		}
		if err := w.s.AdmitSignal(ctx, h, spoolTestID); Code(err) != "storage_error" || err.Error() != "storage_error" {
			t.Fatal(err)
		}
		for _, table := range []string{"spool_announcement", "spool_process", "spool_done"} {
			if spoolCount(t, w.s, table) != 0 {
				t.Fatal("partial identity admission", table)
			}
		}
		if _, err := w.s.conn.ExecContext(ctx, "DROP TRIGGER spool_fault"); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.s.AdmitSignal(ctx, h, spoolTestID); err != nil {
		t.Fatal(err)
	}
	spoolReopen(t, w)
	if err := w.s.AdmitSignal(ctx, h, spoolTestID); err != nil {
		t.Fatal(err)
	}
	after := w.snapshot()
	if after.Generation != before.Generation || len(after.Entries) != len(before.Entries) {
		t.Fatal("identity hint changed authority or records")
	}
	if spoolCount(t, w.s, "spool_done") != 1 {
		t.Fatal("duplicate identity receipt")
	}
}
func TestSpoolCaptureFaultRollsBackAnnouncementOutputAndReceipt(t *testing.T) {
	for _, table := range []string{"spool_announcement", "spool_process", "spool_done"} {
		t.Run(table, func(t *testing.T) {
			ctx := context.Background()
			f := newProducer(t, "rollback source")
			before := f.w.snapshot()
			if _, err := f.w.s.conn.ExecContext(ctx, "CREATE TRIGGER spool_fault BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(ABORT,'private fault'); END"); err != nil {
				t.Fatal(err)
			}
			got, err := f.w.s.CaptureSignal(ctx, spoolTestHint(), spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil })
			if Code(err) != "storage_error" || got.Status != "" {
				t.Fatal(got, err)
			}
			if spoolCount(t, f.w.s, "capture_transition") != 0 || spoolCount(t, f.w.s, "capture_progress") != 0 || spoolCount(t, f.w.s, "spool_announcement") != 0 || spoolCount(t, f.w.s, "spool_done") != 0 {
				t.Fatal("partial capture")
			}
			after := f.w.snapshot()
			if after.Generation != before.Generation || len(after.Entries) != len(before.Entries) {
				t.Fatal("partial record output")
			}
			if _, err = f.w.s.conn.ExecContext(ctx, "DROP TRIGGER spool_fault"); err != nil {
				t.Fatal(err)
			}
			if _, err = f.w.s.CaptureSignal(ctx, spoolTestHint(), spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil }); err != nil {
				t.Fatal("safe retry", err)
			}
		})
	}
}
func TestSpoolRefusalsNeverAcknowledge(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "refused")
	_, err := f.w.s.CaptureSignal(ctx, spoolTestHint(), spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { return CommitPlan{}, errors.New("private producer error") })
	if Code(err) != "producer_refused" {
		t.Fatal(err)
	}
	if done, e := f.w.s.SignalDone(ctx, "claude", spoolTestID); e != nil || done {
		t.Fatal(done, e)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err = f.w.s.AdmitSignal(cancelCtx, func() transport.HookSignal { h := spoolTestHint(); h.TranscriptPath = ""; return h }(), spoolTestID); Code(err) != "cancelled" {
		t.Fatal(err)
	}
	if _, err = f.w.s.CaptureSignal(ctx, spoolTestHint(), spoolTestID, f.q, nil); Code(err) != "invalid_request" {
		t.Fatal(err)
	}
	if spoolCount(t, f.w.s, "spool_done") != 0 || spoolCount(t, f.w.s, "spool_announcement") != 0 {
		t.Fatal("refusal acknowledged")
	}
}
func TestSpoolValidationAndMigration(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	h := spoolTestHint()
	h.TranscriptPath = ""
	for _, change := range []func(*transport.HookSignal){func(h *transport.HookSignal) { h.Event = "free prose" }, func(h *transport.HookSignal) { h.NativeSession = "source prose to retain" }, func(h *transport.HookSignal) { h.Cwd = "relative/path" }, func(h *transport.HookSignal) { h.Ancestry = make([]transport.Proc, 7) }, func(h *transport.HookSignal) {
		h.Ancestry = []transport.Proc{{PID: 1, StartMS: 1, Argv0: "private content"}}
	}, func(h *transport.HookSignal) { h.Source = "secret" }, func(h *transport.HookSignal) { h.Client = "unknown" }, func(h *transport.HookSignal) { h.V = 2 }} {
		bad := h
		change(&bad)
		if err := w.s.AdmitSignal(ctx, bad, spoolTestID); Code(err) != "invalid_signal" {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"", strings.Repeat("0", 25), "81K00000000000000000000000", "01k00000000000000000000000"} {
		if _, err := w.s.SignalDone(ctx, "claude", id); Code(err) != "invalid_signal" {
			t.Fatal(id, err)
		}
	}
	// Emulate an existing pre-spool v2 database, including real capture output.
	f := producerFor(w, "old database retained capture")
	original := f.commit()
	for _, table := range []string{"spool_done", "spool_process", "spool_announcement"} {
		if _, err := w.s.conn.ExecContext(ctx, "DROP TABLE "+table); err != nil {
			t.Fatal(err)
		}
	}
	spoolReopen(t, w)
	got, err := w.s.CaptureSignal(ctx, spoolTestHint(), spoolTestID, f.q, spoolNoCallback(t))
	if err != nil || got.TransitionID != original.TransitionID {
		t.Fatal("migration lost receipt", got, err)
	}
	if done, err := w.s.SignalDone(ctx, "claude", spoolTestID); err != nil || !done {
		t.Fatal(done, err)
	}
}

func TestSpoolUnknownCommitRefusesAcknowledgementUntilRecovery(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "commit uncertainty")
	for _, q := range []string{"CREATE TABLE spool_fault_parent(id INTEGER PRIMARY KEY)", "CREATE TABLE spool_fault_child(id INTEGER REFERENCES spool_fault_parent(id) DEFERRABLE INITIALLY DEFERRED)", "CREATE TRIGGER spool_commit_fault AFTER INSERT ON spool_done BEGIN INSERT INTO spool_fault_child VALUES(999); END"} {
		if _, err := f.w.s.conn.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	got, err := f.w.s.CaptureSignal(ctx, spoolTestHint(), spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil })
	if Code(err) != "outcome_unknown" || got.Status != "" {
		t.Fatal(got, err)
	}
	if done, err := f.w.s.SignalDone(ctx, "claude", spoolTestID); Code(err) != "outcome_unknown" || done {
		t.Fatal("uncertain receipt acknowledged", done, err)
	}
	spoolReopen(t, f.w)
	if done, err := f.w.s.SignalDone(ctx, "claude", spoolTestID); err != nil || done {
		t.Fatal("failed commit durable", done, err)
	}
	if spoolCount(t, f.w.s, "spool_announcement") != 0 || spoolCount(t, f.w.s, "capture_transition") != 0 {
		t.Fatal("failed commit split")
	}
	if _, err = f.w.s.conn.ExecContext(ctx, "DROP TRIGGER spool_commit_fault"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.w.s.CaptureSignal(ctx, spoolTestHint(), spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, nil }); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolConcurrentStoreConnectionsAdmitOneProducer(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "single writer")
	other, err := Open(ctx, f.w.o)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	calls := 0 // protected by SQLite writer acquisition across both store connections
	results := make(chan CaptureReceipt, 2)
	errs := make(chan error, 2)
	for _, s := range []*Store{f.w.s, other} {
		go func(s *Store) {
			r, e := s.CaptureSignal(ctx, spoolTestHint(), spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { calls++; return f.plan, nil })
			results <- r
			errs <- e
		}(s)
	}
	a, b := <-results, <-results
	if e := <-errs; e != nil {
		t.Fatal(e)
	}
	if e := <-errs; e != nil {
		t.Fatal(e)
	}
	a.Status = "prior_transition_committed"
	b.Status = "prior_transition_committed"
	if calls != 1 || !reflect.DeepEqual(a, b) || spoolCount(t, f.w.s, "spool_done") != 1 || spoolCount(t, f.w.s, "spool_announcement") != 1 {
		t.Fatal("concurrent split", calls, a, b)
	}
}

func TestSpoolIdentityFiniteClientVocabularies(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	for _, tc := range []struct{ client, event, reader string }{{"claude", "SessionStart", "claude-code"}, {"codex", "SessionStart", "codex"}, {"cursor", "sessionStart", "cursor-agent"}, {"pi", "session_start", "pi"}} {
		t.Run(tc.client, func(t *testing.T) {
			h := spoolTestHint()
			h.Client = tc.client
			h.Event = tc.event
			h.TranscriptPath = ""
			if signalReader(h.Client) != tc.reader {
				t.Fatal("reader alias")
			}
			if err := w.s.AdmitSignal(ctx, h, spoolTestID); err != nil {
				t.Fatal(err)
			}
			if done, err := w.s.SignalDone(ctx, h.Client, spoolTestID); err != nil || !done {
				t.Fatal(done, err)
			}
		})
	}
	if spoolCount(t, w.s, "spool_done") != 4 {
		t.Fatal("client namespaces collided")
	}
}

func TestSpoolInputBoundsAndIdentityFailClosed(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "input bounds")
	for _, change := range []func(*CaptureRequest){func(q *CaptureRequest) { q.EventIDs = make([]string, 4097) }, func(q *CaptureRequest) { q.EventIDs = []string{"private text"} }, func(q *CaptureRequest) { q.PolicyID = "private text" }, func(q *CaptureRequest) { q.Occurrence.Owner = "bad" }, func(q *CaptureRequest) { q.Reader.ReaderVersion = strings.Repeat("x", 129) }, func(q *CaptureRequest) { q.Occurrence.SessionKey = "sk1:" + strings.Repeat("1", 64) }} {
		q := f.q
		change(&q)
		if _, err := f.w.s.CaptureSignal(ctx, spoolTestHint(), spoolTestID, q, spoolNoCallback(t)); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	for _, change := range []func(*transport.HookSignal){func(h *transport.HookSignal) { h.Cwd = string([]byte{'/', 0xff}) }, func(h *transport.HookSignal) { h.Event = strings.Repeat("x", 4097) }, func(h *transport.HookSignal) {
		h.Ancestry = []transport.Proc{{PID: 1, StartMS: 1, Argv0: strings.Repeat("x", 257)}}
	}} {
		h := spoolTestHint()
		change(&h)
		if _, err := f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, spoolNoCallback(t)); Code(err) != "invalid_signal" {
			t.Fatal(err)
		}
	}
	h := spoolTestHint()
	if err := f.w.s.AdmitSignal(ctx, h, spoolTestID); Code(err) != "invalid_signal" {
		t.Fatal("identity bypassed capture", err)
	}
	h.TranscriptPath = ""
	if _, err := f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, spoolNoCallback(t)); Code(err) != "invalid_signal" {
		t.Fatal("capture lost source hint", err)
	}
	if done, err := f.w.s.SignalDone(ctx, "unknown", spoolTestID); Code(err) != "invalid_signal" || done {
		t.Fatal(done, err)
	}
	if spoolCount(t, f.w.s, "spool_done") != 0 {
		t.Fatal("invalid signal acknowledged")
	}
	if _, err := f.w.s.conn.ExecContext(ctx, "UPDATE capture_instance SET id='replaced'"); err != nil {
		t.Fatal(err)
	}
	if done, err := f.w.s.SignalDone(ctx, "claude", spoolTestID); Code(err) != "outcome_unknown" || done {
		t.Fatal("instance replacement admitted", done, err)
	}
}

// A suppressed unit is skipped, not held. The hint is acknowledged in one
// transaction with no capture progress, transition or record, only when the
// writer still sees the unit as suppressed, and the acknowledgement is stable.
func TestSpoolSkipSuppressedAcknowledgesWithoutCapture(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "erased transcript text must never return")
	h := spoolTestHint()
	if err := f.w.s.SkipSuppressedSignal(ctx, h, spoolTestID, f.q.Occurrence); Code(err) != "not_suppressed" {
		t.Fatal("live unit acknowledged without capture", err)
	}
	if spoolCount(t, f.w.s, "spool_announcement") != 0 || spoolCount(t, f.w.s, "spool_done") != 0 {
		t.Fatal("refused skip wrote a receipt")
	}
	original := f.commit()
	f.w.append(f.w.control(18201, record.KindErasure, f.plan.NewRecords[0].AdvisoryID))
	before := f.w.snapshot()
	progress, transitions := spoolCount(t, f.w.s, "capture_progress"), spoolCount(t, f.w.s, "capture_transition")
	second := spoolTestID[:25] + "2"
	if err := f.w.s.ObserveSignal(ctx, h, second); err != nil {
		t.Fatal(err)
	}
	other := f.q.Occurrence
	other.SessionKey = "sk1:" + strings.Repeat("c", 64)
	if err := f.w.s.SkipSuppressedSignal(ctx, h, second, other); Code(err) != "signal_conflict" {
		t.Fatal("hint bound to a different session", err)
	}
	for _, id := range []string{spoolTestID, second} {
		if err := f.w.s.SkipSuppressedSignal(ctx, h, id, f.q.Occurrence); err != nil {
			t.Fatal("suppressed unit held", err)
		}
		if done, err := f.w.s.SignalDone(ctx, h.Client, id); err != nil || !done {
			t.Fatal("skip not acknowledged", done, err)
		}
	}
	spoolReopen(t, f.w)
	if err := f.w.s.SkipSuppressedSignal(ctx, h, spoolTestID, f.q.Occurrence); err != nil {
		t.Fatal("acknowledged skip replay", err)
	}
	for _, id := range []string{spoolTestID, second} {
		if done, err := f.w.s.SignalDone(ctx, h.Client, id); err != nil || !done {
			t.Fatal("skip acknowledgement lost on reopen", done, err)
		}
	}
	if !reflect.DeepEqual(before, f.w.snapshot()) || spoolCount(t, f.w.s, "capture_progress") != progress || spoolCount(t, f.w.s, "capture_transition") != transitions {
		t.Fatal("skip changed capture state")
	}
	if spoolCount(t, f.w.s, "spool_announcement") != 2 || spoolCount(t, f.w.s, "spool_done") != 2 {
		t.Fatal("skip receipts")
	}
	var raw []byte
	if err := f.w.s.conn.QueryRowContext(ctx, "SELECT receipt FROM spool_done WHERE ulid=?", spoolTestID).Scan(&raw); err != nil || strings.Contains(string(raw), "erased transcript") || !strings.Contains(string(raw), `"suppressed"`) {
		t.Fatal("skip receipt", string(raw), err)
	}
	// The producer never runs again for the erased unit, even with a fresh hint.
	third := spoolTestID[:25] + "3"
	q := f.q
	q.ExpectedVersion = original.ResultingProgress.Version
	if _, err := f.w.s.CaptureSignal(ctx, h, third, q, spoolNoCallback(t)); Code(err) != "suppressed" {
		t.Fatal("erased unit admitted capture", err)
	}
	if done, err := f.w.s.SignalDone(ctx, h.Client, third); err != nil || done {
		t.Fatal("refused capture acknowledged", done, err)
	}
}
