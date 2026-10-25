package store

import (
	"context"
	"path/filepath"
	"testing"
)

// A gap receipt retains the hint and its fixed code in one transaction, is
// idempotent, never advances progress or mints records, refuses reuse of the
// ULID for a different hint, and is reported by the read-only Inspect.
func TestSpoolSkipSignalWithGap(t *testing.T) {
	ctx := context.Background()
	f := newProducer(t, "gap source text must never enter receipts")
	h := spoolTestHint()
	for _, bad := range []string{"", "Invalid", "has space", "../x"} {
		if err := f.w.s.SkipSignalWithGap(ctx, h, spoolTestID, bad); Code(err) != "invalid_request" {
			t.Fatal("unfixed gap code accepted", bad, err)
		}
	}
	records := spoolCount(t, f.w.s, "record")
	for i := 0; i < 2; i++ {
		if err := f.w.s.SkipSignalWithGap(ctx, h, spoolTestID, "native_shape"); err != nil {
			t.Fatal(i, err)
		}
	}
	if spoolCount(t, f.w.s, "spool_announcement") != 1 || spoolCount(t, f.w.s, "spool_done") != 1 || spoolCount(t, f.w.s, "spool_gap") != 1 {
		t.Fatal("gap receipt not atomic or not idempotent")
	}
	if spoolCount(t, f.w.s, "record") != records || spoolCount(t, f.w.s, "capture_progress") != 0 {
		t.Fatal("gap minted records or moved progress")
	}
	if done, err := f.w.s.SignalDone(ctx, h.Client, spoolTestID); err != nil || !done {
		t.Fatal("gap not acknowledged", done, err)
	}
	other := h
	other.Event = "SessionEnd"
	if err := f.w.s.SkipSignalWithGap(ctx, other, spoolTestID, "native_shape"); Code(err) != "signal_conflict" {
		t.Fatal("ULID reuse accepted", err)
	}
	// The completed hint cannot later be turned into a capture of its unit.
	if _, err := f.w.s.CaptureSignal(ctx, h, spoolTestID, f.q, spoolNoCallback(t)); Code(err) != "signal_conflict" {
		t.Fatal("gap receipt replaced by capture", err)
	}
	identity := h
	identity.TranscriptPath = ""
	if err := f.w.s.SkipSignalWithGap(ctx, identity, "01K00000000000000000000001", "no_capture"); err != nil {
		t.Fatal("identity-only gap", err)
	}
	diag, err := Inspect(ctx, filepath.Clean(f.w.o.Dir))
	if err != nil || diag.SpoolGaps["claude:native_shape"] != 1 || diag.SpoolGaps["claude:no_capture"] != 1 || len(diag.SpoolGaps) != 2 {
		t.Fatal("gaps not inspected", diag.SpoolGaps, err)
	}
}
