package store

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// The real driver keeps its fixed five-second busy timeout. A failed BEGIN is
// retried before any authority snapshot or callback, never an acquired write.
func TestWriterAcquisitionRetriesOnlyBusyBeforeCallback(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	other, err := Open(ctx, w.o)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err = other.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- w.s.write(ctx, func() error { calls.Add(1); return nil }) }()
	time.Sleep(5800 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("callback ran while other handle owned writer")
	}
	if _, err = other.conn.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil || calls.Load() != 1 || time.Since(start) < 5*time.Second {
		t.Fatal("busy retry failed", Code(err), calls.Load())
	}
	var pragma int
	if err = w.s.conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&pragma); err != nil || pragma != 5000 {
		t.Fatal("busy timeout changed", pragma, err)
	}
}
func TestWriterAcquisitionCancellationAndFiniteExhaustion(t *testing.T) {
	for _, cancelled := range []bool{true, false} {
		name := "exhaustion"
		if cancelled {
			name = "cancelled"
		}
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			ctx := context.Background()
			other, err := Open(ctx, w.o)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if _, err = other.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
				t.Fatal(err)
			}
			defer other.conn.ExecContext(context.Background(), "ROLLBACK")
			run := ctx
			cancel := func() {}
			if cancelled {
				run, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
			}
			defer cancel()
			calls := 0
			start := time.Now()
			err = w.s.write(run, func() error { calls++; return nil })
			want := "storage_error"
			if cancelled {
				want = "cancelled"
			}
			if Code(err) != want || calls != 0 {
				t.Fatal("failed acquisition called producer or wrong fixed error", Code(err), calls)
			}
			elapsed := time.Since(start)
			if !cancelled && (elapsed < 25*time.Second || elapsed > 45*time.Second) {
				t.Fatal("busy attempts were not finite fixed acquisitions", elapsed)
			}
			if cancelled && elapsed > 7*time.Second {
				t.Fatal("cancellation retried acquisition", elapsed)
			}
			if w.s.poisoned {
				t.Fatal("unacquired transaction poisoned handle")
			}
			if _, err = other.conn.ExecContext(ctx, "ROLLBACK"); err != nil {
				t.Fatal(err)
			}
			if err = w.s.write(ctx, func() error { calls++; return nil }); err != nil || calls != 1 {
				t.Fatal("known unacquired refusal lost handle", err, calls)
			}
		})
	}
}
func TestWriterAcquisitionDoesNotRetryNonBusy(t *testing.T) {
	w := newWorld(t)
	if err := w.s.conn.Close(); err != nil {
		t.Fatal(err)
	}
	calls := 0
	start := time.Now()
	err := w.s.write(context.Background(), func() error { calls++; return nil })
	if Code(err) != "storage_error" || calls != 0 || time.Since(start) > time.Second {
		t.Fatal("nonbusy acquisition retried or callback ran", Code(err), calls)
	}
}
