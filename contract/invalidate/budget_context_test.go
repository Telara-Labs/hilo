package invalidate

import (
	"context"
	"errors"
	"testing"
	"time"
)

var _ context.Context = (*snapshotTraversal)(nil)

func TestSnapshotTraversalForwardsContextAndPreservesBudget(t *testing.T) {
	t.Run("forward-and-cancel", func(t *testing.T) {
		type key struct{}
		base := context.WithValue(context.Background(), key{}, "forwarded")
		deadline := time.Now().Add(time.Hour)
		ctx, cancel := context.WithDeadline(base, deadline)
		defer cancel()

		budget := &snapshotEvaluation{ctx: ctx}
		traversal := &snapshotTraversal{Context: budget.ctx, snapshotEvaluation: budget}

		gotDeadline, gotOK := traversal.Deadline()
		wantDeadline, wantOK := ctx.Deadline()
		if gotOK != wantOK || !gotDeadline.Equal(wantDeadline) {
			t.Fatalf("Deadline() = (%v, %v), want (%v, %v)", gotDeadline, gotOK, wantDeadline, wantOK)
		}
		if traversal.Done() != ctx.Done() {
			t.Fatal("Done() did not forward the underlying cancellation channel")
		}
		if got := traversal.Value(key{}); got != "forwarded" {
			t.Fatalf("Value() = %v, want forwarded value", got)
		}
		if err := traversal.Err(); err != nil {
			t.Fatalf("Err() before cancellation = %v, want nil", err)
		}
		if budget.work != 1 || budget.bytes != 16 {
			t.Fatalf("Err() charge = work %d, bytes %d; want work 1, bytes 16", budget.work, budget.bytes)
		}

		cancel()
		select {
		case <-traversal.Done():
		default:
			t.Fatal("Done() did not close after cancellation")
		}
		if err := traversal.Err(); !errors.Is(err, context.Canceled) {
			t.Fatalf("Err() after cancellation = %v, want context.Canceled", err)
		}
		if budget.work != 1 || budget.bytes != 16 {
			t.Fatalf("canceled Err() changed charge = work %d, bytes %d", budget.work, budget.bytes)
		}
	})

	t.Run("budget-refusal", func(t *testing.T) {
		budget := &snapshotEvaluation{ctx: context.Background(), bytes: maxEvaluationBytes - 8}
		traversal := &snapshotTraversal{Context: budget.ctx, snapshotEvaluation: budget}
		if err := traversal.Err(); !errors.Is(err, ErrEvaluationBudget) {
			t.Fatalf("Err() at exhausted budget = %v, want ErrEvaluationBudget", err)
		}
		if budget.work != 0 || budget.bytes != maxEvaluationBytes-8 {
			t.Fatalf("refused Err() changed charge = work %d, bytes %d", budget.work, budget.bytes)
		}
	})
}
