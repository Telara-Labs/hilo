package custodyguard

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestContentionObserverDoesNotBlockCancellation(t *testing.T) {
	dir := privateDir(t)
	lease, err := BeginUpgrade(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	for _, closed := range []bool{false, true} {
		signal := make(chan struct{})
		if closed {
			close(signal)
		}
		ctx, cancel := context.WithTimeout(ObserveContention(context.Background(), signal), 100*time.Millisecond)
		err := With(ctx, dir, func(context.Context) error { t.Fatal("contender admitted"); return nil })
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("closed=%v: %v", closed, err)
		}
	}
}
