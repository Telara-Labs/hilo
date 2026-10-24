package daemon

import (
	"context"
	"errors"
	"testing"
)

func TestCaptureDrainContextCapability(t *testing.T) {
	if wired, err := DrainCapture(context.Background(), "credential"); wired || err != nil {
		t.Fatal(wired, err)
	}
	called := 0
	ctx := WithCaptureDrain(context.Background(), func(_ context.Context, credential string) error {
		called++
		if credential != "credential" {
			t.Fatal("credential changed")
		}
		return errors.New("denied")
	})
	if wired, err := DrainCapture(ctx, "credential"); !wired || err == nil || called != 1 {
		t.Fatal(wired, err, called)
	}
	// The collector may have applied identity while retaining an unsettled
	// transcript. Its successful result, rather than spool emptiness, governs.
	pending := WithCaptureDrain(context.Background(), func(context.Context, string) error { return nil })
	if wired, err := DrainCapture(pending, "credential"); !wired || err != nil {
		t.Fatal("processed pending identity refused", wired, err)
	}
	if _, err := DrainCapture(nil, "credential"); err == nil {
		t.Fatal("nil context")
	}
	if _, err := DrainCapture(ctx, ""); err == nil || called != 1 {
		t.Fatal("empty credential invoked drain")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := DrainCapture(cancelled, "credential"); err == nil || called != 1 {
		t.Fatal("cancelled drain invoked")
	}
}
