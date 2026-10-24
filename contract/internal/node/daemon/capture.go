package daemon

import (
	"context"
	"errors"
)

type captureDrainKey struct{}

// WithCaptureDrain binds the live collector to an in-process authenticated
// proof operation. This context capability is never decoded from IPC metadata.
func WithCaptureDrain(ctx context.Context, drain func(context.Context, string) error) context.Context {
	return context.WithValue(ctx, captureDrainKey{}, drain)
}

// DrainCapture is called only after installed peer verification and before live
// scope resolution. A missing collector is explicit, allowing the peer to keep
// its historical empty-spool-only compatibility path.
func DrainCapture(ctx context.Context, credential string) (bool, error) {
	if ctx == nil || ctx.Err() != nil || credential == "" {
		return true, errors.New("capture_unavailable")
	}
	drain, ok := ctx.Value(captureDrainKey{}).(func(context.Context, string) error)
	if !ok || drain == nil {
		return false, nil
	}
	return true, drain(ctx, credential)
}
