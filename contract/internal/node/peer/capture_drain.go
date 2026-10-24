package peer

import (
	"context"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
)

// Only VerifyAndDrain invokes this after checking the installed peer image.
func (a Authority) drain(ctx context.Context, credential string) error {
	if a.Drain != nil {
		return a.Drain(ctx, credential)
	}
	if wired, err := daemon.DrainCapture(ctx, credential); wired {
		return err
	}
	return emptySpool(a.DataDir)
}
