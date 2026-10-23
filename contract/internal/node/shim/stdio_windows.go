package shim

import (
	"context"
	"io"
	"os"
)

// Go's Windows pipe Close uses CancelIoEx for synchronous inherited pipes too.
// Keep the native file so Run's cancellation watchers close both directions.
func cancelableFile(_ context.Context, f *os.File) (io.ReadWriter, func(), error) {
	return f, func() {}, nil
}
