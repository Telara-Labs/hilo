package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

func TestArgumentsAndPublicCodes(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"status", "--bad"}, {"daemon", "extra"}} {
		if run(context.Background(), args, strings.NewReader(""), &bytes.Buffer{}) == nil {
			t.Fatal(args)
		}
	}
	for _, e := range []error{errors.New("private-secret"), ipc.ErrUnsafe, ipc.ErrPeer, ipc.ErrBusy, ipc.ErrFrame} {
		if strings.Contains(publicCode(e), "secret") {
			t.Fatal("raw error")
		}
	}
}
