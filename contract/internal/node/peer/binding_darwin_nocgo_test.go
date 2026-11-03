//go:build darwin && !cgo

package peer

import (
	"context"
	"net"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

func TestStaticDarwinDiagnosticsCarryNoAuthority(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, release, e := BindConnection(context.Background(), a)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if _, present := ctx.Value(bindingKey{}).(processBinding); present {
		t.Fatal("static diagnostic invented a binding")
	}
	if e := VerifyLifecycle(ctx, install.Record{}); e == nil {
		t.Fatal("diagnostic control granted authority")
	}
	if e := (Authority{}).VerifyAndDrain(ctx, ipc.Hello{PID: 1}, "credential"); e == nil {
		t.Fatal("diagnostic granted proof")
	}
}
