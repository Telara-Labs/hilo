package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/peer"
)

func TestInstalledHandoffRejectsMalformedOrUnboundControl(t *testing.T) {
	callback := installedCustodyHandoff(install.Record{})
	for _, raw := range []string{"", `{"sha256":"x","extra":true}`, `{"sha256":1}`} {
		if e := callback(context.Background(), json.RawMessage(raw)); !errors.Is(e, install.ErrUnverified) {
			t.Fatal(raw, e)
		}
	}
	if e := callback(context.Background(), json.RawMessage(`{"sha256":"x"}`)); !errors.Is(e, peer.ErrAuthority) {
		t.Fatal("unbound control accepted", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := requestCustodyHandoff(ctx, ipc.Paths{}, "x"); e == nil {
		t.Fatal("canceled lifecycle request accepted")
	}
}
