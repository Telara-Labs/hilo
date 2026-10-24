package vault

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
)

func TestInstalledCustodyRefusesInvalidOwnerBeforeNativeAccess(t *testing.T) {
	h := strings.Repeat("a", 32)
	for _, v := range []Installed{{}, {Vault: &Vault{closed: true}}, {Vault: New(), Record: install.Record{Dir: "relative"}}} {
		if e := v.Put(context.Background(), h, []byte("x")); e == nil {
			t.Fatal("unverified put accepted")
		}
		if _, e := v.Get(context.Background(), h); e == nil {
			t.Fatal("unverified get accepted")
		}
		if e := v.Delete(context.Background(), h); e == nil {
			t.Fatal("unverified delete accepted")
		}
	}
	v := Installed{Vault: New()}
	if e := v.Vault.DeleteCreatedForInstall(context.Background(), install.Record{}, h); e == nil {
		t.Fatal("creator deletion without receipt")
	}
	if _, e := v.Vault.ReadForInstall(context.Background(), install.Record{}, h); e == nil {
		t.Fatal("legacy readback without receipt")
	}
	if e := v.Put(context.Background(), h, nil); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if e := v.Put(context.Background(), h, make([]byte, maxSecret+1)); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if _, e := v.Get(nil, h); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	ctx, c := context.WithCancel(context.Background())
	c()
	if e := v.Delete(ctx, h); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
