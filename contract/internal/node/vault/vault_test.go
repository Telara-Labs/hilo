package vault

import (
	"context"
	"errors"
	"testing"
)

func TestRejectInvalidInputBeforeNativeAccess(t *testing.T) {
	v := New()
	for _, h := range []string{"", "../secret", "0000000000000000000000000000000G", "ABCDEF0123456789abcdef0123456789", "00"} {
		if err := v.Put(context.Background(), h, []byte("x")); !errors.Is(err, ErrInvalid) {
			t.Fatal(h, err)
		}
		if _, err := v.Get(context.Background(), h); !errors.Is(err, ErrInvalid) {
			t.Fatal(h, err)
		}
		if err := v.Delete(context.Background(), h); !errors.Is(err, ErrInvalid) {
			t.Fatal(h, err)
		}
	}
	h := "0123456789abcdef0123456789abcdef"
	for _, b := range [][]byte{nil, make([]byte, maxSecret+1)} {
		if err := v.Put(context.Background(), h, b); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := v.Put(ctx, h, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := v.Get(ctx, h); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := v.Delete(ctx, h); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := v.Get(nil, h); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	var absent *Vault
	if _, err := absent.Get(context.Background(), h); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	closed := &Vault{closed: true}
	if err := closed.Put(context.Background(), h, []byte("x")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed vault fallback", err)
	}
	if _, err := closed.Get(context.Background(), h); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed vault fallback", err)
	}
	if err := closed.Delete(context.Background(), h); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed vault fallback", err)
	}
}
