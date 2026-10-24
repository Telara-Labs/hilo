//go:build darwin && !cgo

package vault

import (
	"context"
	"errors"
	"testing"
)

func TestUnavailableNativeCustodyRefusesEveryOperation(t *testing.T) {
	v := New()
	ctx := context.Background()
	h := "0123456789abcdef0123456789abcdef"
	if err := v.Put(ctx, h, []byte("secret")); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if b, err := v.Get(ctx, h); b != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if err := v.Delete(ctx, h); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
