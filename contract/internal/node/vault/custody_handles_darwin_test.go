//go:build darwin && cgo

package vault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// Keychain custody keys each item by its own handle, so one profile holds the
// installed authority, export key and sync credentials at the same time.
func TestNativeKeychainHoldsIndependentHandles(t *testing.T) {
	v, path := isolatedVault(t)
	ctx := context.Background()
	handles := make([]string, 4)
	for i := range handles {
		var b [16]byte
		if _, e := rand.Read(b[:]); e != nil {
			t.Fatal(e)
		}
		handles[i] = hex.EncodeToString(b[:])
		if e := v.Put(ctx, handles[i], []byte(fmt.Sprint("secret ", i))); e != nil {
			t.Fatal("additional handle refused", i, e)
		}
	}
	other, e := openIsolated(path)
	if e != nil {
		t.Fatal(e)
	}
	defer other.closeIsolated()
	// Replace one credential: new slot first, then retire the old one.
	var b [16]byte
	if _, e = rand.Read(b[:]); e != nil {
		t.Fatal(e)
	}
	replacement := hex.EncodeToString(b[:])
	if e = other.Put(ctx, replacement, []byte("replacement")); e != nil {
		t.Fatal(e)
	}
	if e = other.Delete(ctx, handles[3]); e != nil {
		t.Fatal(e)
	}
	for i, h := range handles[:3] {
		got, e := other.Get(ctx, h)
		if e != nil || string(got) != fmt.Sprint("secret ", i) {
			t.Fatal("handle lost", i, e)
		}
		clear(got)
	}
	if got, e := v.Get(ctx, handles[3]); got != nil || !errors.Is(e, ErrNotFound) {
		t.Fatal("retired handle readable", e)
	}
	for _, h := range append(handles[:3:3], replacement) {
		if e = v.Delete(ctx, h); e != nil {
			t.Fatal(e)
		}
		if got, e := other.Get(ctx, h); got != nil || !errors.Is(e, ErrNotFound) {
			t.Fatal("deleted handle readable", e)
		}
	}
}
