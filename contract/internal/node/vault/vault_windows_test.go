package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
)

func TestNativeCredentialManagerLifecycleAndConcurrentPut(t *testing.T) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString(id[:])
	ctx := context.Background()
	v := New()
	t.Cleanup(func() {
		if err := v.Delete(ctx, h); err != nil {
			t.Error(err)
		}
	})
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- v.Put(ctx, h, []byte{0, 1, 0, 255}) }()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrExists) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatal(wins)
	}
	b, err := New().Get(ctx, h)
	if err != nil || !bytes.Equal(b, []byte{0, 1, 0, 255}) {
		t.Fatal(err)
	}
	clear(b)
	b, err = v.Get(ctx, h)
	if err != nil || b[1] != 1 {
		t.Fatal(err)
	}
	clear(b)
	if err := v.Delete(ctx, h); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(ctx, h); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

// Credential Manager targets are per handle, so one user holds several
// independent secrets for a profile at the same time.
func TestNativeCredentialManagerHoldsIndependentHandles(t *testing.T) {
	ctx := context.Background()
	handles := make([]string, 4)
	for i := range handles {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			t.Fatal(err)
		}
		handles[i] = hex.EncodeToString(id[:])
	}
	t.Cleanup(func() {
		for _, h := range handles {
			_ = New().Delete(ctx, h)
		}
	})
	for i, h := range handles {
		if err := New().Put(ctx, h, []byte{byte(i + 1)}); err != nil {
			t.Fatal("additional handle refused", i, err)
		}
	}
	if err := New().Delete(ctx, handles[0]); err != nil {
		t.Fatal(err)
	}
	for i, h := range handles[1:] {
		b, err := New().Get(ctx, h)
		if err != nil || !bytes.Equal(b, []byte{byte(i + 2)}) {
			t.Fatal("handle lost", i, err)
		}
		clear(b)
	}
	if _, err := New().Get(ctx, handles[0]); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
