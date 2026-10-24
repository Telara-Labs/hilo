//go:build linux

package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"
)

func TestSecretServiceNativeLifecycle(t *testing.T) {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Skip("no session bus; native Secret Service lifecycle UNVERIFIED")
	}
	ctx, c := context.WithTimeout(context.Background(), 20*time.Second)
	defer c()
	var id [16]byte
	rand.Read(id[:])
	h := hex.EncodeToString(id[:])
	v := New()
	if e := v.Put(ctx, h, []byte("isolated synthetic native test")); e != nil {
		t.Fatal("Secret Service absent, locked, or prompting", e)
	}
	defer v.Delete(ctx, h)
	if e := v.Put(ctx, h, []byte("replacement")); !errors.Is(e, ErrExists) {
		t.Fatal(e)
	}
	b, e := v.Get(ctx, h)
	if e != nil || !bytes.Equal(b, []byte("isolated synthetic native test")) {
		t.Fatal(e)
	}
	clear(b)
	if e = v.Delete(ctx, h); e != nil {
		t.Fatal(e)
	}
	if b, e = v.Get(ctx, h); b != nil || !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
}
func TestSecretServiceNoBusRefuses(t *testing.T) {
	// Clear only the existing OS transport variable. No new configuration variable.
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	v := New()
	ctx := context.Background()
	h := "0123456789abcdef0123456789abcdef"
	if e := v.Put(ctx, h, []byte("test")); e != ErrUnavailable {
		t.Fatal(e)
	}
	if b, e := v.Get(ctx, h); b != nil || e != ErrUnavailable {
		t.Fatal(e)
	}
	if e := v.Delete(ctx, h); e != ErrUnavailable {
		t.Fatal(e)
	}
}
func TestSecretServiceWriterLockIsLifetimeBound(t *testing.T) {
	ctx := context.Background()
	h := "1123456789abcdef0123456789abcdef"
	l, e := linuxLock(ctx, h)
	if e != nil {
		t.Fatal(e)
	}
	bounded, c := context.WithTimeout(ctx, 50*time.Millisecond)
	defer c()
	if other, e := linuxLock(bounded, h); e == nil {
		other.Close()
		t.Fatal("duplicate writer")
	}
	l.Close()
	next, e := linuxLock(ctx, h)
	if e != nil {
		t.Fatal(e)
	}
	next.Close()
}
