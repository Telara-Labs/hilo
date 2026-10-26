//go:build linux

package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/godbus/dbus/v5"
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
	m := v.secretItems[h]
	t.Logf("selected alias=%s collection=%s item=%s", m.Alias, m.Collection, m.Item)
	if m.State != "ready" || m.Creation == "" || (m.Alias != collectionAlias && m.Alias != defaultAlias) {
		t.Fatal("custody identity not recorded", m.State, m.Alias)
	}
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
	if v.secretItems[h].State != "deleted" || v.secretItems[h].Item != m.Item {
		t.Fatal("deletion not recorded against the exact item")
	}
}

// A real service must never let custody adopt an item another client made
// with the same handle. The test removes only the item it planted.
func TestSecretServiceNativeForeignItemRefused(t *testing.T) {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Skip("no session bus; native Secret Service foreign item refusal UNVERIFIED")
	}
	ctx, c := context.WithTimeout(context.Background(), 20*time.Second)
	defer c()
	var id [16]byte
	rand.Read(id[:])
	h := hex.EncodeToString(id[:])
	s, e := openSession(ctx, true, "")
	if e != nil {
		t.Fatal("Secret Service absent, locked, or prompting", e)
	}
	defer s.close()
	props := map[string]dbus.Variant{"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("foreign test item"), "org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(map[string]string{"service": service, "handle": h})}
	var item, prompt dbus.ObjectPath
	if e = s.call(s.collection, "Collection.CreateItem", props, wireSecret{s.session, []byte{}, []byte("foreign"), "text/plain"}, false).Store(&item, &prompt); e != nil || prompt != "/" {
		t.Fatal(e)
	}
	defer s.call(item, "Item.Delete")
	v := New()
	if e = v.Put(ctx, h, []byte("isolated synthetic native test")); !errors.Is(e, ErrExists) {
		t.Fatal("foreign item adopted", e)
	}
	if e = v.Delete(ctx, h); !errors.Is(e, ErrUnavailable) {
		t.Fatal("foreign item deleted", e)
	}
	var secret wireSecret
	if e = s.call(item, "Item.GetSecret", s.session).Store(&secret); e != nil || string(secret.Value) != "foreign" {
		t.Fatal("foreign item changed", e)
	}
	var prompt2 dbus.ObjectPath
	if e = s.call(item, "Item.Delete").Store(&prompt2); e != nil || prompt2 != "/" {
		t.Fatal(e)
	}
	if !s.itemAbsent(item, map[string]string{"service": service, "handle": h}) {
		t.Fatal("real service deletion not proven")
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
