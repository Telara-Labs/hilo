//go:build linux

package vault

import (
	"context"
	"fmt"
	"github.com/godbus/dbus/v5"
	"net"
	"os"
	"strings"
	"time"
)

const secretService = "org.freedesktop.secrets"
const secretRoot dbus.ObjectPath = "/org/freedesktop/secrets"
const collectionAlias = "telara-memory"

type linuxSession struct {
	conn                *dbus.Conn
	owner               string
	session, collection dbus.ObjectPath
	ctx                 context.Context
}
type wireSecret struct {
	Session           dbus.ObjectPath
	Parameters, Value []byte
	ContentType       string
}

func (s *linuxSession) call(path dbus.ObjectPath, method string, args ...any) *dbus.Call {
	return s.conn.Object(s.owner, path).CallWithContext(s.ctx, "org.freedesktop.Secret."+method, 0, args...)
}
func openSession(ctx context.Context, create bool) (*linuxSession, error) {
	// No autolaunch or prompt. A service must already own its session-bus name.
	address := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if !strings.HasPrefix(address, "unix:") || strings.Contains(address, ";") || len(address) > 8192 {
		return nil, ErrUnavailable
	}
	conn, e := dbus.Connect(address, dbus.WithContext(ctx))
	if e != nil {
		return nil, ErrUnavailable
	}
	s := &linuxSession{conn: conn, ctx: ctx}
	fail := func() (*linuxSession, error) { conn.Close(); return nil, ErrUnavailable }
	if conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, secretService).Store(&s.owner) != nil {
		return fail()
	}
	var output dbus.Variant
	if s.call(secretRoot, "Service.OpenSession", "plain", dbus.MakeVariant("")).Store(&output, &s.session) != nil || !s.session.IsValid() || s.session == "/" {
		return fail()
	}
	if s.call(secretRoot, "Service.ReadAlias", collectionAlias).Store(&s.collection) != nil {
		return fail()
	}
	if s.collection == "/" && create {
		var prompt dbus.ObjectPath
		props := map[string]dbus.Variant{"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant("Telara Memory")}
		if s.call(secretRoot, "Service.CreateCollection", props, collectionAlias).Store(&s.collection, &prompt) != nil || prompt != "/" {
			return fail()
		}
	}
	if !s.collection.IsValid() || s.collection == "/" {
		return fail()
	}
	var locked dbus.Variant
	if conn.Object(s.owner, s.collection).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.Secret.Collection", "Locked").Store(&locked) != nil || locked.Value() != false {
		return fail()
	}
	return s, nil
}
func (s *linuxSession) close() { _ = s.call(s.session, "Session.Close").Err; s.conn.Close() }
func (s *linuxSession) find(h string) (dbus.ObjectPath, error) {
	var items []dbus.ObjectPath
	if s.call(s.collection, "Collection.SearchItems", map[string]string{"service": service, "handle": h}).Store(&items) != nil {
		return "", ErrUnavailable
	}
	if len(items) == 0 {
		return "", ErrNotFound
	}
	if len(items) != 1 || !items[0].IsValid() {
		return "", ErrUnavailable
	}
	return items[0], nil
}
func linuxLock(ctx context.Context, h string) (*net.UnixListener, error) {
	addr := &net.UnixAddr{Name: fmt.Sprintf("@%s.%d.%s", service, os.Geteuid(), h), Net: "unix"}
	for {
		l, e := net.ListenUnix("unix", addr)
		if e == nil {
			return l, nil
		}
		select {
		case <-ctx.Done():
			return nil, ErrUnavailable
		case <-time.After(20 * time.Millisecond):
		}
	}
}
func (*Vault) put(ctx context.Context, h string, b []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	lock, e := linuxLock(ctx, h)
	if e != nil {
		return e
	}
	defer lock.Close()
	s, e := openSession(ctx, true)
	if e != nil {
		return e
	}
	defer s.close()
	if _, e = s.find(h); e == nil {
		return ErrExists
	} else if e != ErrNotFound {
		return e
	}
	props := map[string]dbus.Variant{"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("Telara Memory runtime authority"), "org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(map[string]string{"service": service, "handle": h})}
	var item, prompt dbus.ObjectPath
	if s.call(s.collection, "Collection.CreateItem", props, wireSecret{s.session, []byte{}, b, "application/octet-stream"}, false).Store(&item, &prompt) != nil || prompt != "/" || !item.IsValid() || item == "/" {
		return ErrUnavailable
	}
	return nil
}
func (*Vault) get(ctx context.Context, h string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, e := openSession(ctx, false)
	if e != nil {
		return nil, e
	}
	defer s.close()
	item, e := s.find(h)
	if e != nil {
		return nil, e
	}
	var secret wireSecret
	if s.call(item, "Item.GetSecret", s.session).Store(&secret) != nil {
		return nil, ErrUnavailable
	}
	if secret.Session != s.session || len(secret.Parameters) != 0 || len(secret.Value) == 0 || len(secret.Value) > maxSecret {
		clear(secret.Value)
		return nil, ErrUnavailable
	}
	return secret.Value, nil
}
func (*Vault) delete(ctx context.Context, h string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	lock, e := linuxLock(ctx, h)
	if e != nil {
		return e
	}
	defer lock.Close()
	s, e := openSession(ctx, false)
	if e != nil {
		return e
	}
	defer s.close()
	item, e := s.find(h)
	if e == ErrNotFound {
		return nil
	}
	if e != nil {
		return e
	}
	var prompt dbus.ObjectPath
	if s.call(item, "Item.Delete").Store(&prompt) != nil || prompt != "/" {
		return ErrUnavailable
	}
	return nil
}
