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
	bus                 string
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
func openSession(ctx context.Context, create bool, collection dbus.ObjectPath) (*linuxSession, error) {
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
	if conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetId", 0).Store(&s.bus) != nil || len(s.bus) != 32 {
		return fail()
	}
	s.collection = collection
	if collection == "" {
		if s.call(secretRoot, "Service.ReadAlias", collectionAlias).Store(&s.collection) != nil {
			return fail()
		}
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

// Search absence alone cannot retire a recorded item. A retained/moved item
// or an ambiguous backend error must preserve custody evidence.
func (s *linuxSession) itemAbsent(item dbus.ObjectPath) bool {
	var secret wireSecret
	e := s.call(item, "Item.GetSecret", s.session).Store(&secret)
	clear(secret.Value)
	var name string
	switch typed := e.(type) {
	case dbus.Error:
		name = typed.Name
	case *dbus.Error:
		if typed != nil {
			name = typed.Name
		}
	}
	return name == "org.freedesktop.DBus.Error.UnknownObject" || name == "org.freedesktop.DBus.Error.NoSuchObject" || name == "org.freedesktop.Secret.Error.NoSuchObject"
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

// selectedSession never resolves an alias after custody selection.
func (v *Vault) selectedSession(ctx context.Context, create bool) (*linuxSession, error) {
	var collection dbus.ObjectPath
	if v.secretService != nil {
		collection = dbus.ObjectPath(v.secretService.Collection)
	}
	if collection == "" && !create {
		return nil, ErrUnavailable
	}
	s, e := openSession(ctx, create, collection)
	if e != nil {
		return nil, e
	}
	if v.secretService == nil {
		v.secretService = &secretServiceLocation{Version: 1, Collection: string(s.collection), Bus: s.bus, Owner: s.owner, State: "selected"}
	}
	return s, nil
}

// Resolve an interrupted CreateItem only in the originally recorded collection.
// After a service/bus restart, absence cannot establish deletion or no creation.
func (v *Vault) locateLinux(s *linuxSession, h string) (dbus.ObjectPath, error) {
	m := *v.secretService
	if m.Handle != h || m.State == "selected" {
		return "", ErrUnavailable
	}
	if m.State == "deleted" {
		return "", ErrNotFound
	}
	item, e := s.find(h)
	if e == ErrNotFound {
		if m.Bus != s.bus || m.Owner != s.owner {
			return "", ErrUnavailable
		}
		if m.Item != "" && !s.itemAbsent(dbus.ObjectPath(m.Item)) {
			return "", ErrUnavailable
		}
	}
	if e != nil {
		return "", e
	}
	if (m.State == "bound" || m.State == "ready") && string(item) != m.Item {
		return "", ErrUnavailable
	}
	if m.State == "creating" || m.Bus != s.bus || m.Owner != s.owner {
		m.Item, m.Bus, m.Owner = string(item), s.bus, s.owner
		if m.State == "creating" {
			m.State = "bound"
		}
		if e = v.saveLinuxLocation(m); e != nil {
			return "", e
		}
	}
	return item, nil
}

func (v *Vault) put(ctx context.Context, h string, b []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	lock, e := linuxLock(ctx, h)
	if e != nil {
		return e
	}
	defer lock.Close()
	s, e := v.selectedSession(ctx, true)
	if e != nil {
		return e
	}
	defer s.close()
	m := *v.secretService
	if m.State == "deleted" {
		m.Handle, m.Item, m.State = "", "", "selected"
	}
	if m.State != "selected" {
		if _, e = v.locateLinux(s, h); e == nil {
			return ErrExists
		} else if e != ErrNotFound {
			return e
		}
	} else {
		if _, e = s.find(h); e == nil {
			return ErrExists
		} else if e != ErrNotFound {
			return e
		}
	}
	m.Handle, m.Item, m.State, m.Bus, m.Owner = h, "", "creating", s.bus, s.owner
	if e = v.saveLinuxLocation(m); e != nil {
		return e
	}
	props := map[string]dbus.Variant{"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("Telara Memory runtime authority"), "org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(map[string]string{"service": service, "handle": h})}
	var item, prompt dbus.ObjectPath
	if s.call(s.collection, "Collection.CreateItem", props, wireSecret{s.session, []byte{}, []byte{}, "application/octet-stream"}, false).Store(&item, &prompt) != nil || prompt != "/" || !item.IsValid() || item == "/" {
		return ErrUnavailable
	}
	found, e := s.find(h)
	if e != nil || found != item {
		return ErrUnavailable
	}
	// Publish the exact backend item identity before any authority is sent.
	m.Item, m.State = string(item), "bound"
	if e = v.saveLinuxLocation(m); e != nil {
		return e
	}
	if s.call(item, "Item.SetSecret", wireSecret{s.session, []byte{}, b, "application/octet-stream"}).Err != nil {
		return ErrUnavailable
	}
	m.State = "ready"
	return v.saveLinuxLocation(m)
}
func (v *Vault) get(ctx context.Context, h string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, e := v.selectedSession(ctx, false)
	if e != nil {
		return nil, e
	}
	defer s.close()
	item, e := v.locateLinux(s, h)
	if e != nil {
		return nil, e
	}
	var secret wireSecret
	if s.call(item, "Item.GetSecret", s.session).Store(&secret) != nil {
		clear(secret.Value)
		return nil, ErrUnavailable
	}
	if secret.Session != s.session || len(secret.Parameters) != 0 || len(secret.Value) == 0 || len(secret.Value) > maxSecret {
		clear(secret.Value)
		return nil, ErrUnavailable
	}
	return secret.Value, nil
}
func (v *Vault) delete(ctx context.Context, h string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	lock, e := linuxLock(ctx, h)
	if e != nil {
		return e
	}
	defer lock.Close()
	s, e := v.selectedSession(ctx, false)
	if e != nil {
		return e
	}
	defer s.close()
	if v.secretService.State == "selected" {
		// Selection precedes handle publication and every native creation intent.
		// No CreateItem was attempted in this generation. Refuse any unexplained
		// item instead of deleting it by guessing its identity.
		if _, e = s.find(h); e != ErrNotFound {
			return ErrUnavailable
		}
		m := *v.secretService
		m.Handle, m.State = h, "deleted"
		return v.saveLinuxLocation(m)
	}
	item, e := v.locateLinux(s, h)
	if e != nil && e != ErrNotFound {
		return e
	}
	if e == nil {
		var prompt dbus.ObjectPath
		if s.call(item, "Item.Delete").Store(&prompt) != nil || prompt != "/" {
			return ErrUnavailable
		}
		if _, e = s.find(h); e != ErrNotFound || !s.itemAbsent(item) {
			return ErrUnavailable
		}
	}
	m := *v.secretService
	// Retain exact item identity even after physical deletion for crash-safe retries.
	m.State = "deleted"
	return v.saveLinuxLocation(m)
}
