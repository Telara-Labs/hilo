//go:build linux

package vault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/godbus/dbus/v5"
	"net"
	"os"
	"strings"
	"time"
)

const secretService = "org.freedesktop.secrets"
const secretRoot dbus.ObjectPath = "/org/freedesktop/secrets"

// collectionAlias is preferred. Services that refuse non-default aliases, such
// as GNOME Keyring, select the default collection instead.
const collectionAlias = "telara-memory"
const defaultAlias = "default"

type linuxSession struct {
	conn                *dbus.Conn
	owner               string
	bus                 string
	alias               string
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
func (s *linuxSession) property(path dbus.ObjectPath, iface, name string) (dbus.Variant, error) {
	var value dbus.Variant
	e := s.conn.Object(s.owner, path).CallWithContext(s.ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, name).Store(&value)
	return value, e
}

// dbusErrorName reports whether e is an error reply sent by the service, as
// opposed to a transport, context or decoding failure.
func dbusErrorName(e error) (string, bool) {
	var value dbus.Error
	if errors.As(e, &value) {
		return value.Name, true
	}
	var pointer *dbus.Error
	if errors.As(e, &pointer) && pointer != nil {
		return pointer.Name, true
	}
	return "", false
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
	if collection == "" && s.selectCollection(create) != nil {
		return fail()
	}
	if !s.collection.IsValid() || s.collection == "/" {
		return fail()
	}
	locked, e := s.property(s.collection, "org.freedesktop.Secret.Collection", "Locked")
	if e != nil || locked.Value() != false {
		return fail()
	}
	return s, nil
}

// selectCollection runs once per profile, before any handle exists. It prefers
// the dedicated alias and creates it only without a prompt. An explicit service
// refusal or a required prompt selects the default collection; the prompt is
// dismissed, never shown. A transport failure refuses instead of guessing.
func (s *linuxSession) selectCollection(create bool) error {
	var path dbus.ObjectPath
	if s.call(secretRoot, "Service.ReadAlias", collectionAlias).Store(&path) != nil {
		return ErrUnavailable
	}
	if path != "/" {
		s.collection, s.alias = path, collectionAlias
		return nil
	}
	if !create {
		return ErrUnavailable
	}
	var prompt dbus.ObjectPath
	props := map[string]dbus.Variant{"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant("Telara Memory")}
	e := s.call(secretRoot, "Service.CreateCollection", props, collectionAlias).Store(&path, &prompt)
	if e == nil && prompt == "/" {
		s.collection, s.alias = path, collectionAlias
		return nil
	}
	if e == nil {
		if prompt.IsValid() {
			_ = s.call(prompt, "Prompt.Dismiss").Err
		}
	} else if _, replied := dbusErrorName(e); !replied {
		return ErrUnavailable
	}
	path = ""
	if s.call(secretRoot, "Service.ReadAlias", defaultAlias).Store(&path) != nil {
		return ErrUnavailable
	}
	s.collection, s.alias = path, defaultAlias
	return nil
}
func (s *linuxSession) close() { _ = s.call(s.session, "Session.Close").Err; s.conn.Close() }

// attributes are the exact item attributes of the recorded generation.
func (m secretServiceLocation) attributes() map[string]string {
	a := map[string]string{"service": service, "handle": m.Handle}
	if m.Creation != "" {
		a["creation"] = m.Creation
	}
	return a
}
func (s *linuxSession) find(attrs map[string]string) (dbus.ObjectPath, error) {
	var items []dbus.ObjectPath
	if s.call(s.collection, "Collection.SearchItems", attrs).Store(&items) != nil {
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

// itemAbsent proves deletion of the exact recorded item from three independent
// observations of the same live collection. The exact attribute search is
// empty. The collection's Items property lists neither the recorded path nor
// is it unreadable. The recorded path itself answers GetSecret with an
// object-missing error. GNOME Keyring reports a missing path as UnknownMethod,
// which a live object with a missing method also returns. That error is never
// proof alone, only together with the search and the item listing.
func (s *linuxSession) itemAbsent(item dbus.ObjectPath, attrs map[string]string) bool {
	if _, e := s.find(attrs); e != ErrNotFound {
		return false
	}
	listed, e := s.property(s.collection, "org.freedesktop.Secret.Collection", "Items")
	if e != nil {
		return false
	}
	paths, ok := listed.Value().([]dbus.ObjectPath)
	if !ok {
		return false
	}
	for _, path := range paths {
		if path == item {
			return false
		}
	}
	var secret wireSecret
	e = s.call(item, "Item.GetSecret", s.session).Store(&secret)
	clear(secret.Value)
	switch name, _ := dbusErrorName(e); name {
	case "org.freedesktop.DBus.Error.UnknownObject", "org.freedesktop.DBus.Error.NoSuchObject", "org.freedesktop.Secret.Error.NoSuchObject", "org.freedesktop.DBus.Error.UnknownMethod":
		return true
	}
	return false
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
		v.secretService = &secretServiceLocation{Version: 1, Collection: string(s.collection), Alias: s.alias, Bus: s.bus, Owner: s.owner, State: "selected"}
	}
	return s, nil
}

// Resolve an interrupted CreateItem only in the originally recorded collection
// and only for an item carrying this record's creation value.
// After a service/bus restart, absence cannot establish deletion or no creation.
func (v *Vault) locateLinux(s *linuxSession, m secretServiceLocation, slot linuxSlot) (dbus.ObjectPath, error) {
	if slot == slotNone || m.State == "selected" {
		return "", ErrUnavailable
	}
	if m.State == "deleted" {
		return "", ErrNotFound
	}
	attrs := m.attributes()
	item, e := s.find(attrs)
	if e == ErrNotFound {
		if m.Bus != s.bus || m.Owner != s.owner {
			return "", ErrUnavailable
		}
		if m.Item != "" && !s.itemAbsent(dbus.ObjectPath(m.Item), attrs) {
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
		if e = v.saveLinuxEntry(m, slot); e != nil {
			return "", e
		}
	}
	return item, nil
}

// put creates a new item for h. Each handle has its own creation generation
// and custody record, so a profile holds any number of independent secrets.
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
	m, slot, e := v.linuxEntry(h)
	if e != nil {
		return e
	}
	if slot != slotNone && m.State != "deleted" {
		if _, e = v.locateLinux(s, m, slot); e == nil {
			return ErrExists
		} else if e != ErrNotFound {
			return e
		}
	}
	// Never adopt or overwrite an item this generation did not create, even
	// one that merely shares the handle in a shared default collection.
	if _, e = s.find(map[string]string{"service": service, "handle": h}); e == nil {
		return ErrExists
	} else if e != ErrNotFound {
		return e
	}
	var creation [16]byte
	if _, e = rand.Read(creation[:]); e != nil {
		return ErrUnavailable
	}
	if slot == slotNone {
		slot = slotItem
	}
	sel := *v.secretService
	m = secretServiceLocation{Version: 1, Collection: sel.Collection, Alias: sel.Alias, Handle: h, Creation: hex.EncodeToString(creation[:]), State: "creating", Bus: s.bus, Owner: s.owner}
	if e = v.saveLinuxEntry(m, slot); e != nil {
		return e
	}
	props := map[string]dbus.Variant{"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("Telara Memory runtime authority"), "org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(m.attributes())}
	var item, prompt dbus.ObjectPath
	if s.call(s.collection, "Collection.CreateItem", props, wireSecret{s.session, []byte{}, []byte{}, "application/octet-stream"}, false).Store(&item, &prompt) != nil || prompt != "/" || !item.IsValid() || item == "/" {
		return ErrUnavailable
	}
	found, e := s.find(m.attributes())
	if e != nil || found != item {
		return ErrUnavailable
	}
	// Publish the exact backend item identity before any authority is sent.
	m.Item, m.State = string(item), "bound"
	if e = v.saveLinuxEntry(m, slot); e != nil {
		return e
	}
	if s.call(item, "Item.SetSecret", wireSecret{s.session, []byte{}, b, "application/octet-stream"}).Err != nil {
		return ErrUnavailable
	}
	m.State = "ready"
	return v.saveLinuxEntry(m, slot)
}
func (v *Vault) get(ctx context.Context, h string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, e := v.selectedSession(ctx, false)
	if e != nil {
		return nil, e
	}
	defer s.close()
	m, slot, e := v.linuxEntry(h)
	if e != nil {
		return nil, e
	}
	item, e := v.locateLinux(s, m, slot)
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
	m, slot, e := v.linuxEntry(h)
	if e != nil {
		return e
	}
	if slot == slotNone {
		// Every native creation is preceded by a durable per-handle intent. No
		// record means no CreateItem was attempted for this handle by this
		// profile. Refuse any unexplained item instead of deleting it by
		// guessing its identity.
		if _, e = s.find(map[string]string{"service": service, "handle": h}); e != ErrNotFound {
			return ErrUnavailable
		}
		sel := *v.secretService
		return v.saveLinuxEntry(secretServiceLocation{Version: 1, Collection: sel.Collection, Alias: sel.Alias, Handle: h, State: "deleted", Bus: s.bus, Owner: s.owner}, slotItem)
	}
	item, e := v.locateLinux(s, m, slot)
	if e != nil && e != ErrNotFound {
		return e
	}
	if e == nil {
		var prompt dbus.ObjectPath
		if s.call(item, "Item.Delete").Store(&prompt) != nil || prompt != "/" {
			return ErrUnavailable
		}
		if !s.itemAbsent(item, m.attributes()) {
			return ErrUnavailable
		}
	}
	// Re-read: locating may have bound an interrupted creation's exact path.
	if m, _, e = v.linuxEntry(h); e != nil {
		return e
	}
	// Retain exact item identity even after physical deletion for crash-safe retries.
	m.State = "deleted"
	return v.saveLinuxEntry(m, slot)
}
