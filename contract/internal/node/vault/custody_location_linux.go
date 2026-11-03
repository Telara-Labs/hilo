//go:build linux

package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const custodyLocationFile = "custody-location.json"

// custodyItemPrefix names one handle's custody record. Each handle owns an
// independent record, written only while that handle's writer lock is held,
// so concurrent operations on different handles never rewrite each other.
const custodyItemPrefix = "custody-item-"

func custodyItemFile(h string) string { return custodyItemPrefix + h + ".json" }

func readLinuxLocation(data string) (*secretServiceLocation, error) {
	return readLinuxRecord(data, custodyLocationFile)
}

func readLinuxRecord(data, name string) (*secretServiceLocation, error) {
	if ipc.ValidateDir(data, false) != nil {
		return nil, ErrUnavailable
	}
	fd, e := unix.Open(filepath.Join(data, name), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, ErrUnavailable
	}
	meta, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || meta.Uid != uint32(os.Geteuid()) || meta.Nlink != 1 || st.Size() > 16384 {
		return nil, ErrUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(raw) > 16384 {
		return nil, ErrUnavailable
	}
	var m secretServiceLocation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || !validLinuxLocation(m) {
		return nil, ErrUnavailable
	}
	return &m, nil
}

func validLinuxLocation(m secretServiceLocation) bool {
	if m.Version != 1 || !dbus.ObjectPath(m.Collection).IsValid() || m.Collection == "/" || len(m.Collection) > 4096 || len(m.Item) > 4096 || len(m.Bus) != 32 || !strings.HasPrefix(m.Owner, ":") || len(m.Owner) > 255 {
		return false
	}
	if m.Alias != "" && m.Alias != collectionAlias && m.Alias != legacyCollectionAlias && m.Alias != defaultAlias {
		return false
	}
	if m.Creation != "" && valid(context.Background(), m.Creation) != nil {
		return false
	}
	switch m.State {
	case "selected":
		return m.Handle == "" && m.Item == "" && m.Creation == ""
	case "creating":
		// Recovery adopts only an item carrying this record's creation value.
		return valid(context.Background(), m.Handle) == nil && m.Item == "" && m.Creation != ""
	case "deleted":
		return valid(context.Background(), m.Handle) == nil && (m.Item == "" || (dbus.ObjectPath(m.Item).IsValid() && m.Item != "/"))
	case "bound", "ready":
		return valid(context.Background(), m.Handle) == nil && dbus.ObjectPath(m.Item).IsValid() && m.Item != "/"
	}
	return false
}

// Persist collection selection before a provisioning handle exists. Secret
// Service assigns item paths only during CreateItem. Create an empty placeholder
// under a durable intent, persist its assigned path, then send authority only
// through SetSecret. A crash cannot leave secret custody at an unrecorded path.
func (v *Vault) bindCustody(ctx context.Context, data string, create bool) error {
	m, e := readLinuxLocation(data)
	if os.IsNotExist(e) && create {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		s, e := openSession(ctx, true, "")
		if e != nil {
			return e
		}
		defer s.close()
		m = &secretServiceLocation{Version: 1, Collection: string(s.collection), Alias: s.alias, Bus: s.bus, Owner: s.owner, State: "selected"}
		if e = writeLinuxLocation(data, *m); e != nil {
			return e
		}
	} else if e != nil {
		return ErrUnavailable
	}
	// A confirmed deletion permits the next provisioning generation. Reset
	// before the caller publishes its new handle, so a pre-Put crash is provably
	// a no-creation state rather than an unexplained handle mismatch.
	if create && m.State == "deleted" {
		m.Handle, m.Item, m.Creation, m.State = "", "", "", "selected"
		if e = writeLinuxLocation(data, *m); e != nil {
			return e
		}
	}
	v.secretService = m
	v.profile = data
	return nil
}

func writeLinuxLocation(data string, m secretServiceLocation) error {
	return writeLinuxRecord(data, custodyLocationFile, m)
}

func writeLinuxRecord(data, name string, m secretServiceLocation) error {
	if !validLinuxLocation(m) || ipc.ValidateDir(data, false) != nil {
		return ErrUnavailable
	}
	raw, e := json.Marshal(m)
	if e != nil || len(raw) > 16384 {
		return ErrUnavailable
	}
	f, e := os.CreateTemp(data, "."+strings.TrimSuffix(name, ".json")+"-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(raw); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(f.Name(), filepath.Join(data, name)); e != nil {
		return e
	}
	dir, e := os.Open(data)
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

// linuxSlot reports where a handle's custody state lives.
type linuxSlot int

const (
	// slotNone: this profile has never recorded a creation intent for the handle.
	slotNone linuxSlot = iota
	// slotItem: the handle's own record.
	slotItem
	// slotLegacy: a record written before per-handle records, which kept its
	// single handle in the selection record itself.
	slotLegacy
)

// linuxEntry reads the handle's custody state. A per-handle record must name
// the handle and the profile's selected collection. A handle recorded both in
// the legacy selection record and in its own record is ambiguous and refuses.
func (v *Vault) linuxEntry(h string) (secretServiceLocation, linuxSlot, error) {
	main := *v.secretService
	legacy := main.State != "selected" && main.Handle == h
	if v.profile == "" {
		if m, ok := v.secretItems[h]; ok {
			return m, slotItem, nil
		}
		if legacy {
			return main, slotLegacy, nil
		}
		return secretServiceLocation{}, slotNone, nil
	}
	m, e := readLinuxRecord(v.profile, custodyItemFile(h))
	if os.IsNotExist(e) {
		if legacy {
			return main, slotLegacy, nil
		}
		return secretServiceLocation{}, slotNone, nil
	}
	if e != nil || legacy || m.Handle != h || m.Collection != main.Collection || m.State == "selected" {
		return secretServiceLocation{}, slotNone, ErrUnavailable
	}
	return *m, slotItem, nil
}

// saveLinuxEntry durably replaces one handle's state. Only the holder of that
// handle's writer lock calls it, so the read-modify-write cannot lose another
// handle's update.
func (v *Vault) saveLinuxEntry(m secretServiceLocation, slot linuxSlot) error {
	if slot == slotLegacy {
		return v.saveLinuxLocation(m)
	}
	if v.profile != "" {
		if e := writeLinuxRecord(v.profile, custodyItemFile(m.Handle), m); e != nil {
			return e
		}
	}
	if v.secretItems == nil {
		v.secretItems = map[string]secretServiceLocation{}
	}
	v.secretItems[m.Handle] = m
	return nil
}

func (v *Vault) saveLinuxLocation(m secretServiceLocation) error {
	if v.profile != "" {
		if e := writeLinuxLocation(v.profile, m); e != nil {
			return e
		}
	}
	v.secretService = &m
	return nil
}
