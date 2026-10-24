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

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const custodyLocationFile = "custody-location.json"

func readLinuxLocation(data string) (*secretServiceLocation, error) {
	if ipc.ValidateDir(data, false) != nil {
		return nil, ErrUnavailable
	}
	fd, e := unix.Open(filepath.Join(data, custodyLocationFile), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), custodyLocationFile)
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
	switch m.State {
	case "selected":
		return m.Handle == "" && m.Item == ""
	case "creating":
		return valid(context.Background(), m.Handle) == nil && m.Item == ""
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
		m = &secretServiceLocation{Version: 1, Collection: string(s.collection), Bus: s.bus, Owner: s.owner, State: "selected"}
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
		m.Handle, m.Item, m.State = "", "", "selected"
		if e = writeLinuxLocation(data, *m); e != nil {
			return e
		}
	}
	v.secretService = m
	v.profile = data
	return nil
}

func writeLinuxLocation(data string, m secretServiceLocation) error {
	if !validLinuxLocation(m) || ipc.ValidateDir(data, false) != nil {
		return ErrUnavailable
	}
	raw, e := json.Marshal(m)
	if e != nil || len(raw) > 16384 {
		return ErrUnavailable
	}
	f, e := os.CreateTemp(data, ".custody-location-")
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
	if e = os.Rename(f.Name(), filepath.Join(data, custodyLocationFile)); e != nil {
		return e
	}
	dir, e := os.Open(data)
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
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
