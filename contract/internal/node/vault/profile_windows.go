//go:build windows

package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"golang.org/x/sys/windows"
)

type windowsCreator struct {
	Version  int    `json:"version"`
	Handle   string `json:"handle"`
	SID      string `json:"owner_sid"`
	Expected string `json:"expected_sha256"`
	Phase    string `json:"phase"`
}

func windowsOwner() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", ErrUnavailable
	}
	return u.User.Sid.String(), nil
}

func windowsCreatorName(h string) string { return "custody-windows-" + h + ".json" }

func (r windowsCreator) valid(h string) bool {
	sid, err := windowsOwner()
	b, decode := hex.DecodeString(r.Expected)
	return err == nil && r.Version == 1 && r.SID == sid && r.Handle == h && valid(context.Background(), h) == nil && decode == nil && len(b) == sha256.Size && hex.EncodeToString(b) == r.Expected &&
		(r.Phase == "planned" || r.Phase == "bound" || r.Phase == "collision" || r.Phase == "deleted")
}

func readWindowsCreator(dir, handle string) (windowsCreator, error) {
	var r windowsCreator
	if ipc.ValidateDir(dir, false) != nil || valid(context.Background(), handle) != nil {
		return r, ErrUnavailable
	}
	path := filepath.Join(dir, windowsCreatorName(handle))
	if _, err := os.Lstat(path); err != nil {
		return r, err
	}
	if err := ipc.ValidatePrivateFile(path); err != nil {
		return r, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return r, err
	}
	defer root.Close()
	f, err := root.Open(windowsCreatorName(handle))
	if err != nil {
		return r, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() > 4096 {
		return r, ErrUnavailable
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(st, after) || ipc.ValidatePrivateFile(path) != nil {
		return r, ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return r, ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || !r.valid(handle) {
		return windowsCreator{}, ErrUnavailable
	}
	return r, nil
}

// Caller holds the native per-handle mutex. The owner-only private directory,
// no-reparse file validation and exact prior record protect the publication.
func writeWindowsCreator(dir string, prior *windowsCreator, r windowsCreator) error {
	if !r.valid(r.Handle) || ipc.ValidateDir(dir, false) != nil {
		return ErrUnavailable
	}
	path := filepath.Join(dir, windowsCreatorName(r.Handle))
	if prior != nil {
		got, err := readWindowsCreator(dir, r.Handle)
		if err != nil || got != *prior {
			return ErrUnavailable
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".custody-windows-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	if err := ipc.ValidatePrivateFile(name); err != nil {
		return err
	}
	source, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if prior != nil {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(source, target, flags)
}

func windowsMatches(r windowsCreator, b []byte) bool {
	if len(b) == 0 || len(b) > maxSecret {
		return false
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]) == r.Expected
}

func (v *Vault) putProfile(ctx context.Context, handle string, secret []byte) error {
	return locked(ctx, handle, func() error {
		if _, err := readWindowsCreator(v.profile, handle); err == nil {
			return ErrExists
		} else if !os.IsNotExist(err) {
			return err
		}
		sid, err := windowsOwner()
		if err != nil {
			return err
		}
		sum := sha256.Sum256(secret)
		r := windowsCreator{1, handle, sid, hex.EncodeToString(sum[:]), "planned"}
		old, probe := read(handle)
		clear(old)
		if probe == nil {
			r.Phase = "collision"
			if err := writeWindowsCreator(v.profile, nil, r); err != nil {
				return err
			}
			return ErrExists
		}
		if !errors.Is(probe, ErrNotFound) {
			return probe
		}
		// The existing native Put still performs its no-replacement check under
		// this same thread-owned mutex. A preexisting slot remains a collision.
		if err := writeWindowsCreator(v.profile, nil, r); err != nil {
			return err
		}
		if err := v.put(ctx, handle, secret); err != nil {
			if errors.Is(err, ErrExists) {
				next := r
				next.Phase = "collision"
				_ = writeWindowsCreator(v.profile, &r, next)
			}
			return err
		}
		got, err := read(handle)
		matched := windowsMatches(r, got)
		clear(got)
		if err != nil || !matched {
			return ErrUnavailable
		}
		next := r
		next.Phase = "bound"
		return writeWindowsCreator(v.profile, &r, next)
	})
}

func (v *Vault) getProfile(ctx context.Context, handle string) ([]byte, error) {
	r, err := readWindowsCreator(v.profile, handle)
	if os.IsNotExist(err) {
		return v.get(ctx, handle)
	}
	if err != nil || r.Phase == "collision" {
		return nil, ErrUnavailable
	}
	if r.Phase == "deleted" {
		return nil, ErrNotFound
	}
	b, err := v.get(ctx, handle)
	if err != nil || !windowsMatches(r, b) {
		clear(b)
		return nil, ErrUnavailable
	}
	return b, nil
}

func (v *Vault) deleteProfile(ctx context.Context, handle string) error {
	return v.deleteWindowsProfile(ctx, handle, false)
}

func (v *Vault) deleteWindowsProfile(ctx context.Context, handle string, planned bool) error {
	return locked(ctx, handle, func() error {
		r, err := readWindowsCreator(v.profile, handle)
		if os.IsNotExist(err) {
			if planned {
				return nil
			} // v2 never attempted creation; no native call.
			return ErrUnavailable // Unknown legacy ownership remains retained.
		}
		if err != nil || r.Phase == "collision" {
			return ErrUnavailable
		}
		if r.Phase == "deleted" {
			return nil
		}
		b, err := read(handle)
		matched := windowsMatches(r, b)
		clear(b)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil {
			if !matched {
				return ErrUnavailable
			}
			if err := v.delete(ctx, handle); err != nil {
				return err
			}
		}
		next := r
		next.Phase = "deleted"
		return writeWindowsCreator(v.profile, &r, next)
	})
}

func (v *Vault) AbandonPlanned(ctx context.Context, handle string) error {
	if v == nil || ctx == nil || valid(ctx, handle) != nil || v.profile == "" {
		return ErrInvalid
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrUnavailable
	}
	return v.deleteWindowsProfile(ctx, handle, true)
}
