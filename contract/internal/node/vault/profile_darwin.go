//go:build darwin && cgo

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

	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

// creatorReceipt binds one logical handle to one exact native creator. The
// commitment covers high-entropy key/credential bytes, never transcript text.
// A receipt is fsynced before native creation; an Exists verdict is a collision,
// never permission to adopt or delete the preexisting item.
type creatorReceipt struct {
	Version   int    `json:"version"`
	Handle    string `json:"handle"`
	Image     string `json:"image"`
	Digest    string `json:"image_sha256"`
	Namespace string `json:"namespace"`
	Keychain  string `json:"keychain"`
	Expected  string `json:"expected_sha256"`
	Phase     string `json:"phase"`
}

func creatorName(handle string) string { return "custody-creator-" + handle + ".json" }

func (r creatorReceipt) valid(handle string) bool {
	return r.Version == 1 && r.Handle == handle && valid(context.Background(), handle) == nil &&
		digestValid(r.Digest) && digestValid(r.Expected) && filepath.IsAbs(r.Image) && filepath.Clean(r.Image) == r.Image &&
		len(r.Namespace) > 0 && len(r.Namespace) <= 1024 && filepath.IsAbs(r.Keychain) && filepath.Clean(r.Keychain) == r.Keychain &&
		(r.Phase == "planned" || r.Phase == "bound" || r.Phase == "collision" || r.Phase == "deleted")
}

func readCreator(dir, handle string) (creatorReceipt, error) {
	var r creatorReceipt
	if valid(context.Background(), handle) != nil {
		return r, ErrInvalid
	}
	b, err := privateRead(filepath.Join(dir, creatorName(handle)))
	if err != nil {
		return r, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || !r.valid(handle) {
		return creatorReceipt{}, ErrUnavailable
	}
	return r, nil
}

func writeCreator(dir string, prior *creatorReceipt, next creatorReceipt) error {
	if !next.valid(next.Handle) || ipc.ValidateDir(dir, false) != nil {
		return ErrUnavailable
	}
	path := filepath.Join(dir, creatorName(next.Handle))
	if prior != nil {
		current, err := readCreator(dir, next.Handle)
		if err != nil || current != *prior {
			return ErrUnavailable
		}
	}
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if prior == nil {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(b)
		if err == nil {
			err = f.Sync()
		}
		closed := f.Close()
		if err != nil {
			return err
		}
		if closed != nil {
			return closed
		}
		return syncHandoffDir(dir)
	}
	f, err := os.CreateTemp(dir, ".custody-creator-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncHandoffDir(dir)
}

func (v *Vault) creatorOperation(ctx context.Context, r creatorReceipt, op byte, secret []byte) ([]byte, error) {
	if !r.valid(r.Handle) || r.Keychain != v.keychainPath {
		return nil, ErrUnavailable
	}
	namespace, err := v.imageOperation(ctx, r.Image, r.Digest, 5, r.Handle, nil)
	if err != nil || string(namespace) != r.Namespace {
		return nil, ErrUnavailable
	}
	return v.imageOperation(ctx, r.Image, r.Digest, op, r.Handle, secret)
}

func (v *Vault) newCreator(ctx context.Context, handle string, secret []byte) (creatorReceipt, error) {
	var r creatorReceipt
	// Installed profiles use the receipt-owning retained helper even when this
	// command was launched from a transient release/download location.
	if v.profile != "" {
		b, read := privateReadLimit(filepath.Join(v.profile, "authority-bootstrap.json"), 32768)
		if read == nil {
			var p struct {
				Version int             `json:"version"`
				Handle  string          `json:"vault_handle"`
				Phase   string          `json:"phase"`
				Creator *install.Record `json:"creator,omitempty"`
			}
			d := json.NewDecoder(bytes.NewReader(b))
			d.DisallowUnknownFields()
			if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Version != 1 {
				return r, ErrUnavailable
			}
			if p.Creator != nil {
				status, err := install.Status(ctx, p.Creator.Dir)
				if (err != nil && !errors.Is(err, install.ErrUnavailable)) || status.Record.DataDir != v.profile || status.Record.Dir != p.Creator.Dir {
					return r, ErrUnavailable
				}
				return v.creatorForImage(ctx, handle, secret, status.Record.Executable, status.Record.SHA256)
			}
		} else if !os.IsNotExist(read) {
			return r, read
		}
	}
	path, err := os.Executable()
	if err != nil {
		return r, err
	}
	f, err := os.Open(path)
	if err != nil {
		return r, err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (512<<20)+1))
	closed := f.Close()
	if err != nil || closed != nil || n > 512<<20 {
		return r, ErrUnavailable
	}
	digest := hex.EncodeToString(h.Sum(nil))
	pin, err := pinHandoffImage(path, digest)
	if err != nil {
		return r, err
	}
	defer pin.Close()
	// A join can create native credentials before it has an install receipt.
	// Retain the exact caller image before publishing any credential intent.
	if v.profile != "" {
		dir := filepath.Join(v.profile, "custody-creators", digest)
		if err := ipc.ValidateDir(dir, true); err != nil {
			return r, err
		}
		retained := filepath.Join(dir, "hilo")
		if _, err := os.Lstat(retained); os.IsNotExist(err) {
			f, err := os.CreateTemp(dir, ".creator-image-")
			if err != nil {
				return r, err
			}
			defer os.Remove(f.Name())
			if err = f.Chmod(0700); err == nil {
				_, err = pin.Seek(0, 0)
			}
			if err == nil {
				_, err = io.Copy(f, io.LimitReader(pin, (512<<20)+1))
			}
			if err == nil {
				err = f.Sync()
			}
			closed := f.Close()
			if err != nil {
				return r, err
			}
			if closed != nil {
				return r, closed
			}
			if err = os.Link(f.Name(), retained); err != nil && !os.IsExist(err) {
				return r, err
			}
			// A retained executable must be single-link when pinHandoffImage
			// checks it. Remove only our exact temporary link before dispatch;
			// the existing retained path is never removed on a collision.
			if err = os.Remove(f.Name()); err != nil {
				return r, err
			}
			if err = syncHandoffDir(dir); err != nil {
				return r, err
			}
		} else if err != nil {
			return r, err
		}
		path = retained
	}
	return v.creatorForImage(ctx, handle, secret, path, digest)
}

func (v *Vault) creatorForImage(ctx context.Context, handle string, secret []byte, path, digest string) (creatorReceipt, error) {
	var r creatorReceipt
	namespace, err := v.imageOperation(ctx, path, digest, 5, handle, nil)
	if err != nil {
		return r, err
	}
	expected := sha256.Sum256(secret)
	r = creatorReceipt{1, handle, path, digest, string(namespace), v.keychainPath, hex.EncodeToString(expected[:]), "planned"}
	if !r.valid(handle) {
		return creatorReceipt{}, ErrUnavailable
	}
	return r, nil
}

func (v *Vault) putProfile(ctx context.Context, handle string, secret []byte) error {
	lock, err := ipc.Lock(filepath.Join(v.profile, "custody-creator-"+handle+".lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := readCreator(v.profile, handle); !os.IsNotExist(err) {
		return ErrExists
	}
	r, err := v.newCreator(ctx, handle, secret)
	if err != nil {
		return err
	}
	// A preexisting own-slot item is a collision even if bytes happen to match.
	old, probe := v.creatorOperation(ctx, r, 9, nil)
	clear(old)
	if probe == nil {
		r.Phase = "collision"
	} else if !errors.Is(probe, ErrNotFound) {
		return probe
	}
	if err := writeCreator(v.profile, nil, r); err != nil {
		return err
	}
	if r.Phase == "collision" {
		return ErrExists
	}
	_, err = v.creatorOperation(ctx, r, 1, secret)
	if errors.Is(err, ErrExists) {
		next := r
		next.Phase = "collision"
		if save := writeCreator(v.profile, &r, next); save != nil {
			return errors.Join(ErrExists, save)
		}
		return ErrExists
	}
	if err != nil {
		return err
	} // Planned receipt retains ambiguous acknowledgement.
	readback, err := v.creatorOperation(ctx, r, 9, nil)
	defer clear(readback)
	if err != nil || !creatorMatches(r, readback) {
		return ErrUnavailable
	}
	next := r
	next.Phase = "bound"
	return writeCreator(v.profile, &r, next)
}

func creatorMatches(r creatorReceipt, secret []byte) bool {
	if len(secret) == 0 || len(secret) > maxSecret {
		return false
	}
	sum := sha256.Sum256(secret)
	return hex.EncodeToString(sum[:]) == r.Expected
}

func (v *Vault) getProfile(ctx context.Context, handle string) ([]byte, error) {
	lock, err := ipc.Lock(filepath.Join(v.profile, "custody-creator-"+handle+".lock"))
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	r, err := readCreator(v.profile, handle)
	if os.IsNotExist(err) {
		return v.get(ctx, handle)
	} // Legacy read only; no adoption.
	if err != nil {
		return nil, err
	}
	if r.Phase == "deleted" {
		return nil, ErrNotFound
	}
	if r.Phase == "collision" {
		return nil, ErrUnavailable
	}
	secret, err := v.creatorOperation(ctx, r, 9, nil)
	if err != nil {
		clear(secret)
		return nil, err
	}
	if !creatorMatches(r, secret) {
		clear(secret)
		return nil, ErrUnavailable
	}
	// Reads never change creator metadata. A planned receipt already commits to
	// these exact bytes; only the fenced creator or lifecycle owner may advance
	// its phase, including after an ambiguous native Put acknowledgement.
	return secret, nil
}

func (v *Vault) deleteProfile(ctx context.Context, handle string) error {
	lock, err := ipc.Lock(filepath.Join(v.profile, "custody-creator-"+handle+".lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	r, err := readCreator(v.profile, handle)
	if err != nil {
		return ErrUnavailable
	} // Unknown legacy ownership is retained.
	if r.Phase == "deleted" {
		return nil
	}
	if r.Phase == "collision" {
		return ErrUnavailable
	}
	secret, err := v.creatorOperation(ctx, r, 9, nil)
	if err == nil && !creatorMatches(r, secret) {
		clear(secret)
		return ErrUnavailable
	}
	clear(secret)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil {
		if _, err := v.creatorOperation(ctx, r, 6, nil); err != nil {
			return err
		}
	}
	next := r
	next.Phase = "deleted"
	return writeCreator(v.profile, &r, next)
}

// AbandonPlanned is only for an owner's validated, not-yet-active v2 typed
// descriptor. No creator receipt means this protocol never attempted native
// creation, so no native lookup or deletion is allowed. A planned receipt
// permits cleanup only when its exact creator proves absence or matching
// committed bytes. It never adopts a collision or an unknown legacy slot.
func (v *Vault) AbandonPlanned(ctx context.Context, handle string) error {
	if v == nil || ctx == nil || valid(ctx, handle) != nil || v.profile == "" {
		return ErrInvalid
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrUnavailable
	}
	if err := v.bindCustody(ctx, v.profile, false); err != nil {
		return err
	}
	lock, err := ipc.Lock(filepath.Join(v.profile, "custody-creator-"+handle+".lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	r, err := readCreator(v.profile, handle)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || (r.Phase != "planned" && r.Phase != "bound" && r.Phase != "deleted") {
		return ErrUnavailable
	}
	if r.Phase == "deleted" {
		return nil
	}
	secret, err := v.creatorOperation(ctx, r, 9, nil)
	matched := creatorMatches(r, secret)
	clear(secret)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil {
		if !matched {
			return ErrUnavailable
		}
		if _, err := v.creatorOperation(ctx, r, 6, nil); err != nil {
			return err
		}
	}
	next := r
	next.Phase = "deleted"
	return writeCreator(v.profile, &r, next)
}
