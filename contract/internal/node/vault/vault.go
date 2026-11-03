// Package vault keeps installed runtime secrets in the operating system vault.
// There is no file, environment or command-line secret fallback.
package vault

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
)

var (
	ErrUnavailable         = errors.New("secret_vault_unavailable")
	ErrKeychainUnavailable = keychainUnavailable{}
	ErrExists              = errors.New("secret_vault_handle_exists")
	ErrNotFound            = errors.New("secret_vault_handle_missing")
	ErrInvalid             = errors.New("secret_vault_invalid_input")
)

// Immutable native credential lookup/lock namespace. Preserve existing handles
// across the Hilo rename; product labels and new collection names use Hilo.
const service = "dev.telara.memory.runtime"
const maxSecret = 2560

// Vault uses only native credential custody. The zero value uses the owner's
// default OS vault. Each Get returns an independent caller-owned byte slice.
type secretServiceLocation struct {
	Version    int    `json:"version"`
	Collection string `json:"collection"`
	// Alias names how the collection was selected. Empty means a record
	// written before the default-collection path, which always used the
	// dedicated alias.
	Alias  string `json:"alias,omitempty"`
	Item   string `json:"item"`
	Handle string `json:"handle"`
	// Creation is a random per-generation attribute known only to this
	// record. It proves that a recovered item was created by this profile.
	Creation string `json:"creation,omitempty"`
	Bus      string `json:"bus"`
	Owner    string `json:"owner"`
	State    string `json:"state"`
}

type Vault struct {
	mu            sync.Mutex
	secretService *secretServiceLocation
	// secretItems holds per-handle Secret Service state for a vault without a
	// profile. A profile keeps each handle's state in its own durable record.
	secretItems  map[string]secretServiceLocation
	keychain     uintptr
	keychainPath string
	profile      string
	closed       bool
}

func New() *Vault { return &Vault{} }

// ForProfile pins native custody to the durable profile location.
func ForProfile(data string) *Vault { return &Vault{profile: data} }

func valid(ctx context.Context, handle string) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := hex.DecodeString(handle)
	if err != nil || len(b) != 16 {
		return ErrInvalid
	}
	for _, c := range handle {
		if c >= 'A' && c <= 'F' {
			return ErrInvalid
		}
	}
	return nil
}

func (v *Vault) Put(ctx context.Context, handle string, secret []byte) error {
	if err := valid(ctx, handle); err != nil {
		return err
	}
	if v == nil || len(secret) == 0 || len(secret) > maxSecret {
		return ErrInvalid
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrUnavailable
	}
	if v.profile != "" {
		if err := v.bindCustody(ctx, v.profile, true); err != nil {
			return err
		}
		return v.putProfile(ctx, handle, secret)
	}
	return v.put(ctx, handle, secret)
}
func (v *Vault) Get(ctx context.Context, handle string) ([]byte, error) {
	if err := valid(ctx, handle); err != nil {
		return nil, err
	}
	if v == nil {
		return nil, ErrInvalid
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, ErrUnavailable
	}
	if v.profile != "" {
		if err := v.bindCustody(ctx, v.profile, false); err != nil {
			return nil, err
		}
		return v.getProfile(ctx, handle)
	}
	return v.get(ctx, handle)
}
func (v *Vault) Delete(ctx context.Context, handle string) error {
	if err := valid(ctx, handle); err != nil {
		return err
	}
	if v == nil {
		return ErrInvalid
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrUnavailable
	}
	if v.profile != "" {
		if err := v.bindCustody(ctx, v.profile, false); err != nil {
			return err
		}
		return v.deleteProfile(ctx, handle)
	}
	return v.delete(ctx, handle)
}

type keychainUnavailable struct{}

func (keychainUnavailable) Error() string { return "keychain_unavailable" }
func (keychainUnavailable) Unwrap() error { return ErrUnavailable }
