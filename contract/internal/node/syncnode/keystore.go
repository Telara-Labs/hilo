package syncnode

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
)

// SecretVault is the native OS credential store used by installation.
type SecretVault interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}

// One vault slot holds the raw 32-byte P-256 DPoP scalar; a second holds the
// enrolled refresh credential. Native slots are never overwritten in place.
const scalarSize = 32
const maxRefresh = 4096

// VaultKeystore implements the sync keystore over opaque vault slots. Every
// Sign re-reads the key slot, so deletion or rotation revokes old handles.
type VaultKeystore struct {
	Vault   SecretVault
	Key     string
	Refresh string
	Tenant  string
}

func (k VaultKeystore) Load(ctx context.Context, s nodesync.Scope) (nodesync.Credentials, error) {
	if k.Vault == nil || !validHandle(k.Key) || !validHandle(k.Refresh) || s.Tenant != k.Tenant {
		return nodesync.Credentials{}, nodesync.ErrKeystoreUnavailable
	}
	key, err := k.read(ctx)
	if err != nil {
		return nodesync.Credentials{}, nodesync.ErrKeystoreUnavailable
	}
	secret, err := k.Vault.Get(ctx, k.Refresh)
	refresh := string(secret)
	clear(secret)
	if err != nil || len(refresh) == 0 || len(refresh) > maxRefresh {
		return nodesync.Credentials{}, nodesync.ErrKeystoreUnavailable
	}
	public, err := nodesync.PublicJWKOf(&key.PublicKey)
	if err != nil {
		return nodesync.Credentials{}, nodesync.ErrKeystoreUnavailable
	}
	return nodesync.Credentials{Refresh: refresh, DPoP: &vaultSigner{store: k, public: public}}, nil
}

// DeleteTenant attempts both slots even if one deletion fails.
func (k VaultKeystore) DeleteTenant(ctx context.Context, s nodesync.Scope) error {
	if k.Vault == nil || s.Tenant != k.Tenant {
		return nodesync.ErrKeystoreUnavailable
	}
	return DeleteCredentials(ctx, k.Vault, k.Key, k.Refresh)
}

// DeleteCredentials removes the named slots. Missing handles are skipped.
func DeleteCredentials(ctx context.Context, vault SecretVault, handles ...string) error {
	var errs []error
	for _, h := range handles {
		if validHandle(h) {
			if err := vault.Delete(ctx, h); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (k VaultKeystore) read(ctx context.Context) (*ecdsa.PrivateKey, error) {
	secret, err := k.Vault.Get(ctx, k.Key)
	defer clear(secret)
	if err != nil || len(secret) != scalarSize {
		return nil, ErrCredential
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), secret)
	if err != nil {
		return nil, ErrCredential
	}
	return key, nil
}

type vaultSigner struct {
	store  VaultKeystore
	public nodesync.PublicJWK
}

func (s *vaultSigner) PublicJWK() nodesync.PublicJWK { return s.public }
func (s *vaultSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(digest) != sha256.Size {
		return nil, nodesync.ErrKeystoreUnavailable
	}
	key, err := s.store.read(ctx)
	if err != nil {
		return nil, nodesync.ErrKeystoreUnavailable
	}
	current, err := nodesync.PublicJWKOf(&key.PublicKey)
	if err != nil || current != s.public {
		return nil, nodesync.ErrKeystoreUnavailable
	}
	r, v, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, nodesync.ErrKeystoreUnavailable
	}
	return append(r.FillBytes(make([]byte, 32)), v.FillBytes(make([]byte, 32))...), nil
}

// NewCredential creates a fresh DPoP key in a new vault slot. It returns the
// slot handle and the key's jkt thumbprint for hosted enrollment.
func NewCredential(ctx context.Context, vault SecretVault) (handle, jkt string, err error) {
	if vault == nil {
		return "", "", ErrCredential
	}
	handle, err = newHandle()
	if err != nil {
		return "", "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", ErrCredential
	}
	scalar, err := key.Bytes()
	if err != nil {
		return "", "", ErrCredential
	}
	defer clear(scalar)
	if err = vault.Put(ctx, handle, scalar); err != nil {
		return "", "", err
	}
	jkt, err = nodesync.Thumbprint(&key.PublicKey)
	if err != nil {
		return "", "", ErrCredential
	}
	return handle, jkt, nil
}

func newHandle() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrCredential
	}
	return hex.EncodeToString(raw[:]), nil
}

// CredentialThumbprint returns the jkt of the DPoP key in a slot.
func CredentialThumbprint(ctx context.Context, vault SecretVault, handle string) (string, error) {
	key, err := VaultKeystore{Vault: vault, Key: handle}.read(ctx)
	if err != nil {
		return "", err
	}
	return nodesync.Thumbprint(&key.PublicKey)
}

// StoreRefresh places the enrolled refresh credential in a new slot.
func StoreRefresh(ctx context.Context, vault SecretVault, refresh string) (string, error) {
	if len(refresh) == 0 || len(refresh) > maxRefresh {
		return "", ErrEnrollment
	}
	handle, err := newHandle()
	if err != nil {
		return "", err
	}
	secret := []byte(refresh)
	defer clear(secret)
	if err = vault.Put(ctx, handle, secret); err != nil {
		return "", err
	}
	return handle, nil
}
