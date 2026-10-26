// Package syncnode runs hosted metadata sync inside the local daemon. It owns
// the typed sync profile, the durable outbox and cursors, the metadata
// exporter and the HELLO, PULL, ENFORCE, PUSH, APPLY and ACK round. Sync is
// disabled unless an explicit enrolled profile enables it.
package syncnode

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// ProfileVersion is the only accepted profile document version.
const ProfileVersion = 1

var (
	ErrProfile      = errors.New("sync_profile_invalid")
	ErrNotEnrolled  = errors.New("sync_not_enrolled")
	ErrIdentity     = errors.New("sync_identity_mismatch")
	ErrCredential   = errors.New("sync_credential_unavailable")
	ErrEnrollment   = errors.New("sync_enrollment_invalid")
	ErrUnsupported  = errors.New("sync_unsupported")
	errStateInvalid = errors.New("sync_state_invalid")
)

// ServiceKey is a tenant service (receipt) key. It is a receipt authority
// only when the profile records that it was pinned from the authenticated TLS
// login response (ServiceKeyPins); keys named by an enrollment document read
// from terminal input are never pins.
type ServiceKey struct {
	KeyID  string `json:"key_id"`
	Public string `json:"public"`
}

// Profile is the typed, owner-only sync configuration. A missing profile and
// Enabled=false both mean sync is off. Credential names an opaque vault slot
// holding the DPoP key and refresh credential; no secret is stored here.
type Profile struct {
	Version     int                 `json:"version"`
	Enabled     bool                `json:"enabled"`
	Genesis     string              `json:"genesis"`
	Device      string              `json:"device"`
	Credential  string              `json:"credential"`
	Refresh     string              `json:"refresh,omitempty"`
	Origin      string              `json:"origin,omitempty"`
	Tenant      string              `json:"tenant,omitempty"`
	User        string              `json:"user,omitempty"`
	Config      string              `json:"config,omitempty"`
	AuthIssuer  string              `json:"auth_issuer,omitempty"`
	AuthKey     *nodesync.PublicJWK `json:"auth_key,omitempty"`
	ServiceKeys []ServiceKey        `json:"service_keys,omitempty"`
	// ServiceKeyPins is the provenance of ServiceKeys. Only "pinned-tls-login",
	// set when every key came from the origin's authenticated login response
	// over validated TLS, makes them receipt authority.
	ServiceKeyPins string                `json:"service_key_pins,omitempty"`
	Grant          *nodesync.MemoryGrant `json:"grant,omitempty"`
	// Retired names credential slots this profile no longer uses whose
	// deletion is not yet established. A slot is recorded here before it is
	// created or replaced and removed only after its deletion succeeded.
	Retired []string `json:"retired,omitempty"`
}

// maxRetired bounds recorded retired slots; each replacement adds at most two.
const maxRetired = 16

// Enrolled reports whether every hosted field required to run is present.
func (p Profile) Enrolled() bool {
	return p.Refresh != "" && p.Origin != "" && p.Tenant != "" && p.User != "" && p.Config != "" && p.AuthIssuer != "" && p.AuthKey != nil && len(p.ServiceKeys) > 0 && p.Grant != nil
}

// ServiceKeysPinned reports whether ServiceKeys are receipt authority: keys of
// an enrolled profile pinned from the authenticated TLS login response.
func (p Profile) ServiceKeysPinned() bool {
	return p.Enrolled() && p.ServiceKeyPins == string(sig.PinnedTLSLogin)
}

// Scope is the authenticated destination for this profile.
func (p Profile) Scope() nodesync.Scope {
	return nodesync.Scope{Origin: p.Origin, Tenant: p.Tenant, User: p.User, Config: p.Config, Genesis: p.Genesis, Device: p.Device}
}

func (p Profile) validate() error {
	if p.Version != ProfileVersion || !record.IsKeyID(p.Genesis) || !record.IsUUIDv4(p.Device) || !validHandle(p.Credential) || len(p.Retired) > maxRetired {
		return ErrProfile
	}
	retired := map[string]bool{}
	for _, h := range p.Retired {
		if !validHandle(h) || retired[h] || h == p.Credential || h == p.Refresh {
			return ErrProfile
		}
		retired[h] = true
	}
	if p.ServiceKeyPins != "" && p.ServiceKeyPins != string(sig.PinnedTLSLogin) {
		return ErrProfile
	}
	if !p.Enrolled() {
		if p.ServiceKeyPins != "" || p.Enabled || p.Refresh != "" || p.Origin != "" || p.Tenant != "" || p.User != "" || p.Config != "" || p.AuthIssuer != "" || p.AuthKey != nil || len(p.ServiceKeys) != 0 || p.Grant != nil {
			return ErrProfile
		}
		return nil
	}
	if !validHandle(p.Refresh) || p.Refresh == p.Credential {
		return ErrProfile
	}
	u, err := url.Parse(p.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return ErrProfile
	}
	if len(p.Tenant) > 200 || len(p.User) > 200 || len(p.Config) > 200 || len(p.AuthIssuer) > 2048 || len(p.ServiceKeys) > 16 {
		return ErrProfile
	}
	if _, err := p.AuthKey.PublicKey(); err != nil {
		return ErrProfile
	}
	seen := map[string]bool{}
	for _, k := range p.ServiceKeys {
		if _, err := k.public(); err != nil || seen[k.KeyID] {
			return ErrProfile
		}
		seen[k.KeyID] = true
	}
	g := p.Grant
	if g.Origin != "local" || g.GenesisID != p.Genesis || g.DeviceID != p.Device || len(g.Repos) == 0 || len(g.Ops) == 0 {
		return ErrProfile
	}
	return nil
}

func (k ServiceKey) public() (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(k.Public)
	if err != nil || len(raw) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(raw) != k.Public {
		return nil, ErrProfile
	}
	if sig.KeyID(raw) != k.KeyID {
		return nil, ErrProfile
	}
	return ed25519.PublicKey(raw), nil
}

func validHandle(h string) bool {
	b, err := hex.DecodeString(h)
	return err == nil && len(b) == 16 && strings.ToLower(h) == h
}

// LoadProfile reads the profile. A missing profile returns os.ErrNotExist.
func LoadProfile(dir string) (Profile, error) {
	var p Profile
	b, err := store.ReadSyncProfile(dir)
	if err != nil {
		return p, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return Profile{}, ErrProfile
	}
	if err := p.validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// SaveProfile validates and atomically replaces the profile.
func SaveProfile(dir string, p Profile) error {
	if err := p.validate(); err != nil {
		return err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return ErrProfile
	}
	return store.WriteSyncProfile(dir, b)
}

// Disabled reports whether a load error means sync is simply not configured.
func Disabled(err error) bool { return errors.Is(err, os.ErrNotExist) }

// destination keys every durable table by the authenticated scope, so a mode
// or tenant switch cannot reuse another target's cursors, receipts or rows.
func destination(s nodesync.Scope) string {
	h := sha256.New()
	for _, part := range []string{s.Origin, s.Tenant, s.User, s.Config, s.Genesis, s.Device} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func profileDigest(p Profile) string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
