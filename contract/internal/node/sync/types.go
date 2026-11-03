// Package sync implements the metadata-only hosted push transport. It does not
// implement pull, control reconciliation, login UI, or durable storage. A caller
// must reconcile controls before enabling pushes and implement Outbox atomically.
package sync

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"time"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

const (
	MaxRecords      = 64
	MaxRequestBytes = 4 << 20
	MaxRetryDelay   = 5 * time.Minute
)

var (
	ErrKeystoreUnavailable = errors.New("keystore_unavailable")
	ErrInvalid             = errors.New("invalid_sync_data")
	ErrForbidden           = errors.New("sync_path_forbidden")
	ErrLoggedOut           = errors.New("sync_logged_out")
	ErrToken               = errors.New("invalid_memory_session")
	ErrReceipt             = errors.New("invalid_memory_receipt")
	ErrCancelled           = errors.New("sync_authority_cancelled")
)

// Scope is authenticated login configuration, never record-authored metadata.
// Origin is the public HTTPS origin. This client always uses the local grant.
type Scope struct {
	Origin, Tenant, User, Config, Genesis, Device string
}

// MemoryGrant matches Auth's snake_case JWT shape. Mint requests encode its
// int64 expiry as a string, as accepted by protobuf JSON at the gateway.
type MemoryGrant struct {
	Ops           []string `json:"ops"`
	Repos         []string `json:"repos"`
	Origin        string   `json:"origin"`
	GenesisID     string   `json:"genesis_id"`
	DeviceID      string   `json:"device_id"`
	ExpiresAtUnix int64    `json:"expires_at_unix"`
}

// Credentials must be returned from a tenant-scoped OS store. Refresh is a
// node-scoped bootstrap key authorized for memory, never a session token.
// Load returns only a public identity and a non-exportable DPoP signing handle.
type Credentials struct {
	Refresh string
	DPoP    DPoPSigner
}

// DPoPSigner retains the private key inside the tenant-scoped keystore. PublicJWK
// returns a cached public-only identity. Sign accepts exactly a SHA-256 digest
// and returns an ES256 signature as 64 bytes R || S, never ASN.1 or key material.
// Sign must check ctx and current tenant/key authority on every call. Deletion
// or rotation invalidates previously returned handles; a handle cannot retain a
// private-key copy that survives DeleteTenant. No store transaction spans Sign.
type DPoPSigner interface {
	PublicJWK() PublicJWK
	Sign(context.Context, []byte) ([]byte, error)
}

type Keystore interface {
	Load(context.Context, Scope) (Credentials, error)
	DeleteTenant(context.Context, Scope) error
}

// OSKeystore is an intentionally unavailable placeholder, with no file fallback.
// Platform credential integration is a separate dependency and acceptance gate.
type OSKeystore struct{}

func (OSKeystore) Load(context.Context, Scope) (Credentials, error) {
	return Credentials{}, ErrKeystoreUnavailable
}
func (OSKeystore) DeleteTenant(context.Context, Scope) error { return ErrKeystoreUnavailable }

type Limits struct{ Records, WireBytes, DecodedBytes int }

// Outbox methods end their transactions before returning. Next supplies the
// oldest durable operation, with controls first, and must never rebuild or split
// an operation once its op_id has been assigned. Persist Operation.Bytes and its
// Digest together; RestoreOperation verifies that digest on restart.
type Outbox interface {
	Next(context.Context, Scope, Limits) (*Operation, error)
	// Authorize rechecks selection/version, live/tomb/lineage state, empty
	// grants, resolved ancestry and current policy AND control reconciliation.
	// False atomically cancels the operation, never granting fresh authority.
	// It runs immediately before EVERY HTTP send, including retries after mint.
	Authorize(context.Context, Scope, string, string) (bool, error)
	// Complete atomically persists all verified receipts and terminal unavailable
	// statuses, completing exactly these rows under op_id + digest CAS. A partial
	// response is never passed here. This MUST NOT advance either pull cursor.
	Complete(context.Context, Scope, Acknowledgment) error
	// Retry persists the next eligible attempt before sleeping or returning a
	// transient failure. Next must honor this deadline after process restart.
	// Update under op_id + digest CAS; never replace the operation's wire bytes.
	Retry(context.Context, Scope, Retry) error
	// Logout cancels this tenant's outbox and applies the tenant-local withdrawal
	// and policy retention rules. Other tenants and pure local data stay intact.
	Logout(context.Context, Scope) error
}

type Result struct {
	ID           string          `json:"id"`
	Status       string          `json:"status"`
	HSeq         int64           `json:"hseq,omitempty"`
	Receipt      *record.Receipt `json:"receipt,omitempty"`
	HostedTaskID string          `json:"hosted_task_id,omitempty"`
}
type Acknowledgment struct {
	OpID, Digest string
	Results      []Result
}

type Retry struct {
	OpID, Digest string
	NotBefore    time.Time
	Attempt      int
}

// RetryError reports an exhausted transient retry budget. The outbox already
// contains the next attempt's deadline.
type RetryError struct {
	After time.Duration
	Cause error
}

func (e *RetryError) Error() string { return "sync_retry_scheduled" }
func (e *RetryError) Unwrap() error { return e.Cause }

// KeyState returns a current, immutable folded keyring snapshot. Its tenant keys
// must originate in pinned login, not receipts or server-provided record fields.
type KeyState interface {
	State(context.Context) (*sig.State, error)
}

type Config struct {
	Scope    Scope
	Grant    MemoryGrant
	Keystore Keystore
	Outbox   Outbox
	Keys     KeyState
	// AuthKey and AuthIssuer are pinned during validated login. No JWKS URL is
	// taken from untrusted token headers. TLS roots default to the system pool.
	AuthKey    *ecdsa.PublicKey
	AuthIssuer string
	TLSRoots   *x509.CertPool
	// MaxRetries bounds transient retries per Push call; zero defaults to four.
	MaxRetries int
}
