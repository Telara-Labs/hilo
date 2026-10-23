package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sync"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

type Channel string

const (
	S Channel = "S"
	P Channel = "P"
	E Channel = "E"
	H Channel = "H"
)

type TaskMutation string

const (
	Create     TaskMutation = "create"
	Checkpoint TaskMutation = "checkpoint"
	Pause      TaskMutation = "pause"
	Complete   TaskMutation = "complete"
)

type RepoSet struct {
	kind string
	ids  []string
}

func AllLocalRepos() RepoSet { return RepoSet{kind: "all-local"} }
func ConcreteRepos(ids []string) (RepoSet, error) {
	if len(ids) > 64 {
		return RepoSet{}, failure("invalid_grant")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !record.IsRepoID(id) || seen[id] {
			return RepoSet{}, failure("invalid_grant")
		}
		seen[id] = true
	}
	return RepoSet{kind: "concrete", ids: append([]string(nil), ids...)}, nil
}

type Grant struct {
	Repos    RepoSet
	Channels []Channel
}
type TaskWriteGrant struct {
	Actions       []TaskMutation
	Repos         RepoSet
	AllowUnscoped bool
}
type RegisterClient struct {
	AdminOpID, ClientName string
	ReadGrant             Grant
	TaskWrites            TaskWriteGrant
}
type RegisteredClient struct {
	CredentialID string
	GrantEpoch   int64
	Secret       *OneUseSecret
}
type GrantReceipt struct {
	CredentialID string
	GrantEpoch   int64
	Status       string
}
type OneUseSecret struct {
	mu    sync.Mutex
	value []byte
}

func (s *OneUseSecret) Take() ([]byte, error) {
	if s == nil {
		return nil, failure("secret_unavailable_rotate_required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.value) != 32 {
		return nil, failure("secret_unavailable_rotate_required")
	}
	v := append([]byte(nil), s.value...)
	clear(s.value)
	s.value = nil
	return v, nil
}

type CredentialProof struct {
	CredentialID string
	Token        []byte
}
type IdentityInput struct{ ConversationHandle, LegacySessionID, ShimInstanceID, NativeAnnouncementID string }
type CallIdentity struct {
	SuppliedOpID string
	JSONRPCID    json.RawMessage
}
type ByteBudget = disclosuretext.ByteBudget
type TypedCommand = disclosuretext.Command
type DisclosureConfig struct {
	OwnerGenesis, MachineID string
	MaxReplyBytes           int
}
type PreloadedDisclosureAuthority struct {
	salt    [32]byte
	private [64]byte
	keyID   string
	valid   bool
}

func PreloadDisclosureAuthority(salt []byte, private ed25519.PrivateKey) (PreloadedDisclosureAuthority, error) {
	var p PreloadedDisclosureAuthority
	if len(salt) != 32 || len(private) != 64 {
		return p, failure("key_material")
	}
	expected := ed25519.NewKeyFromSeed(private[:32])
	defer clear(expected)
	if !bytes.Equal(private, expected) {
		return p, failure("key_material")
	}
	copy(p.salt[:], salt)
	copy(p.private[:], private)
	p.keyID = sig.KeyID(private.Public().(ed25519.PublicKey))
	p.valid = true
	return p, nil
}
func (p *PreloadedDisclosureAuthority) Clear() {
	if p != nil {
		clear(p.salt[:])
		clear(p.private[:])
		p.keyID = ""
		p.valid = false
	}
}

type ClientHandle struct {
	engine                 *DisclosureEngine
	credential, connection string
	epoch                  int64
}
type ScopeHandle struct {
	engine               *DisclosureEngine
	credential, id       string
	generation, evidence int64
}
type CommittedReplyHandle struct {
	engine                *DisclosureEngine
	credential, op, scope string
}
type ReleasedText struct {
	text    string
	isError bool
}

func (r ReleasedText) Text() string  { return r.text }
func (r ReleasedText) IsError() bool { return r.isError }

type ItemMarker struct{ LID, ID string }
type ACK struct {
	Nonce string
	Items []ItemMarker
}
type ACKReceipt struct{ Status string }
type DisclosureAdministration struct{ engine *DisclosureEngine }
type DisclosureEngine struct {
	store         *Store
	authority     PreloadedDisclosureAuthority
	config        DisclosureConfig
	instance, id  string
	closed        bool
	closedClients map[string]bool
	deadlines     map[string]time.Time
	ruleset       record.Ruleset
}

func (e *DisclosureEngine) Close() error {
	if e == nil || e.store == nil {
		return nil
	}
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	e.closed = true
	e.authority.Clear()
	clear(e.deadlines)
	return nil
}
func (e *DisclosureEngine) CloseClient(h ClientHandle) {
	if e == nil || e.store == nil {
		return
	}
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if h.engine == e {
		e.closedClients[h.connection] = true
	}
}
func (e *DisclosureEngine) Administration(ctx context.Context) (*DisclosureAdministration, error) {
	if e == nil || e.store == nil {
		return nil, failure("unauthorized")
	}
	err := e.store.writeMode(ctx, true, func() error { return e.checkAuthority(ctx) })
	if err != nil {
		return nil, err
	}
	return &DisclosureAdministration{engine: e}, nil
}
