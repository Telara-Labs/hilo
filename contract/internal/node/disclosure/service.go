// Package disclosure is the thin private byte-budget facade over the store's
// fixed authority, mutation and release boundary. No transport is installed.
package disclosure

import (
	"context"
	"crypto/ed25519"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"sync"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
)

type Config = store.DisclosureConfig
type RuntimeMaterial = store.PreloadedDisclosureAuthority
type RepoSet = store.RepoSet
type Channel = store.Channel
type TaskMutation = store.TaskMutation
type Grant = store.Grant
type TaskWriteGrant = store.TaskWriteGrant
type RegisterClient = store.RegisterClient
type RegisteredClient = store.RegisteredClient
type GrantReceipt = store.GrantReceipt
type CredentialProof = store.CredentialProof
type IdentityInput = store.IdentityInput
type CallIdentity = store.CallIdentity
type ByteBudget = disclosuretext.ByteBudget
type Command = disclosuretext.Command
type ACK = store.ACK
type ACKReceipt = store.ACKReceipt
type ItemMarker = store.ItemMarker

const (
	S          = store.S
	P          = store.P
	E          = store.E
	H          = store.H
	Create     = store.Create
	Checkpoint = store.Checkpoint
	Pause      = store.Pause
	Complete   = store.Complete
)

func AllLocalRepos() RepoSet                      { return store.AllLocalRepos() }
func ConcreteRepos(ids []string) (RepoSet, error) { return store.ConcreteRepos(ids) }
func DecodeCommand(tool string, raw []byte) (Command, error) {
	return disclosuretext.DecodeCommand(tool, raw)
}
func PreloadRuntimeMaterial(salt []byte, private ed25519.PrivateKey) (RuntimeMaterial, error) {
	return store.PreloadDisclosureAuthority(salt, private)
}

type facadeError struct{}

func (facadeError) Error() string { return "disclosure_unavailable" }

type Service struct{ engine *store.DisclosureEngine }
type Connection struct {
	mu      sync.Mutex
	closed  bool
	unhook  func()
	service *Service
	handle  store.ClientHandle
}
type RequestScope struct {
	ephemeral bool
	service   *Service
	handle    store.ScopeHandle
}
type Reply struct {
	ephemeral  bool
	connection *Connection
	handle     store.CommittedReplyHandle
}
type Administration struct {
	handle *store.DisclosureAdministration
}

// Result is created only after store.Release returns from known FULL commit.
// There is exactly one text content item and no structured/resource channel.
type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
type Result struct {
	Content []TextContent `json:"content"`
	IsError bool          `json:"isError"`
}

func New(ctx context.Context, st *store.Store, cfg Config, material RuntimeMaterial) (*Service, error) {
	if err := disclosuretext.Capability(); err != nil {
		return nil, err
	}
	e, err := store.NewDisclosureEngine(ctx, st, material, cfg)
	if err != nil {
		return nil, err
	}
	return &Service{e}, nil
}
func (s *Service) Close() error {
	if s == nil || s.engine == nil {
		return nil
	}
	return s.engine.Close()
}
func (s *Service) Administration(ctx context.Context) (*Administration, error) {
	if s == nil || s.engine == nil {
		return nil, facadeError{}
	}
	a, e := s.engine.Administration(ctx)
	if e != nil {
		return nil, e
	}
	return &Administration{a}, nil
}
func (s *Service) Authenticate(ctx context.Context, proof CredentialProof) (*Connection, error) {
	if s == nil || s.engine == nil {
		return nil, facadeError{}
	}
	h, e := s.engine.Authenticate(ctx, proof)
	if e != nil {
		return nil, e
	}
	c := &Connection{service: s, handle: h}
	if daemon.ConnectionID(ctx) != "" {
		remove, ok := daemon.RegisterConnectionClose(ctx, func() { _ = c.Close() })
		if !ok {
			_ = c.Close()
			return nil, facadeError{}
		}
		c.mu.Lock()
		closed := c.closed
		if !closed {
			c.unhook = remove
		}
		c.mu.Unlock()
		if closed {
			remove()
			return nil, facadeError{}
		}
	}
	return c, nil
}
func (c *Connection) Close() error {
	if c != nil && c.service != nil && c.service.engine != nil {
		c.mu.Lock()
		c.closed = true
		remove := c.unhook
		c.unhook = nil
		c.mu.Unlock()
		if remove != nil {
			remove()
		}
		c.service.engine.CloseClient(c.handle)
	}
	return nil
}
func (c *Connection) Resolve(ctx context.Context, input IdentityInput) (RequestScope, error) {
	if c == nil || c.service == nil || c.service.engine == nil {
		return RequestScope{}, facadeError{}
	}
	h, e := c.service.engine.Resolve(ctx, c.handle, input)
	if e != nil {
		_ = c.Close()
		return RequestScope{}, e
	}
	return RequestScope{ephemeral: input.ConversationHandle == "", service: c.service, handle: h}, nil
}
func (c *Connection) Execute(ctx context.Context, scope RequestScope, call CallIdentity, command Command, budget ByteBudget) (*Reply, error) {
	if c == nil || c.service == nil || scope.service != c.service {
		return nil, facadeError{}
	}
	h, e := c.service.engine.Execute(ctx, c.handle, scope.handle, call, command, budget)
	if e != nil {
		if scope.ephemeral {
			_ = c.Close()
		}
		return nil, e
	}
	return &Reply{ephemeral: scope.ephemeral, connection: c, handle: h}, nil
}
func (c *Connection) Next(ctx context.Context, scope RequestScope, call CallIdentity, cursor string, budget ByteBudget) (*Reply, error) {
	if c == nil || c.service == nil || scope.service != c.service {
		return nil, facadeError{}
	}
	h, e := c.service.engine.Next(ctx, c.handle, scope.handle, call, cursor, budget)
	if e != nil {
		if scope.ephemeral {
			_ = c.Close()
		}
		return nil, e
	}
	return &Reply{ephemeral: scope.ephemeral, connection: c, handle: h}, nil
}
func (c *Connection) Acknowledge(ctx context.Context, ack ACK) (ACKReceipt, error) {
	if c == nil || c.service == nil || c.service.engine == nil {
		return ACKReceipt{}, facadeError{}
	}
	return c.service.engine.Acknowledge(ctx, c.handle, ack)
}
func (r *Reply) Release(ctx context.Context) (Result, error) {
	if r == nil || r.connection == nil || r.connection.service == nil {
		return Result{}, facadeError{}
	}
	c := r.connection
	if r.ephemeral {
		defer c.Close()
	}
	text, e := c.service.engine.Release(ctx, c.handle, r.handle)
	if e != nil {
		return Result{}, e
	}
	return Result{Content: []TextContent{{Type: "text", Text: text.Text()}}, IsError: text.IsError()}, nil
}
func (a *Administration) Register(ctx context.Context, q RegisterClient) (RegisteredClient, error) {
	if a == nil || a.handle == nil {
		return RegisteredClient{}, facadeError{}
	}
	return a.handle.Register(ctx, q)
}
func (a *Administration) ReplaceGrant(ctx context.Context, op, id string, epoch int64, g Grant) (GrantReceipt, error) {
	if a == nil || a.handle == nil {
		return GrantReceipt{}, facadeError{}
	}
	return a.handle.ReplaceGrant(ctx, op, id, epoch, g)
}
func (a *Administration) ReplaceTaskWrites(ctx context.Context, op, id string, epoch int64, g TaskWriteGrant) (GrantReceipt, error) {
	if a == nil || a.handle == nil {
		return GrantReceipt{}, facadeError{}
	}
	return a.handle.ReplaceTaskWrites(ctx, op, id, epoch, g)
}
func (a *Administration) RotateCredential(ctx context.Context, op, id string, epoch int64) (RegisteredClient, error) {
	if a == nil || a.handle == nil {
		return RegisteredClient{}, facadeError{}
	}
	return a.handle.RotateCredential(ctx, op, id, epoch)
}
func (a *Administration) RevokeCredential(ctx context.Context, op, id string, epoch int64) (GrantReceipt, error) {
	if a == nil || a.handle == nil {
		return GrantReceipt{}, facadeError{}
	}
	return a.handle.RevokeCredential(ctx, op, id, epoch)
}

// IssueOperationTokens returns a bounded durable receiver-issued pool for initialize.
func (c *Connection) IssueOperationTokens(ctx context.Context) ([]string, error) {
	if c == nil || c.service == nil || c.service.engine == nil {
		return nil, facadeError{}
	}
	return c.service.engine.IssueOperationTokens(ctx, c.handle)
}
