package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"

	tapredact "github.com/Telara-Labs/TAP-Runtime/discover/redact"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// Access comes only from the installed credential resolver, never clientInfo,
// user-agent, cwd or tool arguments. Store rechecks this identity's current grant.
type Access struct {
	CredentialID, Client, MachineID, Owner, RepoID string
	PolicyID                                       string
	ScopeID, SessionKey, Confidence                string
	Ambiguous, Disagreement                        bool
}
type Native = daemon.Native
type Metadata = daemon.Metadata

var asciiHandle = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var clientToken = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var errIdentity = errors.New("invalid_identity")

func metadata(raw []byte) (Metadata, error) {
	if len(raw) == 0 {
		return Metadata{}, nil
	}
	params := append([]byte(`{"_meta":`), raw...)
	params = append(params, '}')
	_, m, e := daemon.RequestParams(params)
	if e != nil {
		return m, errIdentity
	}
	return m, nil
}

type Announcement struct {
	Native   Native
	Ancestor ipc.Proc
}
type CredentialSource interface {
	Authenticate(context.Context, ipc.Hello) (Access, error)
	// Drain returns only live, unacknowledged signals after durable incorporation.
	// A tmp spool file is unseen. Verify native fields and pid/start_ms on ingress.
	Drain(context.Context, string) ([]Announcement, error)
	Alive(ipc.Proc) bool
}
type Resolver interface {
	Resolve(context.Context, ipc.Hello, Metadata) (Access, error)
}
type IdentityResolver struct {
	Source          CredentialSource
	LegacySupported bool
}

func (r IdentityResolver) Resolve(ctx context.Context, h ipc.Hello, m Metadata) (Access, error) {
	encoded, e := json.Marshal(m)
	if e != nil {
		return Access{}, errIdentity
	}
	if _, e = metadata(encoded); e != nil {
		return Access{}, errIdentity
	}
	if h.Shim != "" && (!asciiHandle.MatchString(h.Shim) || !safeIdentity("shim", h.Shim)) {
		return Access{}, errIdentity
	}
	if r.Source == nil {
		return Access{}, errors.New("identity_unavailable")
	}
	a, e := r.Source.Authenticate(ctx, h)
	if e != nil || a.CredentialID == "" || !clientToken.MatchString(a.Client) || !record.IsUUIDv4(a.MachineID) || !record.IsKeyID(a.Owner) {
		return Access{}, errors.New("identity_unavailable")
	}
	// Always start from a fresh scope, even when a process survives clear/resume.
	a.ScopeID = ""
	a.SessionKey = ""
	a.Confidence = ""
	a.Ambiguous = false
	a.Disagreement = false
	signals, e := r.Source.Drain(ctx, a.CredentialID)
	if e != nil {
		return Access{}, errors.New("identity_unavailable")
	}
	matched := map[string]Native{}
	for _, signal := range signals {
		if !r.Source.Alive(signal.Ancestor) {
			continue
		}
		for _, ancestor := range h.Ancestry {
			if ancestor == signal.Ancestor {
				if signal.Native.Client != a.Client {
					return Access{}, errors.New("identity_unavailable")
				}
				b, _ := json.Marshal(Metadata{Native: &signal.Native})
				if _, e := metadata(b); e != nil {
					return Access{}, errors.New("identity_unavailable")
				}
				sk, e := record.SessionKey(signal.Native.Client, signal.Native.Origin, signal.Native.Kind, signal.Native.ID, a.MachineID)
				if e != nil {
					return Access{}, errors.New("identity_unavailable")
				}
				matched[sk] = signal.Native
			}
		}
	}
	if m.Native != nil {
		if m.Native.Client != a.Client {
			return Access{}, errIdentity
		}
		a.SessionKey, e = record.SessionKey(m.Native.Client, m.Native.Origin, m.Native.Kind, m.Native.ID, a.MachineID)
		if e != nil {
			return Access{}, errIdentity
		}
		a.ScopeID = a.SessionKey
		if m.Handle != "" {
			a.ScopeID = record.H("handle", a.CredentialID, m.Handle)
		}
		a.Confidence = "stated"
		for sk := range matched {
			if sk != a.SessionKey {
				a.Disagreement = true
			}
		}
	} else if m.Handle != "" {
		a.ScopeID = record.H("handle", a.CredentialID, m.Handle)
		a.Confidence = "handle-only"
	} else if len(matched) == 1 {
		for sk := range matched {
			a.ScopeID = sk
			a.SessionKey = sk
		}
		a.Confidence = "process-matched"
	} else if len(matched) > 1 {
		a.Ambiguous = true
	}
	// Modern transports can carry unrelated conversations on one process. Only
	// explicit handles or freshly resolved native identity establish continuity.
	legacy := m.ProtocolVersion != daemon.LatestProtocolVersion
	if legacy && a.ScopeID == "" && !a.Ambiguous && m.Legacy != "" && r.LegacySupported {
		a.ScopeID = record.H("legacy", a.CredentialID, m.Legacy)
		a.Confidence = "inferred"
	}
	if legacy && a.ScopeID == "" && h.Shim != "" {
		if !asciiHandle.MatchString(h.Shim) {
			return Access{}, errIdentity
		}
		a.ScopeID = record.H("shim", a.CredentialID, h.Shim)
		a.Confidence = "inferred"
	}
	// No stable scope means no task auto-binding or restored delivery set.
	return a, nil
}

// Reject recognized credential literals instead of hashing them as identities.
func safeIdentity(key, value string) bool {
	return tapredact.Redact(value) == value && tapredact.Argument(key, value) == value
}
