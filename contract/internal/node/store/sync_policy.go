package store

import (
	"context"
	"encoding/json"

	"github.com/Telara-Labs/hilo/contract/policy"
	"github.com/Telara-Labs/hilo/contract/record"
)

// SyncPolicy is the current tenant decision for hosted metadata push. Governed
// is false only when no tenant context is installed; the hosted side then
// enforces its own policy. Body is a private copy of the verified head.
type SyncPolicy struct {
	Governed     bool
	DataPush     bool
	CancelOutbox bool
	PolicyID     string
	Body         *record.PolicyBody
}

// PushAllowed applies the push ceiling to one normalized remote. An installed
// tenant with a missing, stale, tampered or killed head denies every record.
func (p SyncPolicy) PushAllowed(remote string) bool {
	if !p.DataPush {
		return false
	}
	if !p.Governed {
		return true
	}
	return policy.PushAllowed(p.Body, remote)
}

// SyncPushPolicy evaluates the installed tenant chain and trusted clock under
// the writer, exactly as capture and read-back do, before every hosted send.
func (s *Store) SyncPushPolicy(ctx context.Context) (SyncPolicy, error) {
	var out SyncPolicy
	err := s.write(ctx, func() error {
		t, err := s.tenant(ctx)
		if err != nil {
			return err
		}
		if t == nil {
			out = SyncPolicy{DataPush: true}
			return nil
		}
		out = SyncPolicy{Governed: true, CancelOutbox: t.effects.CancelOutbox}
		b := t.body()
		if b == nil || !t.effects.DataPush || !policy.AppliesTo(b, t.user) {
			return nil
		}
		raw, err := json.Marshal(b)
		if err != nil {
			return failure("policy_unavailable")
		}
		defer clear(raw)
		copied := &record.PolicyBody{}
		if json.Unmarshal(raw, copied) != nil {
			return failure("policy_unavailable")
		}
		out.DataPush, out.PolicyID, out.Body = true, t.chain.HighestID, copied
		return nil
	})
	if err != nil {
		return SyncPolicy{}, err
	}
	return out, nil
}
