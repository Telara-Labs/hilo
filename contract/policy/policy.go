// Package policy is the signed tenant policy of the memory node contract
// (§9): verification, the per-tenant head chain with rollback and tamper
// detection, trusted time with a persisted floor, freshness, and the
// effects a policy state has on what may leave the machine.
//
// Policy enforcement on the node is cooperative; the enforcing boundary is
// the hosted service. Everything here is a pure function of its inputs.
package policy

import (
	"fmt"
	"path"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// Policy is a verified policy record.
type Policy struct {
	ID   string
	Body *record.PolicyBody
}

// Verify checks a policy record: it parsed as a policy, its one signature
// verifies under a policy-role key of the keyring (§2.1 matrix), and the
// key belongs to the policy's tenant.
func Verify(r *record.Record, sigs []record.Signature, st *sig.State) (*Policy, error) {
	if r.Header.Type != record.KindPolicy {
		return nil, fmt.Errorf("policy: record is a %s", r.Header.Type)
	}
	b, ok := r.Body.(*record.PolicyBody)
	if !ok {
		return nil, fmt.Errorf("policy: body absent")
	}
	res := sig.VerifyRecord(r, sigs, st, sig.Context{Route: record.RouteHostedPull})
	if res.Status != sig.StatusVerified {
		return nil, fmt.Errorf("policy: signature %s: %s", res.Status, res.Reason)
	}
	if res.Key.Role != record.RolePolicy || res.Key.Tenant != b.Tenant {
		return nil, fmt.Errorf("policy: signer is not the policy key of tenant %q", b.Tenant)
	}
	return &Policy{ID: r.ID, Body: b}, nil
}

// Offer outcomes.
const (
	Accepted  = "accepted"  // new head
	Duplicate = "duplicate" // the current head again
	Rollback  = "rollback"  // lower seq than the head: refused
	Tamper    = "tamper"    // equal seq, different id
)

// Chain is the policy chain of one tenant: the highest verified sequence.
type Chain struct {
	Tenant string
	Head   *Policy
	// Tampered is set when two different policies with the head's sequence
	// were seen. The chain is then stale until a higher sequence arrives
	// (OPEN-QUESTIONS Q34).
	Tampered bool
}

// NewChain returns an empty chain for a tenant.
func NewChain(tenant string) *Chain { return &Chain{Tenant: tenant} }

// Offer adds a verified policy to the chain.
func (c *Chain) Offer(p *Policy) (string, error) {
	if p.Body.Tenant != c.Tenant {
		return "", fmt.Errorf("policy for tenant %q offered to chain %q", p.Body.Tenant, c.Tenant)
	}
	switch {
	case c.Head == nil || p.Body.Seq > c.Head.Body.Seq:
		c.Head, c.Tampered = p, false
		return Accepted, nil
	case p.ID == c.Head.ID:
		return Duplicate, nil
	case p.Body.Seq == c.Head.Body.Seq:
		c.Tampered = true
		return Tamper, nil
	default:
		return Rollback, nil
	}
}

// Clock is trusted time (§9.2): T = max(wall, anchor_date + (mono −
// anchor_mono)) with an anchor, else max(wall, floor). All times are unix
// ms; mono is any monotonic millisecond reading of this process.
type Clock struct {
	floor      int64
	anchored   bool
	anchorDate int64
	anchorMono int64
	rollback   bool
}

// RestoreClock starts a clock from a persisted floor, as after a restart.
// A new process has no anchor.
func RestoreClock(floor int64) *Clock { return &Clock{floor: floor} }

// Floor returns the value to persist (every minute and at shutdown).
func (c *Clock) Floor() int64 { return c.floor }

// Rollback reports whether a wall clock below the floor was observed and no
// fresh hosted Date has cleared it.
func (c *Clock) Rollback() bool { return c.rollback }

// ObserveDate records a hosted Date header and the monotonic reading at its
// receipt. A Date at or above the floor clears a detected rollback.
func (c *Clock) ObserveDate(date, mono int64) {
	c.anchored, c.anchorDate, c.anchorMono = true, date, mono
	if date >= c.floor {
		c.rollback = false
	}
}

// Now returns trusted time for a wall and monotonic reading and advances the
// floor to it.
func (c *Clock) Now(wall, mono int64) int64 {
	if wall < c.floor {
		c.rollback = true
	}
	t := wall
	if c.anchored {
		if a := c.anchorDate + (mono - c.anchorMono); a > t {
			t = a
		}
	} else if c.floor > t {
		t = c.floor
	}
	if t > c.floor {
		c.floor = t
	}
	return t
}

// Freshness of the policy head at trusted time T.
type Freshness string

const (
	NoPolicy     Freshness = "none"
	Fresh        Freshness = "fresh"       // T < refresh_after
	RefreshDue   Freshness = "refresh-due" // refresh_after ≤ T < not_after: enforce, retry, warn
	Expired      Freshness = "expired"     // T ≥ not_after: fail closed
	RolledBack   Freshness = "rollback"    // wall clock below the floor: fail closed
	TamperedHead Freshness = "tampered"    // equal-seq conflict: fail closed
	Invalid      Freshness = "invalid"     // a policy was offered but none verified: fail closed
)

// Evaluate returns the freshness of a chain's head.
func Evaluate(c *Chain, clock *Clock, t int64, sawInvalid bool) Freshness {
	switch {
	case c.Head == nil && sawInvalid:
		return Invalid
	case c.Head == nil:
		return NoPolicy
	case c.Tampered:
		return TamperedHead
	case clock.Rollback():
		return RolledBack
	case t >= c.Head.Body.NotAfter:
		return Expired
	case c.Head.Body.RefreshAfter != 0 && t >= c.Head.Body.RefreshAfter:
		return RefreshDue
	}
	return Fresh
}

// Effects is what a policy state allows (§9.2).
type Effects struct {
	DataPush       bool // push of data records
	DataPull       bool // pull of tenant data records
	TenantHookPull bool // hook injection of tenant-pulled records (ceiling only; H ships off)
	ControlRefresh bool // HELLO, PULL(control), ENFORCE: never stopped except by logout
	CancelOutbox   bool
	WithdrawPulled bool // apply a withdrawal with all for this tenant
	// RestrictiveLocal: blocked repos, forced shapes and the minimum epoch
	// keep applying whenever a head exists, even when stale.
	RestrictiveLocal bool
}

// EffectsOf returns the effects of a freshness state and the head's kill
// switch. A chain with no policy has no tenant restrictions.
func EffectsOf(c *Chain, f Freshness) Effects {
	e := Effects{ControlRefresh: true}
	switch f {
	case NoPolicy:
		e.DataPush, e.DataPull, e.TenantHookPull = true, true, true
		return e
	case Fresh, RefreshDue:
		e.DataPush, e.DataPull = true, true
		e.TenantHookPull = c.Head.Body.Readback.HookInjection
	}
	if c.Head != nil {
		e.RestrictiveLocal = true
		k := c.Head.Body.Kill
		if k.Sync {
			e.DataPush, e.DataPull, e.CancelOutbox = false, false, true
		}
		if k.WithdrawPulled {
			e.WithdrawPulled = true
		}
	}
	if !e.DataPush {
		e.TenantHookPull = false
	}
	return e
}

// AppliesTo reports whether the head applies to a user id.
func AppliesTo(b *record.PolicyBody, user string) bool {
	for _, u := range b.Applies.Users {
		if u == "*" || u == user {
			return true
		}
	}
	return false
}

// RepoBlocked reports whether a normalized remote matches a blocked-repo
// rule with the given effect. Globs use path.Match syntax; a malformed glob
// matches everything (fail closed).
func RepoBlocked(b *record.PolicyBody, remote, effect string) bool {
	for _, r := range b.BlockedRepos {
		if r.Effect != effect {
			continue
		}
		ok, err := path.Match(r.RemoteGlob, remote)
		if err != nil || ok {
			return true
		}
	}
	return false
}

// PushAllowed reports whether a repository may be pushed under the head:
// AllowRepos empty allows none; "*" allows every repository not blocked.
func PushAllowed(b *record.PolicyBody, remote string) bool {
	if RepoBlocked(b, remote, "no-push") {
		return false
	}
	for _, g := range b.Push.AllowRepos {
		if ok, err := path.Match(g, remote); err == nil && ok {
			return true
		}
	}
	return false
}

// Ceiling returns the effective value of a boolean node setting under a
// policy ceiling: the setting holds only if the policy allows it.
func Ceiling(setting, allowed bool) bool { return setting && allowed }
