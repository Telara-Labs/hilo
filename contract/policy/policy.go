// Package policy is the signed tenant policy of the memory node contract
// verification, the per-tenant head chain with rollback and tamper
// detection, trusted time with a persisted floor, freshness, and the
// effects a policy state has on what may leave the machine.
//
// Policy enforcement on the node is cooperative; the enforcing boundary is
// the hosted service. Everything here is a pure function of its inputs.
package policy

import (
	"encoding/json"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
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
// verifies under a policy-role key of the keyring, and the
// key belongs to the policy's tenant.
func Verify(r *record.Record, sigs []record.Signature, st *sig.State, issuer sig.TrustedIssuer) (*Policy, error) {
	if r == nil {
		return nil, fmt.Errorf("policy: record required")
	}
	parsed, err := record.Parse(r.HeaderJCS, r.BodyJCS, r.ID)
	if err != nil {
		return nil, fmt.Errorf("policy: invalid canonical record")
	}
	r = parsed
	if r.Header.Type != record.KindPolicy {
		return nil, fmt.Errorf("policy: record is a %s", r.Header.Type)
	}
	b, ok := r.Body.(*record.PolicyBody)
	if !ok {
		return nil, fmt.Errorf("policy: body absent")
	}
	res := sig.VerifyRecord(r, sigs, st, sig.Context{Route: record.RouteHostedPull, SignerRole: record.RolePolicy, Issuer: issuer})
	if res.Status != sig.StatusVerified {
		return nil, fmt.Errorf("policy: signature %s: %s", res.Status, res.Reason)
	}
	if res.Key.Role != record.RolePolicy || res.Key.Tenant != b.Tenant || b.Tenant != issuer.Tenant {
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
	Tenant     string
	HighestSeq int64
	HighestID  string
	Head       *Policy
	// Tampered is set when two different policies with the head's sequence
	// were seen. The chain is then stale until a higher sequence arrives
	// (OPEN-QUESTIONS Q34).
	Tampered bool
}

// NewChain returns an empty chain for a tenant.
func NewChain(tenant string) *Chain { return &Chain{Tenant: tenant} }

// Offer adds a verified policy to the chain.
func (c *Chain) Offer(p *Policy) (string, error) {
	if p == nil || p.Body == nil {
		return "", fmt.Errorf("verified policy required")
	}
	if p.Body.Tenant != c.Tenant {
		return "", fmt.Errorf("policy for tenant %q offered to chain %q", p.Body.Tenant, c.Tenant)
	}
	if c.Head != nil && c.Head.Body.Seq > c.HighestSeq {
		c.HighestSeq = c.Head.Body.Seq
		c.HighestID = c.Head.ID
	}
	switch {
	case p.Body.Seq > c.HighestSeq:
		c.purgeConfiguration()
		c.Head = copyPolicy(p)
		c.HighestSeq = p.Body.Seq
		c.HighestID = p.ID
		c.Tampered = false
		return Accepted, nil
	case p.Body.Seq < c.HighestSeq:
		return Rollback, nil
	case p.ID != c.HighestID:
		c.Tampered = true
		return Tamper, nil
	default:
		if c.Head == nil {
			c.Head = copyPolicy(p)
		}
		return Duplicate, nil
	}

}

// Clock maintains runtime high-water time on EVERY evaluation. Persist Floor
// at least once per minute and shutdown; process monotonic anchors never restore.
type Clock struct {
	floor                  int64
	anchored               bool
	anchorDate, anchorMono int64
	rollback               bool
	lastWall, lastMono     int64
	haveWall               bool
}

func RestoreClock(floor int64) *Clock {
	c := &Clock{floor: floor}
	if floor < 0 || floor > jcs.MaxSafeInteger {
		c.floor = jcs.MaxSafeInteger
		c.rollback = true
	}
	return c
}
func (c *Clock) Floor() int64   { return c.floor }
func (c *Clock) Rollback() bool { return c.rollback }

// DateObservation is authenticated receiver context, never bundle/record data.
// Transport adapters validate TLS origin/endpoint, live request binding, HTTP
// cache and single IMF-fixdate parsing before setting these observations.
type DateObservation struct {
	Date, RequestStartMono, ReceiptMono, ReceiptWall              int64
	ServerTime                                                    int64
	Authenticated, ConfiguredEndpoint, BoundLiveResponse, NoStore bool
	DateCount                                                     int
	Age                                                           int64 // zero for absent or zero
}

func (c *Clock) ObserveAnchor(o DateObservation) error {
	// Evaluate old clock before considering any replacement, including rejection.
	priorMono, hadReading := c.lastMono, c.haveWall
	c.Now(o.ReceiptWall, o.ReceiptMono)
	if !o.Authenticated || !o.ConfiguredEndpoint || !o.BoundLiveResponse || !o.NoStore || o.DateCount != 1 || o.Age != 0 || o.Date <= 0 || o.Date > jcs.MaxSafeInteger || o.RequestStartMono < 0 || o.ReceiptMono < o.RequestStartMono || o.ReceiptMono-o.RequestStartMono > 30000 || o.ReceiptMono < 0 || o.ReceiptWall < 0 || o.ReceiptWall > jcs.MaxSafeInteger {
		return fmt.Errorf("untrusted Date observation")
	}
	if o.ServerTime != 0 && (o.ServerTime <= 0 || o.ServerTime > jcs.MaxSafeInteger || o.ServerTime-o.Date > 999 || o.Date-o.ServerTime > 999) {
		return fmt.Errorf("Date/server_time mismatch")
	}
	r := o.ReceiptMono - o.RequestStartMono
	if o.Date > jcs.MaxSafeInteger-999-r || o.Date+999+r < c.floor {
		return fmt.Errorf("stale or overflow Date")
	}
	if hadReading && (o.ReceiptMono < priorMono) {
		return fmt.Errorf("monotonic regression")
	}
	c.anchored = true
	c.anchorDate = o.Date
	c.anchorMono = o.ReceiptMono
	if o.Date > c.floor {
		c.floor = o.Date
	}
	c.lastWall = o.ReceiptWall
	c.lastMono = o.ReceiptMono
	c.haveWall = true
	c.rollback = false
	return nil
}

// ObserveDate cannot authenticate freshness from Date alone. Legacy adapters
// fail closed until migrated to the measured live-response API.
func (c *Clock) ObserveDate(date, mono, wall int64)   { c.Now(wall, mono); c.rollback = true }
func (c *Clock) ObserveDateAt(date, mono, wall int64) { c.ObserveDate(date, mono, wall) }
func (c *Clock) Now(wall, mono int64) int64 {
	if wall < 0 || wall > jcs.MaxSafeInteger || mono < 0 {
		c.rollback = true
		return c.floor
	}
	if c.haveWall && (wall < c.lastWall || mono < c.lastMono) || !c.anchored && wall < c.floor {
		c.rollback = true
	}
	t := wall
	if c.anchored {
		delta := int64(0)
		if mono >= c.anchorMono {
			delta = mono - c.anchorMono
		}
		if delta > jcs.MaxSafeInteger-c.anchorDate {
			c.rollback = true
			t = jcs.MaxSafeInteger
		} else if a := c.anchorDate + delta; a > t {
			t = a
		}
	}
	if t < c.floor {
		t = c.floor
	}
	c.floor = t
	if !c.haveWall || wall > c.lastWall {
		c.lastWall = wall
	}
	if !c.haveWall || mono > c.lastMono {
		c.lastMono = mono
	}
	c.haveWall = true
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
	case c.Tampered:
		return TamperedHead
	case c.Head == nil && sawInvalid:
		return Invalid
	case c.Head == nil:
		return NoPolicy
	case clock.Rollback():
		return RolledBack
	case t >= c.Head.Body.NotAfter:
		return Expired
	case c.Head.Body.RefreshAfter != 0 && t >= c.Head.Body.RefreshAfter:
		return RefreshDue
	}
	return Fresh
}

// Effects is what a policy state allows.
type Effects struct {
	DataPush       bool // push of data records
	DataPull       bool // pull of tenant data records
	TenantReadback bool // current tenant-derived content, every read channel
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
	if c.Tampered {
		f = TamperedHead
	}
	if c.Head == nil && (f == Fresh || f == RefreshDue) || c.Head != nil && f == NoPolicy {
		f = Invalid
	}
	switch f {
	case NoPolicy:
		e.DataPush, e.DataPull, e.TenantHookPull = true, true, true
		return e
	case Fresh, RefreshDue:
		e.DataPush, e.DataPull, e.TenantReadback = true, true, true
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
		if r.RemoteGlob == "*" {
			return true
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
	if remote == "" || b == nil || b.Push.MaxProfile != record.ProfilePushMetadata || RepoBlocked(b, remote, "no-capture") || RepoBlocked(b, remote, "no-push") {
		return false
	}
	for _, g := range b.Push.AllowRepos {
		if g == "*" {
			return true
		}
		if ok, err := path.Match(g, remote); err == nil && ok {
			return true
		}
	}
	return false
}

// Ceiling returns the effective value of a boolean node setting under a
// policy ceiling: the setting holds only if the policy allows it.
func Ceiling(setting, allowed bool) bool { return setting && allowed }

// LoginState enforces one active tenant authority. Logout keeps historical
// policy provenance and rollback/equivocation facts in the adapter's ledger.
type LoginState struct{ ActiveTenant string }

func (s *LoginState) Login(tenant string) error {
	if tenant == "" || s.ActiveTenant != "" && s.ActiveTenant != tenant {
		return fmt.Errorf("tenant_conflict")
	}
	s.ActiveTenant = tenant
	return nil
}
func (s *LoginState) Logout() { s.ActiveTenant = "" }

func MaxProfile(b *record.PolicyBody) string {
	if b != nil && b.Push.MaxProfile == record.ProfilePushMetadata {
		return record.ProfilePushMetadata
	}
	return record.ProfileLocal
}

func copyPolicy(p *Policy) *Policy {
	raw, _ := json.Marshal(p.Body)
	defer clear(raw)
	b := &record.PolicyBody{}
	json.Unmarshal(raw, b)
	return &Policy{ID: p.ID, Body: b}
}
func (c *Chain) purgeConfiguration() {
	if c.Head != nil && c.Head.Body != nil {
		*c.Head.Body = record.PolicyBody{}
	}
	c.Head = nil
}

// Logout scrubs current private configuration/salt but preserves rollback and
// equivocation settlement; a replay/Date/logout cannot clear the latch.
func (c *Chain) Logout() { c.purgeConfiguration() }
