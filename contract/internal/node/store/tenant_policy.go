package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/telara-memory/contract/policy"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

const tenantSchema = `
CREATE TABLE IF NOT EXISTS tenant_context(tenant TEXT PRIMARY KEY,user_id TEXT NOT NULL,origin TEXT NOT NULL,active INTEGER NOT NULL CHECK(active IN(0,1)),highest_seq INTEGER NOT NULL,highest_id TEXT NOT NULL,tampered INTEGER NOT NULL CHECK(tampered IN(0,1)));
CREATE UNIQUE INDEX IF NOT EXISTS one_active_tenant ON tenant_context(active) WHERE active=1;
CREATE TABLE IF NOT EXISTS tenant_key(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,header BLOB NOT NULL,body BLOB NOT NULL,sigs BLOB NOT NULL,login INTEGER NOT NULL CHECK(login IN(0,1)));
CREATE TABLE IF NOT EXISTS tenant_policy(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,seq INTEGER NOT NULL,header BLOB NOT NULL,body BLOB,sigs BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS policy_equivocation(tenant TEXT NOT NULL,seq INTEGER NOT NULL,id TEXT NOT NULL,PRIMARY KEY(tenant,seq,id));
CREATE TABLE IF NOT EXISTS policy_logout(id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS trusted_time(singleton INTEGER PRIMARY KEY CHECK(singleton=1),floor INTEGER NOT NULL,rollback INTEGER NOT NULL DEFAULT 0 CHECK(rollback IN(0,1)));
INSERT OR IGNORE INTO trusted_time(singleton,floor) VALUES(1,0);
` + serviceAuthoritySchema

// TenantPolicyContext is installed, authenticated local authority, never MCP,
// native transcript, bundle metadata or a signed record's assertion of trust.
// Root must be the policy key pinned by a validated TLS login.
type TenantPolicyContext struct {
	Tenant, UserID, Origin string
	Root                   SignedRecord
}
type tenantState struct {
	tenant, user, origin string
	chain                *policy.Chain
	freshness            policy.Freshness
	effects              policy.Effects
	// overlay is the effective policy while staged candidates restrict the
	// head: their intersection. It is never signed and never the head.
	overlay *record.PolicyBody
}

func (s *Store) InstallTenantPolicyContext(ctx context.Context, c TenantPolicyContext) error {
	u, err := url.Parse(c.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || c.UserID == "" || len(c.UserID) > 200 || c.Tenant == "" {
		return failure("invalid_policy_context")
	}
	r, err := record.Parse(c.Root.HeaderJCS, c.Root.BodyJCS, c.Root.AdvisoryID)
	if err != nil || r.Header.Type != record.KindKeyOp {
		return failure("invalid_policy_context")
	}
	b, ok := r.Body.(*record.KeyOpBody)
	if !ok {
		return failure("invalid_policy_context")
	}
	if b.Op != record.OpTenantKey || b.Subject.Role != record.RolePolicy || b.Genesis != c.Tenant {
		return failure("invalid_policy_context")
	}
	return s.write(ctx, func() error {
		var active string
		err := s.conn.QueryRowContext(ctx, "SELECT tenant FROM tenant_context WHERE active=1").Scan(&active)
		if err != nil && err != sql.ErrNoRows {
			return failure("storage_error")
		}
		if active != "" && active != c.Tenant {
			return failure("tenant_conflict")
		}
		var existing string
		err = s.conn.QueryRowContext(ctx, "SELECT id FROM tenant_key WHERE tenant=? AND login=1", c.Tenant).Scan(&existing)
		if err != nil && err != sql.ErrNoRows {
			return failure("storage_error")
		}
		if existing != "" && existing != r.ID {
			return failure("tenant_pin_conflict")
		}
		kr := sig.NewKeyring(s.opts.PinnedGenesisID)
		op := &sig.KeyOp{Rec: r, Body: b, Sigs: c.Root.Sigs, FromLogin: true, Issuer: sig.TrustedIssuer{Tenant: c.Tenant, Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin}}
		if sig.VerifyKeyOp(kr, op).Status != sig.OpAuthorized {
			return failure("invalid_policy_context")
		}
		signatures, _ := json.Marshal(c.Root.Sigs)
		if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO tenant_key VALUES(?,?,?,?,?,1)", r.ID, c.Tenant, r.HeaderJCS, r.BodyJCS, signatures); err != nil {
			return failure("storage_error")
		}
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO tenant_context VALUES(?,?,?,1,0,'',0) ON CONFLICT(tenant) DO UPDATE SET active=1,user_id=excluded.user_id,origin=excluded.origin", c.Tenant, c.UserID, u.Scheme+"://"+u.Host); err != nil {
			return failure("storage_error")
		}
		return s.policyProjectionFence(ctx)
	})
}

func (s *Store) tenantKeyring(ctx context.Context, tenant string) (*sig.Keyring, error) {
	rows, err := s.conn.QueryContext(ctx, "SELECT id,header,body,sigs,login FROM tenant_key WHERE tenant=? ORDER BY rowid", tenant)
	if err != nil {
		return nil, failure("storage_error")
	}
	defer rows.Close()
	kr := sig.NewKeyring(s.opts.PinnedGenesisID)
	count := 0
	for rows.Next() {
		count++
		if count > 8192 {
			return nil, failure("authority_evaluation_required")
		}
		var id string
		var h, b, sg []byte
		var login bool
		if rows.Scan(&id, &h, &b, &sg, &login) != nil {
			return nil, failure("storage_error")
		}
		r, err := record.Parse(h, b, id)
		if err != nil || r.Header.Type != record.KindKeyOp {
			return nil, failure("corrupt_database")
		}
		body, ok := r.Body.(*record.KeyOpBody)
		if !ok {
			return nil, failure("corrupt_database")
		}
		op := &sig.KeyOp{Rec: r, Body: body, Sigs: decodeSignatures(sg), FromLogin: login, AdmittedSeq: int64(count), Issuer: sig.TrustedIssuer{Tenant: tenant, Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin}}
		if kr.Add(op) != nil {
			return nil, failure("corrupt_database")
		}
	}
	if rows.Err() != nil {
		return nil, failure("storage_error")
	}
	return kr, nil
}

func (s *Store) clock(ctx context.Context) (*policy.Clock, error) {
	var floor int64
	if s.conn.QueryRowContext(ctx, "SELECT floor FROM trusted_time WHERE singleton=1").Scan(&floor) != nil {
		return nil, failure("storage_error")
	}
	if s.policyClock == nil {
		s.policyClock = policy.RestoreClock(floor)
	}
	if floor > s.policyClock.Floor() {
		s.policyClock = policy.RestoreClock(floor)
	}
	s.policyClock.Now(time.Now().UnixMilli(), time.Since(s.policyStart).Milliseconds())
	if _, err := s.conn.ExecContext(ctx, "UPDATE trusted_time SET floor=max(floor,?),rollback=max(rollback,?) WHERE singleton=1", s.policyClock.Floor(), boolInt(s.policyClock.Rollback())); err != nil {
		return nil, failure("storage_error")
	}
	return s.policyClock, nil
}
func (s *Store) tenant(ctx context.Context) (*tenantState, error) {
	return s.tenantWith(ctx, s.clock)
}

// tenantWith evaluates the installed policy chain with the supplied clock
// source. Admission uses the persisting clock; read-only inspection does not.
func (s *Store) tenantWith(ctx context.Context, clockOf func(context.Context) (*policy.Clock, error)) (*tenantState, error) {
	t := &tenantState{}
	var seq int64
	var id string
	var tampered bool
	err := s.conn.QueryRowContext(ctx, "SELECT tenant,user_id,origin,highest_seq,highest_id,tampered FROM tenant_context WHERE active=1").Scan(&t.tenant, &t.user, &t.origin, &seq, &id, &tampered)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, failure("storage_error")
	}
	t.chain = policy.NewChain(t.tenant)
	t.chain.HighestSeq = seq
	t.chain.HighestID = id
	t.chain.Tampered = tampered
	if id != "" {
		var h, b, sg []byte
		if s.conn.QueryRowContext(ctx, "SELECT header,body,sigs FROM tenant_policy WHERE id=? AND tenant=?", id, t.tenant).Scan(&h, &b, &sg) != nil {
			return nil, failure("corrupt_database")
		}
		if len(b) > 0 {
			r, err := record.Parse(h, b, id)
			if err != nil {
				return nil, failure("corrupt_database")
			}
			kr, err := s.tenantKeyring(ctx, t.tenant)
			if err != nil {
				return nil, err
			}
			verified, err := policy.Verify(r, decodeSignatures(sg), kr.State(), sig.TrustedIssuer{Tenant: t.tenant, Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin})
			if err == nil {
				t.chain.Head = verified
			}
		}
	}
	if err = s.loadPolicyOverlay(ctx, t); err != nil {
		return nil, err
	}
	clock, err := clockOf(ctx)
	if err != nil {
		return nil, err
	}
	// Freshness and effects follow the effective policy; the chain the
	// next offer is checked against keeps the committed head.
	effective := t.chain
	if t.overlay != nil {
		c := *t.chain
		c.Head = &policy.Policy{ID: t.chain.Head.ID, Body: t.overlay}
		effective = &c
	}
	t.freshness = policy.Evaluate(effective, clock, clock.Floor(), true)
	var rollback bool
	if s.conn.QueryRowContext(ctx, "SELECT rollback FROM trusted_time WHERE singleton=1").Scan(&rollback) != nil {
		return nil, failure("storage_error")
	}
	if rollback && t.freshness != policy.TamperedHead {
		t.freshness = policy.RolledBack
	}
	t.effects = policy.EffectsOf(effective, t.freshness)
	return t, nil
}

// OfferTenantPolicy verifies against installed tenant pins and commits rollback
// and equal-sequence equivocation state before acknowledging a control. It does
// not accept a policy key from the record, a bundle, or a client hint.
func (s *Store) OfferTenantPolicy(ctx context.Context, in SignedRecord) (AdmissionResult, error) {
	var out AdmissionResult
	r, err := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
	if err != nil || r.Header.Type != record.KindPolicy {
		return out, failure("invalid_policy")
	}
	err = s.write(ctx, func() error {
		t, err := s.tenant(ctx)
		if err != nil {
			return err
		}
		if t == nil {
			return failure("policy_context_required")
		}
		kr, err := s.tenantKeyring(ctx, t.tenant)
		if err != nil {
			return err
		}
		p, err := policy.Verify(r, in.Sigs, kr.State(), sig.TrustedIssuer{Tenant: t.tenant, Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin})
		if err != nil {
			return failure("invalid_policy")
		}
		previousID := t.chain.HighestID
		result, err := t.chain.Offer(p)
		if err != nil {
			return failure("invalid_policy")
		}
		out = AdmissionResult{ID: r.ID, State: result, Duplicate: result == policy.Duplicate}
		if result == policy.Rollback {
			return failure("policy_rollback")
		}
		if result == policy.Tamper {
			for _, id := range []string{t.chain.HighestID, p.ID} {
				if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO policy_equivocation VALUES(?,?,?)", t.tenant, p.Body.Seq, id); err != nil {
					return failure("storage_error")
				}
			}
		}
		if result == policy.Accepted {
			if previousID != "" {
				if _, err = s.conn.ExecContext(ctx, "INSERT INTO scrub_job VALUES(?,(SELECT generation+1 FROM meta WHERE singleton=1),'pending',0) ON CONFLICT(control) DO UPDATE SET state='pending'", previousID); err != nil {
					return failure("storage_error")
				}
			}
			signatures, _ := json.Marshal(in.Sigs)
			if _, err = s.conn.ExecContext(ctx, "UPDATE tenant_policy SET body=NULL WHERE tenant=?", t.tenant); err != nil {
				return failure("storage_error")
			}
			if _, err = s.conn.ExecContext(ctx, "INSERT INTO tenant_policy VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", r.ID, t.tenant, p.Body.Seq, r.HeaderJCS, r.BodyJCS, signatures); err != nil {
				return failure("storage_error")
			}
		}
		// A staged candidate the committed chain has reached is no longer an
		// overlay: it is the head, or a later head superseded it.
		if err = s.clearPolicyOverlays(ctx, t.tenant, t.chain.HighestSeq); err != nil {
			return err
		}
		if _, err = s.conn.ExecContext(ctx, "UPDATE tenant_context SET highest_seq=?,highest_id=?,tampered=? WHERE tenant=?", t.chain.HighestSeq, t.chain.HighestID, boolInt(t.chain.Tampered), t.tenant); err != nil {
			return failure("storage_error")
		}
		return s.policyProjectionFence(ctx)
	})
	if err != nil {
		return AdmissionResult{}, err
	}
	if complete, err := s.finishPolicyScrubs(ctx); err == nil && complete {
		out.Physical = "complete"
	} else {
		out.Physical = "pending"
	}
	return out, nil
}

// ObserveTenantDate consumes measured authenticated live-response context from
// the configured origin. It cannot be reached from record/bundle/MCP decoding.
func (s *Store) ObserveTenantDate(ctx context.Context, origin string, o policy.DateObservation) error {
	return s.write(ctx, func() error {
		var configured string
		if s.conn.QueryRowContext(ctx, "SELECT origin FROM tenant_context WHERE active=1").Scan(&configured) != nil || origin != configured {
			return failure("untrusted_time")
		}
		if s.policyClock == nil {
			var floor int64
			if s.conn.QueryRowContext(ctx, "SELECT floor FROM trusted_time WHERE singleton=1").Scan(&floor) != nil {
				return failure("storage_error")
			}
			s.policyClock = policy.RestoreClock(floor)
		}
		// Monotonic observations must share this process's time base.
		now := time.Since(s.policyStart).Milliseconds()
		if o.ReceiptMono > now || now-o.ReceiptMono > 30000 {
			return failure("untrusted_time")
		}
		if err := tClockObserve(s.policyClock, o); err != nil {
			return err
		}
		_, err := s.conn.ExecContext(ctx, "UPDATE trusted_time SET floor=max(floor,?),rollback=0 WHERE singleton=1", s.policyClock.Floor())
		if err != nil {
			return failure("storage_error")
		}
		return nil
	})
}
func tClockObserve(c *policy.Clock, o policy.DateObservation) error {
	if c.ObserveAnchor(o) != nil {
		return failure("untrusted_time")
	}
	return nil
}

func (s *Store) LogoutTenant(ctx context.Context) error {
	err := s.write(ctx, func() error {
		if _, err := s.clock(ctx); err != nil {
			return err
		}
		if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO policy_logout SELECT id FROM tenant_policy WHERE tenant IN(SELECT tenant FROM tenant_context WHERE active=1)"); err != nil {
			return failure("storage_error")
		}
		if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO scrub_job SELECT id,(SELECT generation+1 FROM meta WHERE singleton=1),'pending',0 FROM tenant_policy WHERE body IS NOT NULL AND tenant IN(SELECT tenant FROM tenant_context WHERE active=1)"); err != nil {
			return failure("storage_error")
		}
		if _, err := s.conn.ExecContext(ctx, "UPDATE tenant_policy SET body=NULL WHERE tenant IN(SELECT tenant FROM tenant_context WHERE active=1)"); err != nil {
			return failure("storage_error")
		}
		if _, err := s.conn.ExecContext(ctx, "DELETE FROM policy_overlay WHERE tenant IN(SELECT tenant FROM tenant_context WHERE active=1)"); err != nil {
			return failure("storage_error")
		}
		if _, err := s.conn.ExecContext(ctx, "UPDATE tenant_context SET active=0 WHERE active=1"); err != nil {
			return failure("storage_error")
		}
		return s.policyProjectionFence(ctx)
	})
	if err != nil {
		return err
	}
	if complete, err := s.finishPolicyScrubs(ctx); err != nil || !complete {
		return failure("physical_pending")
	}
	return nil
}

// Policy replacement/logout has the same physical secret lifecycle as record
// erasure. A busy reader leaves a durable pending job and no clean receipt.
func (s *Store) finishPolicyScrubs(ctx context.Context) (bool, error) {
	s.mu.Lock()
	rows, err := s.conn.QueryContext(ctx, "SELECT j.control FROM scrub_job j JOIN tenant_policy p ON p.id=j.control WHERE p.body IS NULL AND j.state!='complete' LIMIT 8193")
	if err != nil {
		s.mu.Unlock()
		return false, failure("storage_error")
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			s.mu.Unlock()
			return false, failure("storage_error")
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	s.mu.Unlock()
	if err != nil || len(ids) > 8192 {
		return false, failure("physical_pending")
	}
	complete := true
	for _, id := range ids {
		result, err := s.Scrub(ctx, id)
		if err != nil {
			return false, err
		}
		complete = complete && result.State == "complete"
	}
	return complete, nil
}

func (s *Store) loadPolicyProvenance(ctx context.Context, d *databaseState) error {
	d.policyTenants = map[string]string{}
	d.policyLogout = map[string]bool{}
	rows, err := s.conn.QueryContext(ctx, "SELECT p.id,p.tenant,EXISTS(SELECT 1 FROM policy_logout l WHERE l.id=p.id) FROM tenant_policy p LIMIT 8193")
	if err != nil {
		return failure("storage_error")
	}
	defer rows.Close()
	for rows.Next() {
		var id, tenant string
		var loggedOut bool
		if rows.Scan(&id, &tenant, &loggedOut) != nil {
			return failure("storage_error")
		}
		if len(d.policyTenants) >= 8192 {
			return failure("authority_evaluation_required")
		}
		d.policyTenants[id] = tenant
		d.policyLogout[id] = loggedOut
	}
	if rows.Err() != nil {
		return failure("storage_error")
	}
	return nil
}
func (d *databaseState) policyReadAllowed(x *stored) bool {
	id := x.rec.Header.Pol
	if id == "" {
		return true
	}
	if d.tenant == nil || !d.tenant.readAllowed() || d.policyTenants[id] != d.tenant.tenant || d.policyLogout[id] {
		return false
	}
	b := d.tenant.body()
	if x.rec.Header.Red.Epoch < b.Redaction.MinEpoch {
		return false
	}
	overlay, err := localpolicy.TenantOverlay(b)
	if err != nil {
		return false
	}
	return bodyPolicyAllowed(x.rec.Body, overlay)
}

// body is the effective policy: the committed head, intersected with any
// staged candidate's restrictions.
func (t *tenantState) body() *record.PolicyBody {
	if t == nil || t.chain.Head == nil {
		return nil
	}
	if t.overlay != nil {
		return t.overlay
	}
	return t.chain.Head.Body
}
func (t *tenantState) readAllowed() bool {
	return t != nil && t.effects.TenantReadback && t.chain.Head != nil && policy.AppliesTo(t.body(), t.user)
}
func (t *tenantState) sealAllowed(remote string, epoch int) bool {
	b := t.body()
	if t == nil {
		return true
	}
	if b == nil {
		return false
	}
	if !policy.AppliesTo(b, t.user) {
		return false
	}
	// Unknown repository identity must not bypass a repository restriction.
	if b.Kill.CaptureTenantRepos || epoch < b.Redaction.MinEpoch {
		return false
	}
	if remote == "" {
		for _, rule := range b.BlockedRepos {
			if rule.Effect == "no-capture" {
				return false
			}
		}
	}
	return !policy.RepoBlocked(b, remote, "no-capture")
}

// PolicyTimeReading supplies this process's monotonic base to a trusted live
// HTTPS transport before sending a request and at receipt. It conveys no grant.
func (s *Store) PolicyTimeReading() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.policyStart).Milliseconds()
}

func (s *Store) OfferTenantKeyOperation(ctx context.Context, in SignedRecord) error {
	r, err := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
	if err != nil || r.Header.Type != record.KindKeyOp {
		return failure("invalid_policy_context")
	}
	b, ok := r.Body.(*record.KeyOpBody)
	if !ok {
		return failure("invalid_policy_context")
	}
	// Initial tenant roots only enter through authenticated TLS login. Keep
	// the public refusal contract identical for both issuer roles.
	if b.Op == record.OpTenantKey {
		return failure("invalid_policy_context")
	}
	if b.Subject.Role == record.RoleService {
		return s.offerServiceKeyOperation(ctx, in, r, b)
	}
	if b.Subject.Role != record.RolePolicy {
		return failure("invalid_policy_context")
	}
	return s.write(ctx, func() error {
		var tenant string
		if s.conn.QueryRowContext(ctx, "SELECT tenant FROM tenant_context WHERE active=1").Scan(&tenant) != nil || tenant != b.Genesis {
			return failure("policy_context_required")
		}
		kr, err := s.tenantKeyring(ctx, tenant)
		if err != nil {
			return err
		}
		op := &sig.KeyOp{Rec: r, Body: b, Sigs: in.Sigs, Issuer: sig.TrustedIssuer{Tenant: tenant, Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin}}
		if sig.VerifyKeyOp(kr, op).Status != sig.OpAuthorized {
			return failure("invalid_policy_context")
		}
		signatures, _ := json.Marshal(in.Sigs)
		if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO tenant_key VALUES(?,?,?,?,?,0)", r.ID, tenant, r.HeaderJCS, r.BodyJCS, signatures); err != nil {
			return failure("storage_error")
		}
		return s.policyProjectionFence(ctx)
	})
}
func (s *Store) CapturePolicy(ctx context.Context) (string, *record.PolicyBody, error) {
	var id string
	var body *record.PolicyBody
	err := s.write(ctx, func() error {
		t, err := s.tenant(ctx)
		if err != nil {
			return err
		}
		if t == nil {
			return nil
		}
		b := t.body()
		if b == nil {
			return failure("policy_unavailable")
		}
		id = t.chain.HighestID
		raw, _ := json.Marshal(b)
		defer clear(raw)
		body = &record.PolicyBody{}
		if json.Unmarshal(raw, body) != nil {
			return failure("policy_unavailable")
		}
		return nil
	})
	return id, body, err
}

// validateAdmittedBody keeps capture sealed to the current policy head. Only
// transferred metadata may retain its signed source policy provenance; current
// authorization, capture restrictions and body overlays still apply separately.
func (d *databaseState) validateAdmittedBody(r *record.Record) error {
	h := r.Header
	if !d.store.bundleImport || d.tenant == nil || h.Red.Profile != record.ProfilePushMetadata || (h.Type != record.KindSession && h.Type != record.KindTask) {
		return d.tenant.validateBody(r)
	}
	if h.Pol == "" || d.policyTenants[h.Pol] != d.tenant.tenant || d.policyLogout[h.Pol] {
		return failure("policy_violation")
	}
	a := d.bundleAuthorization(r)
	if !d.tenant.sealAllowed(a.Repo, h.Red.Epoch) || !transport.BundlePolicyAllowed(r, a) {
		return failure("policy_violation")
	}
	return nil
}

func (t *tenantState) validateBody(r *record.Record) error {
	if r.Header.Type.IsControl() {
		return nil
	}
	if t == nil {
		if r.Header.Pol != "" {
			return failure("policy_unavailable")
		}
		return nil
	}
	if !t.sealAllowed(recordRemote(r), r.Header.Red.Epoch) || r.Header.Pol != t.chain.HighestID {
		return failure("policy_violation")
	}
	overlay, err := localpolicy.TenantOverlay(t.body())
	if err != nil {
		return failure("policy_violation")
	}
	if !bodyPolicyAllowed(r.Body, overlay) {
		return failure("policy_violation")
	}
	return nil
}
func recordRemote(r *record.Record) string {
	if b, ok := r.Body.(*record.SessionBody); ok && b.Repo != nil {
		return b.Repo.Remote
	}
	return ""
}
