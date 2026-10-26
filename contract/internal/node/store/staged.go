package store

import (
	"context"
	"slices"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/policy"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// Coverage-pending recovery uses a verification-only authority view: the
// completed durable keyring and tenant pins plus key operations and policies
// that are staged, in log order, while an earlier erasure still lacks event
// coverage. The view is rebuilt from the caller's exact staged envelopes on
// every call. Nothing staged is written, so no staged relaxation or key
// activation becomes live by loading it, and a staged op cannot authorize
// itself because the keyring requires an authorizer already in its history.
// Staged policies are also reduced by sequence and identity in a view-only
// chain that starts at the committed chain. It decides nothing by itself: it
// names the staged policy a later one equivocates with or rolls back behind.

type authorityView struct {
	devices *sig.Keyring
	tenant  *sig.Keyring
	service *sig.Keyring
	name    string
	// policy is the verification-only chain: the committed sequence and id
	// plus every staged policy in log order. Its head is a private copy.
	policy *policy.Chain
}

// release scrubs the view chain's private copy of a staged policy body.
func (v *authorityView) release() {
	if v != nil && v.policy != nil {
		v.policy.Logout()
	}
}

// stagedView replays staged controls into a copy of completed authority and
// refuses any that is not valid at its position.
func (s *Store) stagedView(ctx context.Context, d *databaseState, staged []SignedRecord) (_ *authorityView, err error) {
	if len(staged) > 256 {
		return nil, failure("invalid_request")
	}
	v := &authorityView{devices: sig.NewKeyring(s.opts.PinnedGenesisID)}
	defer func() {
		if err != nil {
			v.release()
		}
	}()
	for _, op := range d.kr.Ops() {
		if v.devices.Add(op) != nil {
			return nil, failure("corrupt_database")
		}
	}
	if d.tenant != nil {
		kr, err := s.tenantKeyring(ctx, d.tenant.tenant)
		if err != nil {
			return nil, err
		}
		v.tenant, v.name = kr, d.tenant.tenant
		if service, err := s.serviceKeyring(ctx, v.name); err == nil {
			v.service = service
		} else if Code(err) != "service_pins_required" {
			return nil, err
		}
		c := d.tenant.chain
		v.policy = &policy.Chain{Tenant: c.Tenant, HighestSeq: c.HighestSeq, HighestID: c.HighestID, Tampered: c.Tampered}
	}
	seq := d.nextSeq
	for _, in := range staged {
		if len(in.HeaderJCS) > record.MaxHeaderBytes || len(in.BodyJCS) > record.MaxBodyBytes || len(in.Sigs) == 0 || len(in.Sigs) > 2 {
			return nil, failure("invalid_record")
		}
		r, err := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
		if err != nil {
			return nil, failure("invalid_record")
		}
		switch b := r.Body.(type) {
		case *record.KeyOpBody:
			seq++
			op := &sig.KeyOp{Rec: r, Body: b, Sigs: in.Sigs, AdmittedSeq: seq}
			kr := v.devices
			switch {
			case b.Op == record.OpTenantKey:
				// Tenant roots come only from an authenticated login.
				return nil, failure("unauthorized_staged")
			case b.Subject.Role == record.RoleDevice:
				if b.Genesis != s.opts.PinnedGenesisID {
					return nil, failure("unauthorized_staged")
				}
			case b.Subject.Role == record.RoleService && v.service != nil && b.Genesis == v.name:
				op.Issuer = receiptIssuerContext(v.name)
				kr = v.service
			case b.Subject.Role == record.RolePolicy && v.tenant != nil && b.Genesis == v.name:
				op.Issuer = sig.TrustedIssuer{Tenant: v.name, Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin}
				kr = v.tenant
			default:
				return nil, failure("unauthorized_staged")
			}
			if st := sig.VerifyKeyOp(kr, op).Status; st != sig.OpAuthorized && st != sig.OpConflictLost {
				return nil, failure("unauthorized_staged")
			}
		case *record.PolicyBody:
			if v.tenant == nil {
				return nil, failure("policy_context_required")
			}
			p, err := policy.Verify(r, in.Sigs, v.tenant.State(), sig.TrustedIssuer{Tenant: v.name, Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin})
			if err != nil {
				return nil, failure("invalid_policy")
			}
			// Rollback and equivocation inside the staged log are not errors:
			// ordinary order refuses or latches them when they commit.
			if _, err = v.policy.Offer(p); err != nil {
				return nil, failure("invalid_policy")
			}
		default:
			return nil, failure("invalid_request")
		}
	}
	return v, nil
}

// authorityState loads completed state as ordinary admission does, with the
// installed tenant authority.
func (s *Store) authorityState(ctx context.Context) (*databaseState, error) {
	d, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	if d.tenant == nil {
		if d.tenant, err = s.tenant(ctx); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// VerifyStaged checks that each staged key operation or policy is valid at its
// log position against completed authority plus the staged controls before it.
// It writes nothing.
func (s *Store) VerifyStaged(ctx context.Context, staged []SignedRecord) error {
	return s.write(ctx, func() error {
		d, err := s.authorityState(ctx)
		if err != nil {
			return err
		}
		v, err := s.stagedView(ctx, d, staged)
		v.release()
		return err
	})
}

// PolicyRelaxes verifies a tenant policy in the staged view and reports whether
// committing it would relax current durable authority in any respect. Only a
// policy that is at least as restrictive everywhere reports false. Rollback and
// equal-sequence offers against the committed chain report false: their
// durable effect is a refusal or the equivocation latch, never a relaxation.
// A policy above the committed chain but below a staged one is a rollback in
// log order; it reports true, so it stays staged, and it supplies nothing.
// Durable authority is the effective policy, including restrictions already
// staged. It writes nothing.
func (s *Store) PolicyRelaxes(ctx context.Context, in SignedRecord, staged []SignedRecord) (bool, error) {
	return s.stagePolicy(ctx, in, staged, false)
}

// StagePolicy is PolicyRelaxes for a policy about to be staged. A relaxing
// policy's restrictions apply at once and durably: in the same writer
// transaction it joins the effective-policy overlay, so disclosure, capture,
// push and pull enforce the intersection of the committed head and every
// staged candidate. Its relaxations stay staged until it commits normally.
// A policy that equivocates with the view's highest policy, staged or
// committed, durably records both ids at that sequence in the same
// transaction. The latch then applies at once and survives restart and logout,
// though neither policy's permissions become live.
func (s *Store) StagePolicy(ctx context.Context, in SignedRecord, staged []SignedRecord) (bool, error) {
	return s.stagePolicy(ctx, in, staged, true)
}

func (s *Store) stagePolicy(ctx context.Context, in SignedRecord, staged []SignedRecord, persist bool) (bool, error) {
	var relaxes bool
	err := s.write(ctx, func() error {
		d, err := s.authorityState(ctx)
		if err != nil {
			return err
		}
		if d.tenant == nil {
			return failure("policy_context_required")
		}
		v, err := s.stagedView(ctx, d, staged)
		if err != nil {
			return err
		}
		r, err := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
		if err != nil || r.Header.Type != record.KindPolicy {
			return failure("invalid_policy")
		}
		defer v.release()
		p, err := policy.Verify(r, in.Sigs, v.tenant.State(), sig.TrustedIssuer{Tenant: v.name, Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin})
		if err != nil {
			return failure("invalid_policy")
		}
		t := d.tenant
		prior := v.policy.HighestID
		offered, err := v.policy.Offer(p)
		if err != nil {
			return failure("invalid_policy")
		}
		if offered == policy.Tamper && persist {
			if err = s.recordEquivocation(ctx, t.tenant, p.Body.Seq, prior, p.ID); err != nil {
				return err
			}
		}
		switch {
		case p.Body.Seq <= t.chain.HighestSeq:
			relaxes = false
		case offered == policy.Rollback:
			// Committing it after its staged successor is a refused rollback.
			relaxes = true
			return nil
		case t.chain.Tampered || t.chain.Head == nil:
			relaxes = true
		case t.freshness != policy.Fresh && t.freshness != policy.RefreshDue:
			// A stale head supplies no authority; a fresh successor restores it.
			relaxes = true
		default:
			relaxes = policyRelaxes(t.body(), p.Body, t.user)
		}
		if relaxes && persist {
			return s.recordPolicyOverlay(ctx, t, p)
		}
		return nil
	})
	return relaxes, err
}

// policyRelaxes reports whether next allows anything head does not.
func policyRelaxes(head, next *record.PolicyBody, user string) bool {
	if policy.AppliesTo(next, user) && !policy.AppliesTo(head, user) || next.NotAfter > head.NotAfter {
		return true
	}
	if head.Kill.Sync && !next.Kill.Sync || head.Kill.CaptureTenantRepos && !next.Kill.CaptureTenantRepos || head.Kill.WithdrawPulled && !next.Kill.WithdrawPulled {
		return true
	}
	for _, b := range head.BlockedRepos {
		if !slices.Contains(next.BlockedRepos, b) {
			return true
		}
	}
	if next.Redaction.MinEpoch < head.Redaction.MinEpoch {
		return true
	}
	for _, sh := range head.Redaction.Shapes {
		if !slices.Contains(next.Redaction.Shapes, sh) {
			return true
		}
	}
	if next.Push.MaxProfile == record.ProfilePushMetadata && head.Push.MaxProfile != record.ProfilePushMetadata || head.Push.RequirePreview && !next.Push.RequirePreview {
		return true
	}
	if !slices.Contains(head.Push.AllowRepos, "*") {
		for _, g := range next.Push.AllowRepos {
			if !slices.Contains(head.Push.AllowRepos, g) {
				return true
			}
		}
	}
	h, n := head.Readback, next.Readback
	return n.HookInjection && !h.HookInjection || n.CloudPull && !h.CloudPull || n.HostedOriginPull && !h.HostedOriginPull
}

// ApplySupplement admits one erasure or retraction signed by an enrolled
// device of the pinned genesis, including another device than this one. It
// needs no private signing key. Only the control is persisted. An erasure may
// be verified against the staged view, so a key enrolled after a
// coverage-pending erasure can supply its supplement; a retraction is verified
// against completed authority only. The control's bans and membership are
// permanent facts once admitted, independently of later key state.
func (s *Store) ApplySupplement(ctx context.Context, in SignedRecord, staged []SignedRecord) (AdmissionResult, error) {
	r, signatures, err := parse(in)
	if err != nil {
		return AdmissionResult{}, err
	}
	if r.Header.Type != record.KindErasure && r.Header.Type != record.KindRetraction {
		return AdmissionResult{}, failure("unsupported_context")
	}
	var out AdmissionResult
	err = s.write(ctx, func() error {
		d, err := s.authorityState(ctx)
		if err != nil {
			return err
		}
		var view *sig.State
		if r.Header.Type == record.KindErasure && len(staged) > 0 {
			v, err := s.stagedView(ctx, d, staged)
			if err != nil {
				return err
			}
			v.release()
			view = v.devices.State()
		}
		// A staged rotation of this device's key retires the old key durably
		// at once while its successor is active only in the view, so
		// enrollment is satisfied by either.
		if !localEnrolled(d.keyState(), s.opts) && !localEnrolled(view, s.opts) {
			return failure("device_not_enrolled")
		}
		s.verifyView = view
		s.bundleImport = true
		defer func() { s.bundleImport, s.verifyView = false, nil }()
		out, err = s.appendLocked(ctx, r, signatures)
		return err
	})
	return out, err
}

// A device key operation staged during coverage-pending recovery may carry
// restrictive consequences for keys that are already active: a rotation
// retires its previous key, a rotation that wins against an earlier one
// revokes the loser's subject for conflict, and a revocation whose parents are
// only staged revokes its subject. Those consequences apply at once and
// durably through a key-restriction overlay that keeps the exact staged
// envelope. Effective key state is completed authority restricted by the
// state the overlay operations would fold to: a key already present may only
// move from active to retired or revoked, gaining revocation causes. A key
// that exists only because of a staged operation is never activated by it. A
// row is dropped when its operation is admitted durably by ordinary
// admission, and kept when revalidation refuses it, so restrictions survive.

const keyRestrictionSchema = `
CREATE TABLE IF NOT EXISTS key_restriction(id TEXT PRIMARY KEY,seq INTEGER NOT NULL,header BLOB NOT NULL,sigs BLOB NOT NULL,body BLOB NOT NULL);
`

// maxKeyRestrictions bounds staged key operations; it matches the staged view.
const maxKeyRestrictions = 256

// StageKeyOperation verifies a device key operation at its position in the
// staged view and stages it. Its restrictive consequences for keys that are
// already active apply at once and durably, in the same writer transaction;
// its key activation stays only in the verification view until it commits by
// ordinary admission.
func (s *Store) StageKeyOperation(ctx context.Context, in SignedRecord, staged []SignedRecord) error {
	return s.write(ctx, func() error {
		d, err := s.authorityState(ctx)
		if err != nil {
			return err
		}
		v, err := s.stagedView(ctx, d, append(append([]SignedRecord(nil), staged...), in))
		if err != nil {
			return err
		}
		v.release()
		r, signatures, err := parse(in)
		if err != nil {
			return err
		}
		b, ok := r.Body.(*record.KeyOpBody)
		if !ok || b.Subject.Role != record.RoleDevice || b.Genesis != s.opts.PinnedGenesisID {
			return failure("unauthorized_staged")
		}
		if d.byID[r.ID] != nil {
			return nil
		}
		var n int
		if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM key_restriction").Scan(&n) != nil {
			return failure("storage_error")
		}
		if n >= maxKeyRestrictions {
			return failure("invalid_request")
		}
		raw, err := jcs.MarshalRecord(signatures)
		if err != nil {
			return failure("invalid_record")
		}
		res, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO key_restriction VALUES(?,?,?,?,?)", r.ID, d.nextSeq, r.HeaderJCS, raw, r.BodyJCS)
		if err != nil {
			return failure("storage_error")
		}
		if added, _ := res.RowsAffected(); added == 0 {
			return nil
		}
		return s.policyProjectionFence(ctx)
	})
}

// loadKeyRestrictions reads staged key operations not yet admitted durably.
// An unreadable or foreign row fails closed.
func (s *Store) loadKeyRestrictions(ctx context.Context, d *databaseState) error {
	d.restrict = nil
	// Read-only inspection may open a database written before the table.
	var present int
	if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='key_restriction'").Scan(&present) != nil {
		return failure("storage_error")
	}
	if present == 0 {
		return nil
	}
	rows, err := s.conn.QueryContext(ctx, "SELECT id,seq,header,sigs,body FROM key_restriction ORDER BY seq,id LIMIT ?", maxKeyRestrictions+1)
	if err != nil {
		return failure("storage_error")
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var seq int64
		var h, sg, b []byte
		if len(d.restrict) >= maxKeyRestrictions || rows.Scan(&id, &seq, &h, &sg, &b) != nil {
			return failure("corrupt_database")
		}
		r, signatures, err := parse(SignedRecord{HeaderJCS: h, BodyJCS: b, Sigs: decodeSignatures(sg), AdvisoryID: id})
		if err != nil || r.Header.Type != record.KindKeyOp || seq <= 0 {
			return failure("corrupt_database")
		}
		body := r.Body.(*record.KeyOpBody)
		if body.Genesis != s.opts.PinnedGenesisID {
			return failure("corrupt_database")
		}
		d.restrict = append(d.restrict, &sig.KeyOp{Rec: r, Body: body, Sigs: signatures, AdmittedSeq: seq})
	}
	if rows.Err() != nil {
		return failure("storage_error")
	}
	return nil
}

// keyState is the effective device key state: completed authority restricted
// by the staged key-restriction overlay.
func (d *databaseState) keyState() *sig.State {
	st := d.kr.State()
	if len(d.restrict) == 0 {
		return st
	}
	kr := sig.NewKeyring(d.kr.Pinned())
	ops := d.kr.Ops()
	for _, op := range ops {
		if kr.Add(op) != nil {
			return st
		}
	}
	for _, op := range d.restrict {
		if ops[op.Rec.ID] == nil {
			// A row that no longer adds to the keyring restricts nothing more.
			_ = kr.Add(op)
		}
	}
	restrictKeys(st, kr.State())
	return st
}

func keySeverity(s sig.KeyStatus) int {
	switch s {
	case sig.KeyActive:
		return 0
	case sig.KeyRetired:
		return 1
	}
	return 2
}

// restrictKeys moves each key of st to the more restrictive status in
// combined, never the reverse, and never adds a key.
func restrictKeys(st, combined *sig.State) {
	for binding, k := range st.Keys {
		c := combined.Keys[binding]
		if c == nil || keySeverity(c.Status) < keySeverity(k.Status) {
			continue
		}
		if c.Status == sig.KeyRevoked {
			causes := slices.Clone(k.RevocationCauses)
			for _, cause := range c.RevocationCauses {
				if !slices.Contains(causes, cause) {
					causes = append(causes, cause)
				}
			}
			slices.Sort(causes)
			k.RevocationCauses = causes
			if k.Status != sig.KeyRevoked || c.RevokedReason == "compromised" {
				k.RevokedReason = c.RevokedReason
			}
			if c.RevokedSeq > 0 && (k.RevokedSeq == 0 || c.RevokedSeq < k.RevokedSeq) {
				k.RevokedSeq = c.RevokedSeq
			}
		}
		k.Status = c.Status
	}
}

func localEnrolled(st *sig.State, o Options) bool {
	if st == nil {
		return false
	}
	for _, k := range st.Keys {
		if k.Role == record.RoleDevice && k.Genesis == o.PinnedGenesisID && k.MachineID == o.LocalMachineID && k.Status == sig.KeyActive {
			return true
		}
	}
	return false
}

// DeviceKeyStatus reports a device key's effective durable status: active,
// retired or revoked, or empty when completed authority does not hold it. A
// key active only in a staged verification view reports empty.
func (s *Store) DeviceKeyStatus(ctx context.Context, keyID string) (string, error) {
	var out string
	err := s.write(ctx, func() error {
		d, err := s.loadAuthority(ctx)
		if err != nil {
			return err
		}
		if k := d.keyState().KeyFor(keyID, record.RoleDevice, ""); k != nil {
			out = string(k.Status)
		}
		return nil
	})
	return out, err
}
