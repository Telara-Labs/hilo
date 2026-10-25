package store

import (
	"context"
	"slices"

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

type authorityView struct {
	devices *sig.Keyring
	tenant  *sig.Keyring
	name    string
}

// stagedView replays staged controls into a copy of completed authority and
// refuses any that is not valid at its position.
func (s *Store) stagedView(ctx context.Context, d *databaseState, staged []SignedRecord) (*authorityView, error) {
	if len(staged) > 256 {
		return nil, failure("invalid_request")
	}
	v := &authorityView{devices: sig.NewKeyring(s.opts.PinnedGenesisID)}
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
			if _, err = policy.Verify(r, in.Sigs, v.tenant.State(), sig.TrustedIssuer{Tenant: v.name, Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin}); err != nil {
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
		_, err = s.stagedView(ctx, d, staged)
		return err
	})
}

// PolicyRelaxes verifies a tenant policy in the staged view and reports whether
// committing it would relax current durable authority in any respect. Only a
// policy that is at least as restrictive everywhere reports false. Rollback and
// equal-sequence offers report false: their durable effect is a refusal or the
// equivocation latch, never a relaxation. Durable authority is the effective
// policy, including restrictions already staged. It writes nothing.
func (s *Store) PolicyRelaxes(ctx context.Context, in SignedRecord, staged []SignedRecord) (bool, error) {
	return s.stagePolicy(ctx, in, staged, false)
}

// StagePolicy is PolicyRelaxes for a policy about to be staged. A relaxing
// policy's restrictions apply at once and durably: in the same writer
// transaction it joins the effective-policy overlay, so disclosure, capture,
// push and pull enforce the intersection of the committed head and every
// staged candidate. Its relaxations stay staged until it commits normally.
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
		p, err := policy.Verify(r, in.Sigs, v.tenant.State(), sig.TrustedIssuer{Tenant: v.name, Role: record.RolePolicy, Provenance: sig.PinnedTLSLogin})
		if err != nil {
			return failure("invalid_policy")
		}
		t := d.tenant
		switch {
		case p.Body.Seq <= t.chain.HighestSeq:
			relaxes = false
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
		enrolled := false
		for _, k := range d.kr.State().Keys {
			if k.Role == record.RoleDevice && k.Genesis == s.opts.PinnedGenesisID && k.MachineID == s.opts.LocalMachineID && k.Status == sig.KeyActive {
				enrolled = true
			}
		}
		if !enrolled {
			return failure("device_not_enrolled")
		}
		if r.Header.Type == record.KindErasure && len(staged) > 0 {
			v, err := s.stagedView(ctx, d, staged)
			if err != nil {
				return err
			}
			s.verifyView = v.devices.State()
		}
		s.bundleImport = true
		defer func() { s.bundleImport, s.verifyView = false, nil }()
		out, err = s.appendLocked(ctx, r, signatures)
		return err
	})
	return out, err
}
