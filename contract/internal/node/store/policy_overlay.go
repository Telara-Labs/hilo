package store

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"

	"github.com/Telara-Labs/telara-memory/contract/policy"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// A tenant policy staged during coverage-pending recovery may both tighten
// and relax authority. Its relaxations wait in the verification-only view,
// but its restrictions apply at once through a local effective-policy overlay:
// the intersection of the committed head with every staged candidate above
// the head's sequence. The overlay is not a signed policy. It never becomes
// the head, never changes the head's id or sequence, and records sealed under
// it still name the head. It is durable, so it survives restart, and it is
// dropped once the head reaches the candidate's sequence by ordinary commit.

const policyOverlaySchema = `
CREATE TABLE IF NOT EXISTS policy_overlay(tenant TEXT NOT NULL,id TEXT NOT NULL,seq INTEGER NOT NULL,body BLOB NOT NULL,PRIMARY KEY(tenant,id));
`

// maxPolicyOverlays bounds staged candidates; it matches the staged view.
const maxPolicyOverlays = 256

// recordPolicyOverlay persists a verified staged candidate's restrictions.
func (s *Store) recordPolicyOverlay(ctx context.Context, t *tenantState, p *policy.Policy) error {
	if p.Body.Seq <= t.chain.HighestSeq {
		return nil
	}
	var n int
	if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM policy_overlay WHERE tenant=?", t.tenant).Scan(&n) != nil {
		return failure("storage_error")
	}
	if n >= maxPolicyOverlays {
		return failure("invalid_request")
	}
	raw, err := json.Marshal(p.Body)
	if err != nil {
		return failure("invalid_policy")
	}
	defer clear(raw)
	res, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO policy_overlay VALUES(?,?,?,?)", t.tenant, p.ID, p.Body.Seq, raw)
	if err != nil {
		return failure("storage_error")
	}
	if added, _ := res.RowsAffected(); added == 0 {
		return nil
	}
	return s.policyProjectionFence(ctx)
}

// clearPolicyOverlays drops candidates the committed head has reached.
func (s *Store) clearPolicyOverlays(ctx context.Context, tenant string, through int64) error {
	if _, err := s.conn.ExecContext(ctx, "DELETE FROM policy_overlay WHERE tenant=? AND seq<=?", tenant, through); err != nil {
		return failure("storage_error")
	}
	return nil
}

// loadPolicyOverlay intersects the verified head with every staged candidate
// above its sequence. An unreadable overlay fails closed.
func (s *Store) loadPolicyOverlay(ctx context.Context, t *tenantState) error {
	if t.chain.Head == nil {
		return nil
	}
	// Read-only inspection may open a database written before the table.
	var present int
	if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='policy_overlay'").Scan(&present) != nil {
		return failure("storage_error")
	}
	if present == 0 {
		return nil
	}
	rows, err := s.conn.QueryContext(ctx, "SELECT body FROM policy_overlay WHERE tenant=? AND seq>? ORDER BY seq,id LIMIT ?", t.tenant, t.chain.HighestSeq, maxPolicyOverlays+1)
	if err != nil {
		return failure("storage_error")
	}
	defer rows.Close()
	eff := t.chain.Head.Body
	count := 0
	for rows.Next() {
		count++
		var raw []byte
		if count > maxPolicyOverlays || rows.Scan(&raw) != nil {
			return failure("corrupt_database")
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var c record.PolicyBody
		err := dec.Decode(&c)
		clear(raw)
		if err != nil || c.Tenant != t.tenant {
			return failure("corrupt_database")
		}
		eff = intersectPolicy(eff, &c, t.user)
	}
	if rows.Err() != nil {
		return failure("storage_error")
	}
	if count > 0 {
		t.overlay = eff
	}
	return nil
}

// intersectPolicy returns a policy that allows only what both allow. Identity
// fields stay the head's. Allowed repositories are intersected by exact
// glob, a subset of the true intersection, which only denies more.
func intersectPolicy(head, c *record.PolicyBody, user string) *record.PolicyBody {
	out := *head
	out.Applies.Users = slices.Clone(head.Applies.Users)
	if !policy.AppliesTo(c, user) {
		out.Applies.Users = nil
	}
	if c.NotAfter < out.NotAfter {
		out.NotAfter = c.NotAfter
	}
	if c.RefreshAfter != 0 && (out.RefreshAfter == 0 || c.RefreshAfter < out.RefreshAfter) {
		out.RefreshAfter = c.RefreshAfter
	}
	out.Kill = record.PolicyKill{Sync: head.Kill.Sync || c.Kill.Sync, CaptureTenantRepos: head.Kill.CaptureTenantRepos || c.Kill.CaptureTenantRepos, WithdrawPulled: head.Kill.WithdrawPulled || c.Kill.WithdrawPulled}
	out.BlockedRepos = slices.Clone(head.BlockedRepos)
	for _, b := range c.BlockedRepos {
		if !slices.Contains(out.BlockedRepos, b) {
			out.BlockedRepos = append(out.BlockedRepos, b)
		}
	}
	out.Redaction.MinEpoch = max(head.Redaction.MinEpoch, c.Redaction.MinEpoch)
	out.Redaction.Shapes = slices.Clone(head.Redaction.Shapes)
	for _, sh := range c.Redaction.Shapes {
		if !slices.Contains(out.Redaction.Shapes, sh) {
			out.Redaction.Shapes = append(out.Redaction.Shapes, sh)
		}
	}
	out.Push.MaxProfile = ""
	if head.Push.MaxProfile == record.ProfilePushMetadata && c.Push.MaxProfile == record.ProfilePushMetadata {
		out.Push.MaxProfile = record.ProfilePushMetadata
	}
	out.Push.RequirePreview = head.Push.RequirePreview || c.Push.RequirePreview
	switch {
	case slices.Contains(head.Push.AllowRepos, "*"):
		out.Push.AllowRepos = slices.Clone(c.Push.AllowRepos)
	case slices.Contains(c.Push.AllowRepos, "*"):
		out.Push.AllowRepos = slices.Clone(head.Push.AllowRepos)
	default:
		out.Push.AllowRepos = nil
		for _, g := range head.Push.AllowRepos {
			if slices.Contains(c.Push.AllowRepos, g) {
				out.Push.AllowRepos = append(out.Push.AllowRepos, g)
			}
		}
	}
	out.Readback = record.PolicyReadback{HookInjection: head.Readback.HookInjection && c.Readback.HookInjection, CloudPull: head.Readback.CloudPull && c.Readback.CloudPull, HostedOriginPull: head.Readback.HostedOriginPull && c.Readback.HostedOriginPull}
	return &out
}
