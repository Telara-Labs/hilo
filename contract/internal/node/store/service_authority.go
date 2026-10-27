package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

const serviceAuthoritySchema = `CREATE TABLE IF NOT EXISTS tenant_service_key(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,header BLOB NOT NULL,body BLOB NOT NULL,sigs BLOB NOT NULL,login INTEGER NOT NULL CHECK(login IN(0,1)));`

// InstallServiceKeyRoots accepts only roots supplied by the authenticated TLS
// login adapter. Public enrollment documents and bundle data never call it.
// The exact signed operations are retained so subsequent rotation/revocation
// is verified through the same causal keyring as the policy authority.
func (s *Store) InstallServiceKeyRoots(ctx context.Context, tenant string, roots []SignedRecord) error {
	if tenant == "" || len(roots) == 0 || len(roots) > 16 {
		return failure("invalid_service_context")
	}
	return s.write(ctx, func() error {
		var active string
		if s.conn.QueryRowContext(ctx, "SELECT tenant FROM tenant_context WHERE active=1").Scan(&active) != nil || active != tenant {
			return failure("policy_context_required")
		}
		kr, err := s.serviceKeyring(ctx, tenant)
		if err != nil && Code(err) != "service_pins_required" {
			return err
		}
		if kr == nil {
			kr = sig.NewKeyring(s.opts.PinnedGenesisID)
		}
		for _, in := range roots {
			r, err := record.Parse(in.HeaderJCS, in.BodyJCS, in.AdvisoryID)
			if err != nil {
				return failure("invalid_service_context")
			}
			b, ok := r.Body.(*record.KeyOpBody)
			if !ok || b.Op != record.OpTenantKey || b.Subject.Role != record.RoleService || b.Genesis != tenant {
				return failure("invalid_service_context")
			}
			op := &sig.KeyOp{Rec: r, Body: b, Sigs: in.Sigs, FromLogin: true, Issuer: receiptIssuerContext(tenant)}
			if sig.VerifyKeyOpContext(ctx, kr, op).Status != sig.OpAuthorized {
				return failure("invalid_service_context")
			}
			raw, _ := json.Marshal(in.Sigs)
			if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO tenant_service_key VALUES(?,?,?,?,?,1)", r.ID, tenant, r.HeaderJCS, r.BodyJCS, raw); err != nil {
				return failure("storage_error")
			}
		}
		return nil
	})
}

func (s *Store) serviceKeyring(ctx context.Context, tenant string) (*sig.Keyring, error) {
	rows, err := s.conn.QueryContext(ctx, "SELECT id,header,body,sigs,login FROM tenant_service_key WHERE tenant=? ORDER BY rowid", tenant)
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
		var header, body, raw []byte
		var login bool
		if rows.Scan(&id, &header, &body, &raw, &login) != nil {
			return nil, failure("storage_error")
		}
		r, err := record.Parse(header, body, id)
		if err != nil {
			return nil, failure("corrupt_database")
		}
		b, ok := r.Body.(*record.KeyOpBody)
		if !ok || b.Subject.Role != record.RoleService || b.Genesis != tenant {
			return nil, failure("corrupt_database")
		}
		op := &sig.KeyOp{Rec: r, Body: b, Sigs: decodeSignatures(raw), FromLogin: login, AdmittedSeq: int64(count), Issuer: receiptIssuerContext(tenant)}
		if kr.Add(op) != nil {
			return nil, failure("corrupt_database")
		}
	}
	if rows.Err() != nil {
		return nil, failure("storage_error")
	}
	if count == 0 {
		return nil, failure("service_pins_required")
	}
	return kr, nil
}

// ServiceKeyState returns current role/tenant-scoped active, retired and
// revoked keys. Callers must evaluate it at receipt verification time rather
// than cache the public keys captured at login.
func (s *Store) ServiceKeyState(ctx context.Context, tenant string) (*sig.State, error) {
	var state *sig.State
	err := s.write(ctx, func() error {
		kr, err := s.serviceKeyring(ctx, tenant)
		if err != nil {
			return err
		}
		state, err = kr.StateContext(ctx)
		return contractEvaluationError(err)
	})
	return state, err
}

func (s *Store) offerServiceKeyOperation(ctx context.Context, in SignedRecord, r *record.Record, b *record.KeyOpBody) error {
	if b.Op != record.OpTenantKeyRotate {
		return failure("invalid_service_context")
	}
	return s.write(ctx, func() error {
		var tenant string
		if err := s.conn.QueryRowContext(ctx, "SELECT tenant FROM tenant_context WHERE active=1").Scan(&tenant); err != nil {
			if err == sql.ErrNoRows {
				return failure("policy_context_required")
			}
			return failure("storage_error")
		}
		if b.Genesis != tenant {
			return failure("invalid_service_context")
		}
		kr, err := s.serviceKeyring(ctx, tenant)
		if err != nil {
			return err
		}
		op := &sig.KeyOp{Rec: r, Body: b, Sigs: in.Sigs, Issuer: receiptIssuerContext(tenant)}
		if status := sig.VerifyKeyOpContext(ctx, kr, op).Status; status != sig.OpAuthorized && status != sig.OpConflictLost {
			return failure("invalid_service_context")
		}
		raw, _ := json.Marshal(in.Sigs)
		if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO tenant_service_key VALUES(?,?,?,?,?,0)", r.ID, tenant, r.HeaderJCS, r.BodyJCS, raw); err != nil {
			return failure("storage_error")
		}
		// Receipt-backed grandfathering must be reevaluated immediately when its
		// service authority changes, as with any other projection authority.
		return s.policyProjectionFence(ctx)
	})
}
