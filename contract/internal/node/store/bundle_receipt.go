package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// maxBundleReceipts bounds retained receipts and receipt issuer keys.
const maxBundleReceipts = 16384

// ReceiptIssuer is this device's existing receipt authority: one tenant and
// the service keys pinned for it over an authenticated TLS login. It is
// receiver state, never bundle content; a bundle cannot create it.
type ReceiptIssuer struct {
	Tenant string
	Keys   map[string]ed25519.PublicKey // key id to public key
	state  *sig.State                   // current locally retained service authority, never wire data
}

func receiptIssuerContext(tenant string) sig.TrustedIssuer {
	return sig.TrustedIssuer{Tenant: tenant, Role: record.RoleService, Provenance: sig.PinnedTLSLogin}
}

func serviceBinding(tenant, keyID string) string {
	return record.H("authority", string(record.RoleService), tenant, keyID)
}

// valid reports a well-formed pin set whose key ids match their keys.
func (i *ReceiptIssuer) valid() bool {
	if i == nil || i.Tenant == "" || len(i.Tenant) > 200 || len(i.Keys) == 0 || len(i.Keys) > 16 {
		return false
	}
	for id, pub := range i.Keys {
		if len(pub) != ed25519.PublicKeySize || sig.KeyID(pub) != id {
			return false
		}
	}
	return true
}

// verify returns the carried receipts that verify under the pinned issuer,
// each bound to the record id it is carried with. Without a valid pin it
// verifies none.
func (i *ReceiptIssuer) verify(carried map[string]record.Receipt) map[string]record.Receipt {
	out := map[string]record.Receipt{}
	if !i.valid() {
		return out
	}
	st := &sig.State{Keys: map[string]*sig.Key{}}
	for id, pub := range i.Keys {
		st.Keys[serviceBinding(i.Tenant, id)] = &sig.Key{KeyID: id, Pub: pub, Role: record.RoleService, Tenant: i.Tenant, Status: sig.KeyActive}
	}
	if i.state != nil {
		st = i.state
	}
	for id, rc := range carried {
		if rc.ID == id && rc.Tenant == i.Tenant && sig.VerifyReceipt(rc, st, receiptIssuerContext(i.Tenant)) == nil {
			out[id] = rc
		}
	}
	return out
}

func (s *Store) persistReceiptIssuer(ctx context.Context, i *ReceiptIssuer) error {
	for id, pub := range i.Keys {
		if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO bundle_receipt_issuer VALUES(?,?,?)", i.Tenant, id, []byte(pub)); err != nil {
			return failure("storage_error")
		}
	}
	return nil
}

func (s *Store) persistReceipt(ctx context.Context, rc record.Receipt) error {
	raw, err := jcs.MarshalRecord(rc)
	if err != nil {
		return failure("invalid_bundle")
	}
	if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO bundle_receipt VALUES(?,?)", rc.ID, raw); err != nil {
		return failure("storage_error")
	}
	return nil
}

// loadReceipts reads retained verified receipts and the pinned issuer keys
// they were verified under.
func (s *Store) loadReceipts(ctx context.Context, d *databaseState) error {
	d.receipts = map[string]record.Receipt{}
	d.receiptIssuers = map[string]map[string]ed25519.PublicKey{}
	rows, err := s.conn.QueryContext(ctx, "SELECT id,receipt FROM bundle_receipt ORDER BY id LIMIT ?", maxBundleReceipts+1)
	if err != nil {
		return failure("storage_error")
	}
	for rows.Next() {
		var id string
		var raw []byte
		var rc record.Receipt
		if rows.Scan(&id, &raw) != nil {
			rows.Close()
			return failure("storage_error")
		}
		if json.Unmarshal(raw, &rc) != nil || rc.ID != id {
			rows.Close()
			return failure("corrupt_database")
		}
		d.receipts[id] = rc
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(d.receipts) > maxBundleReceipts {
		return failure("storage_error")
	}
	rows, err = s.conn.QueryContext(ctx, "SELECT tenant,key_id,pub FROM bundle_receipt_issuer ORDER BY tenant,key_id LIMIT ?", maxBundleReceipts+1)
	if err != nil {
		return failure("storage_error")
	}
	defer rows.Close()
	for rows.Next() {
		var tenant, id string
		var pub []byte
		if rows.Scan(&tenant, &id, &pub) != nil {
			return failure("storage_error")
		}
		if len(pub) != ed25519.PublicKeySize || sig.KeyID(pub) != id {
			return failure("corrupt_database")
		}
		if d.receiptIssuers[tenant] == nil {
			d.receiptIssuers[tenant] = map[string]ed25519.PublicKey{}
		}
		d.receiptIssuers[tenant][id] = ed25519.PublicKey(pub)
	}
	if rows.Err() != nil {
		return failure("storage_error")
	}
	return nil
}

// receiptState extends a keyring state with one tenant's pinned service keys
// and the retained receipts of its key operations, so revocation cutoffs are
// checked in that issuer's receipt-time domain. Nil when nothing is pinned.
func (d *databaseState) receiptState(st *sig.State, tenant string) *sig.State {
	keys := d.receiptIssuers[tenant]
	if len(keys) == 0 || st == nil {
		return nil
	}
	out := &sig.State{Genesis: st.Genesis, Keys: map[string]*sig.Key{}, Status: st.Status, Ops: map[string]*sig.KeyOp{}}
	for k, v := range st.Keys {
		out.Keys[k] = v
	}
	if kr, err := d.store.serviceKeyring(d.ctx, tenant); err == nil {
		for binding, key := range kr.State().Keys {
			out.Keys[binding] = key
		}
	} else if Code(err) == "service_pins_required" {
		for id, pub := range keys {
			out.Keys[serviceBinding(tenant, id)] = &sig.Key{KeyID: id, Pub: pub, Role: record.RoleService, Tenant: tenant, Status: sig.KeyActive}
		}
	} else {
		return nil
	}
	for id, op := range st.Ops {
		rc, ok := d.receipts[id]
		if !ok || rc.Tenant != tenant {
			out.Ops[id] = op
			continue
		}
		c := *op
		c.Receipt = &rc
		c.ReceiptIssuer = receiptIssuerContext(tenant)
		out.Ops[id] = &c
	}
	return out
}

// verifyWithReceipt is VerifyRecord on the local route, then, only for a
// record whose signer is revoked, the same verification with its retained
// (or, during import, its just-verified) receipt under the pinned issuer.
func (d *databaseState) verifyWithReceipt(r *record.Record, sigs []record.Signature, st *sig.State, seq int64, carried *record.Receipt) sig.Result {
	c := sig.Context{Route: record.RouteLocal, AdmittedSeq: seq}
	res := sig.VerifyRecord(r, sigs, st, c)
	if res.Status != sig.StatusSignerRevoked {
		return res
	}
	var rc record.Receipt
	if carried != nil {
		rc = *carried
	} else if retained, ok := d.receipts[r.ID]; ok {
		rc = retained
	} else {
		return res
	}
	rst := d.receiptState(st, rc.Tenant)
	if rst == nil {
		return res
	}
	c.Receipt = &rc
	c.ReceiptIssuer = receiptIssuerContext(rc.Tenant)
	if again := sig.VerifyRecord(r, sigs, rst, c); again.Status == sig.StatusVerified {
		return again
	}
	return res
}

// recordSigStatus is the rebuild status of one stored non-key record.
func (d *databaseState) recordSigStatus(x *stored, st *sig.State) sig.SigStatus {
	return d.verifyWithReceipt(x.rec, x.sigs, st, x.seq, nil).Status
}
