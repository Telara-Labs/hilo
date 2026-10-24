package sig

import (
	"errors"
	"fmt"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// SigStatus is a record's signature status.
type SigStatus string

const (
	StatusVerified      SigStatus = "verified"
	StatusSignerRevoked SigStatus = "signer-revoked"
	StatusUnsignedLocal SigStatus = "unsigned-local" // own record awaiting the key store; never pushed
	StatusUnknownSigner SigStatus = "unknown-signer" // quarantined; retry after keyring sync, expire after 7 days
	StatusRejected      SigStatus = "rejected"       // invalid recognized schema; discard raw bytes, never quarantine
	StatusInvalid       SigStatus = "invalid"        // quarantined; never indexed, never rendered
	StatusIgnored       SigStatus = "ignored"        // control kind over an unauthenticated route
)

// Quarantined reports statuses that keep the full envelope out of every
// projection.
func (s SigStatus) Quarantined() bool { return s == StatusUnknownSigner || s == StatusInvalid }

// Context carries receiver-side facts VerifyRecord needs. None of it is part
// of the record.
type Context struct {
	SignerRole    record.Role   // default device; service/policy require trusted issuer
	Issuer        TrustedIssuer // authenticated transport/pinned login, not record metadata
	ReceiptIssuer TrustedIssuer // independent authenticated issuer of receipt
	Route         record.Route
	AdmittedSeq   int64           // this node's admission order of the record
	Receipt       *record.Receipt // hosted acceptance, if carried
	RecordID      string          // filled by VerifyRecord, never caller authority
}

// Result is the outcome of VerifyRecord.
type Result struct {
	Status SigStatus
	Key    *Key   // the signing key when known
	Owner  string // owner namespace of the signer
	Reason string // why the status is not verified
}

func fail(s SigStatus, format string, a ...any) Result {
	return Result{Status: s, Reason: fmt.Sprintf(format, a...)}
}

// VerifyRecord verifies a record of any kind except key_op against the
// folded keyring. It checks, in order: the signature list shape, the
// signer is in the keyring, the Ed25519 signature, the signer and
// provenance matrix, the device machine binding, the owner-scoped
// LID, and validity across rotation and revocation. Retired keys
// verify. A record that fails is quarantined, never indexed.
func VerifyRecord(r *record.Record, sigs []record.Signature, st *State, c Context) Result {
	if r == nil || st == nil {
		return fail(StatusInvalid, "record and keyring required")
	}
	parsed, err := record.Parse(r.HeaderJCS, r.BodyJCS, r.ID)
	if err != nil {
		var admission *record.Error
		if errors.As(err, &admission) && admission.Quarantine {
			return fail(StatusInvalid, "unsupported opaque record")
		}
		return fail(StatusRejected, "invalid canonical record")
	}
	r = parsed
	c.RecordID = r.ID
	h := r.Header
	if h.Type == record.KindKeyOp {
		return fail(StatusInvalid, "key_op records are verified by VerifyKeyOp")
	}
	if c.Route == record.RouteGitImport && h.Type.IsControl() {
		return fail(StatusIgnored, "control records over an unauthenticated route have no effect")
	}
	if len(sigs) != 1 {
		return fail(StatusInvalid, "a record carries exactly one signature, has %d", len(sigs))
	}
	s := sigs[0]
	if s.Alg != AlgEd25519 || s.Ctx != CtxRecord || s.KeyID != h.Author.KeyID {
		return fail(StatusInvalid, "signature alg, ctx or key id does not match the header author")
	}
	role := c.SignerRole
	if role == "" {
		role = record.RoleDevice
	}
	if role != record.RoleDevice && !c.Issuer.ValidFor(role) {
		return fail(StatusUnknownSigner, "authenticated issuer context required")
	}
	k := st.KeyFor(s.KeyID, role, c.Issuer.Tenant)
	if k == nil {
		return fail(StatusUnknownSigner, "signer %s is not in the keyring", s.KeyID)
	}
	msg, err := RecordMessage(r.ID)
	if err != nil {
		return fail(StatusInvalid, "%v", err)
	}
	if err := Verify(k.Pub, CtxRecord, msg, s); err != nil {
		return fail(StatusInvalid, "%v", err)
	}
	res := Result{Key: k, Owner: k.Owner()}
	if !record.MatrixAllows(k.Role, h.Prov, h.Type) {
		res.Status, res.Reason = StatusInvalid, fmt.Sprintf("(%s, %s, %s) is not in the signer matrix", k.Role, h.Prov, h.Type)
		return res
	}
	if k.Role == record.RoleDevice && k.MachineID != h.Author.MachineID {
		res.Status, res.Reason = StatusInvalid, "author machine does not match the device key's machine"
		return res
	}
	if k.Role != record.RoleDevice && h.Author.MachineID != "" {
		res.Status, res.Reason = StatusInvalid, "a service or policy record names no machine"
		return res
	}
	if erasure, ok := r.Body.(*record.ErasureBody); ok {
		for _, event := range erasure.Selectors.Events {
			if k.Role != record.RoleDevice || event.Owner != res.Owner {
				res.Status, res.Reason = StatusInvalid, "event selector outside signer owner"
				return res
			}
		}
	}
	if record.OwnerScoped(&h) {
		lid, ok := record.ExpectedLID(&h, r.Body, res.Owner)
		if !ok || lid != h.LID {
			res.Status, res.Reason = StatusInvalid, "lid does not match the signer's owner namespace"
			return res
		}
	}
	switch k.Status {
	case KeyActive, KeyRetired:
		res.Status = StatusVerified
	case KeyRevoked:
		if PreRevocation(k, c, st) {
			res.Status = StatusVerified
		} else {
			res.Status, res.Reason = StatusSignerRevoked, "signed by a revoked key after its revocation"
		}
	}
	return res
}

// PreRevocation applies the prior-admission rule: a record signed by a revoked key stays
// verified if it carries a valid TSK receipt accepted before the revocation,
// or if this node admitted it before it admitted the revocation.
func PreRevocation(k *Key, c Context, st *State) bool {
	if c.AdmittedSeq > 0 && k.RevokedSeq > 0 && c.AdmittedSeq < k.RevokedSeq {
		return true
	}
	if c.Receipt != nil && VerifyReceipt(*c.Receipt, st, c.ReceiptIssuer) == nil && c.Receipt.ID == c.RecordID && (k.Role != record.RoleDevice || c.Receipt.DeviceID == k.MachineID) && beforeCutoff(k, *c.Receipt, st) {
		return true
	}
	return false
}

// VerifyReceipt checks a receipt's signature by an active or retired service
// key of the receipt's tenant.
func VerifyReceipt(r record.Receipt, st *State, issuer TrustedIssuer) error {
	if !issuer.ValidFor(record.RoleService) || r.Tenant != issuer.Tenant {
		return fmt.Errorf("receipt: authenticated issuer required")
	}
	if r.Sig == nil {
		return fmt.Errorf("receipt is unsigned")
	}
	k := st.KeyFor(r.Sig.KeyID, record.RoleService, issuer.Tenant)
	if k == nil || k.Role != record.RoleService || k.Tenant != r.Tenant || (k.Status != KeyActive && k.Status != KeyRetired) {
		return fmt.Errorf("receipt signer is not a valid service key of tenant %q", r.Tenant)
	}
	if !record.IsHex64(r.ID) || !record.IsHex64(r.Policy) || r.AcceptedAt <= 0 || r.HSeq <= 0 || !record.IsUUID(r.DeviceID) {
		return fmt.Errorf("receipt id malformed")
	}
	msg, err := ReceiptMessage(r)
	if err != nil {
		return err
	}
	return Verify(k.Pub, CtxReceipt, msg, *r.Sig)
}

// KeyOpResult is the outcome of VerifyKeyOp.
type KeyOpResult struct {
	Status OpStatus
	Err    error
}

// VerifyKeyOp adds a key operation to the keyring and reports its status in
// the folded state: invalid when its shape or possession signature
// fails (it is then not stored), held while parents are missing or while a
// second genesis awaits confirmation, unauthorized when its authorizer is
// not active in the state of its own history, authorized otherwise.
func VerifyKeyOp(kr *Keyring, op *KeyOp) KeyOpResult {
	if err := kr.Add(op); err != nil {
		return KeyOpResult{Status: OpInvalid, Err: err}
	}
	return KeyOpResult{Status: kr.State().Status[op.Rec.ID]}
}

// beforeCutoff uses only authenticated times in the receipt issuer's domain.
// Missing receipts for ANY independent revocation cause fail closed.
func beforeCutoff(k *Key, r record.Receipt, st *State) bool {
	if len(k.RevocationCauses) == 0 {
		return false
	}
	var cutoff int64
	for _, id := range k.RevocationCauses {
		op := st.Ops[id]
		if op == nil || op.Receipt == nil {
			return false
		}
		rc := *op.Receipt
		if rc.ID != id || rc.Tenant != r.Tenant || op.ReceiptIssuer.Tenant != r.Tenant || VerifyReceipt(rc, st, op.ReceiptIssuer) != nil {
			return false
		}
		if cutoff == 0 || rc.AcceptedAt < cutoff {
			cutoff = rc.AcceptedAt
		}
	}
	return r.AcceptedAt < cutoff
}
