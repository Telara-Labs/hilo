package sig

import (
	"fmt"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// SigStatus is a record's signature status (§4.6).
type SigStatus string

const (
	StatusVerified      SigStatus = "verified"
	StatusSignerRevoked SigStatus = "signer-revoked"
	StatusUnsignedLocal SigStatus = "unsigned-local" // own record awaiting the key store; never pushed
	StatusUnknownSigner SigStatus = "unknown-signer" // quarantined; retry after keyring sync, expire after 7 days
	StatusInvalid       SigStatus = "invalid"        // quarantined; never indexed, never rendered
	StatusIgnored       SigStatus = "ignored"        // control kind over an unauthenticated route
)

// Quarantined reports statuses that keep the full envelope out of every
// projection.
func (s SigStatus) Quarantined() bool { return s == StatusUnknownSigner || s == StatusInvalid }

// Context carries receiver-side facts VerifyRecord needs. None of it is part
// of the record.
type Context struct {
	Route       record.Route
	AdmittedSeq int64           // this node's admission order of the record
	Receipt     *record.Receipt // hosted acceptance, if carried
}

// Result is the outcome of VerifyRecord.
type Result struct {
	Status SigStatus
	Key    *Key   // the signing key when known
	Owner  string // owner namespace of the signer (§1.3)
	Reason string // why the status is not verified
}

func fail(s SigStatus, format string, a ...any) Result {
	return Result{Status: s, Reason: fmt.Sprintf(format, a...)}
}

// VerifyRecord verifies a record of any kind except key_op against the
// folded keyring (§4.6). It checks, in order: the signature list shape, the
// signer is in the keyring, the Ed25519 signature, the signer and
// provenance matrix (§2.1), the device machine binding, the owner-scoped
// LID, and validity across rotation and revocation (§4.4). Retired keys
// verify (R4.1). A record that fails is quarantined, never indexed.
func VerifyRecord(r *record.Record, sigs []record.Signature, st *State, c Context) Result {
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
	k := st.Key(s.KeyID)
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

// PreRevocation applies §4.4 row 3: a record signed by a revoked key stays
// verified if it carries a valid TSK receipt accepted before the revocation,
// or if this node admitted it before it admitted the revocation.
func PreRevocation(k *Key, c Context, st *State) bool {
	if c.AdmittedSeq > 0 && k.RevokedSeq > 0 && c.AdmittedSeq < k.RevokedSeq {
		return true
	}
	if c.Receipt != nil && VerifyReceipt(*c.Receipt, st) == nil && c.Receipt.AcceptedAt < k.RevokedAt {
		return true
	}
	return false
}

// VerifyReceipt checks a receipt's signature by an active or retired service
// key of the receipt's tenant.
func VerifyReceipt(r record.Receipt, st *State) error {
	if r.Sig == nil {
		return fmt.Errorf("receipt is unsigned")
	}
	k := st.Key(r.Sig.KeyID)
	if k == nil || k.Role != record.RoleService || k.Tenant != r.Tenant || k.Status == KeyRevoked {
		return fmt.Errorf("receipt signer is not a valid service key of tenant %q", r.Tenant)
	}
	if !record.IsHex64(r.ID) {
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
// the folded state (§4.6): invalid when its shape or possession signature
// fails (it is then not stored), held while parents are missing or while a
// second genesis awaits confirmation, unauthorized when its authorizer is
// not active in the state of its own history, authorized otherwise.
func VerifyKeyOp(kr *Keyring, op *KeyOp) KeyOpResult {
	if err := kr.Add(op); err != nil {
		return KeyOpResult{Status: OpInvalid, Err: err}
	}
	return KeyOpResult{Status: kr.State().Status[op.Rec.ID]}
}
