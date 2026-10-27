// Package sig is signing and verification for the memory node contract:
// the domain-separated signed bytes, Ed25519 signatures, the keyring
// of key operations and its deterministic key state, validity across
// rotation and revocation, receipts and the two admission
// verifiers VerifyRecord and VerifyKeyOp.
package sig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
)

// Signature contexts.
const (
	CtxRecord  = "mnc/v1/record"
	CtxBundle  = "mnc/v1/bundle"
	CtxReceipt = "mnc/v1/receipt"
	CtxGrant   = "mnc/v1/grant"
)

// AlgEd25519 is the only signature algorithm of v1.
const AlgEd25519 = "ed25519"

var b64 = base64.RawURLEncoding.Strict()

// decodeCanonical decodes base64url without padding and accepts only the one
// canonical spelling. The standard decoder skips CR and LF even in strict mode,
// so a decoded value must re-encode to exactly the input.
func decodeCanonical(s string) ([]byte, bool) {
	b, err := b64.DecodeString(s)
	if err != nil || b64.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

// KeyID returns hex(sha256(raw32 pub))[:32].
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:32]
}

// EncodePub renders a public key as base64url without padding.
func EncodePub(pub ed25519.PublicKey) string { return b64.EncodeToString(pub) }

// DecodePub parses a base64url public key of exactly 32 bytes.
func DecodePub(s string) (ed25519.PublicKey, error) {
	b, ok := decodeCanonical(s)
	if !ok || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be 32 bytes of base64url without padding")
	}
	return ed25519.PublicKey(b), nil
}

func message(ctx string, digest []byte) []byte {
	m := make([]byte, 0, len(ctx)+1+len(digest))
	m = append(m, ctx...)
	m = append(m, 0)
	return append(m, digest...)
}

// RecordMessage returns "mnc/v1/record" || 0x00 || raw32(id).
func RecordMessage(id string) ([]byte, error) {
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != 32 || !record.IsHex64(id) {
		return nil, fmt.Errorf("record id must be 64 lowercase hex")
	}
	return message(CtxRecord, raw), nil
}

// BundleMessage returns "mnc/v1/bundle" || 0x00 || raw32(sha256(manifest_jcs_without_sigs)).
func BundleMessage(manifestJCSWithoutSigs []byte) []byte {
	sum := sha256.Sum256(manifestJCSWithoutSigs)
	return message(CtxBundle, sum[:])
}

// ReceiptMessage returns "mnc/v1/receipt" || 0x00 || raw32(sha256(receipt_jcs_without_sig)).
func ReceiptMessage(r record.Receipt) ([]byte, error) {
	r.Sig = nil
	b, err := jcs.MarshalRecord(&r)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return message(CtxReceipt, sum[:]), nil
}

// Sign signs msg under ctx and returns the signature record.
func Sign(priv ed25519.PrivateKey, ctx string, msg []byte) record.Signature {
	return record.Signature{
		Alg:   AlgEd25519,
		KeyID: KeyID(priv.Public().(ed25519.PublicKey)),
		Ctx:   ctx,
		Value: b64.EncodeToString(ed25519.Sign(priv, msg)),
	}
}

// SignRecord signs a record id.
func SignRecord(priv ed25519.PrivateKey, id string) (record.Signature, error) {
	m, err := RecordMessage(id)
	if err != nil {
		return record.Signature{}, err
	}
	return Sign(priv, CtxRecord, m), nil
}

// SignReceipt signs a receipt and returns it with Sig set.
func SignReceipt(priv ed25519.PrivateKey, r record.Receipt) (record.Receipt, error) {
	m, err := ReceiptMessage(r)
	if err != nil {
		return r, err
	}
	s := Sign(priv, CtxReceipt, m)
	r.Sig = &s
	return r, nil
}

// Errors returned by Verify.
var (
	ErrAlg       = errors.New("signature algorithm is not ed25519")
	ErrCtx       = errors.New("signature context is wrong for this message")
	ErrKeyID     = errors.New("signature key id does not match the key")
	ErrEncoding  = errors.New("signature value is not 64 bytes of base64url without padding")
	ErrSignature = errors.New("signature does not verify")
)

// Verify checks one signature over msg under pub with the expected context.
// It rejects any encoding other than the canonical one; Go's Ed25519
// verifier rejects non-canonical S values, so a malleated signature fails.
func Verify(pub ed25519.PublicKey, ctx string, msg []byte, s record.Signature) error {
	if s.Alg != AlgEd25519 {
		return ErrAlg
	}
	if s.Ctx != ctx {
		return ErrCtx
	}
	if s.KeyID != KeyID(pub) {
		return ErrKeyID
	}
	v, ok := decodeCanonical(s.Value)
	if !ok || len(v) != ed25519.SignatureSize {
		return ErrEncoding
	}
	if !ed25519.Verify(pub, msg, v) {
		return ErrSignature
	}
	return nil
}

// GrantMessage is context-separated independently of acceptance receipts.
func GrantMessage(g record.DeliveryGrant) ([]byte, error) {
	g.Sig = nil
	b, err := jcs.MarshalRecord(g)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return message(CtxGrant, sum[:]), nil
}
func SignGrant(priv ed25519.PrivateKey, g record.DeliveryGrant) (record.DeliveryGrant, error) {
	msg, err := GrantMessage(g)
	if err != nil {
		return g, err
	}
	s := Sign(priv, CtxGrant, msg)
	g.Sig = &s
	return g, nil
}

// VerifyGrant binds delivery to this exact record, pinned recipient and policy generation.
func VerifyGrant(g record.DeliveryGrant, st *State, recordID string, issuer TrustedIssuer, genesis, policyID string, policySeq, withdrawnThrough int64) error {
	tenant := issuer.Tenant
	if !issuer.ValidFor(record.RoleService) || st == nil || g.Sig == nil || g.RecordID != recordID || !record.IsHex64(recordID) || g.Tenant != tenant || g.RecipientGenesis != genesis || !record.IsKeyID(genesis) || g.Policy != policyID || !record.IsHex64(policyID) || g.Generation <= 0 || g.Generation != policySeq || g.Generation <= withdrawnThrough {
		return fmt.Errorf("grant: identity, policy or generation mismatch")
	}
	key := st.KeyFor(g.Sig.KeyID, record.RoleService, tenant)
	if key == nil || key.Role != record.RoleService || key.Tenant != tenant || (key.Status != KeyActive && key.Status != KeyRetired) {
		return fmt.Errorf("grant: untrusted service authority")
	}
	msg, err := GrantMessage(g)
	if err != nil {
		return err
	}
	return Verify(key.Pub, CtxGrant, msg, *g.Sig)
}
