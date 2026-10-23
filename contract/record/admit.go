package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
)

// Rejection codes. Hosted maps them to its wire errors.
const (
	CodeTooLarge           = "too_large"
	CodeNotCanonical       = "not_canonical"
	CodeUnsupportedVersion = "unsupported_version" // quarantine the full envelope
	CodeUnknownKind        = "unknown_kind"        // quarantine; the transport class decides data vs control
	CodeUnknownField       = "unknown_field"
	CodeIDMismatch         = "id_mismatch"
	CodeBodyMismatch       = "body_mismatch"
	CodeInvalidHeader      = "invalid_header"
	CodeInvalidBody        = "invalid_body"
	CodeLIDMismatch        = "lid_mismatch"
	CodeProfileNotAllowed  = "profile_not_allowed"
	CodeProvNotAllowed     = "prov_not_allowed"
	CodeListTooLong        = "list_too_long"
)

// Error is an admission rejection.
type Error struct {
	Code string
	Msg  string
	// Quarantine is true when the receiver keeps the full envelope instead of
	// dropping it (a higher contract version or an unknown kind).
	Quarantine bool
}

func (e *Error) Error() string { return "record: " + e.Code + ": " + e.Msg }

func rej(code, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// CodeOf returns the rejection code of err, or "" when err is not an *Error.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Record is an admitted record: its canonical bytes and decoded forms.
type Record struct {
	ID        string
	HeaderJCS []byte
	Header    Header
	BodyJCS   []byte // nil when the body is absent (header-only or purged)
	Body      any    // pointer to the typed body; nil when absent
}

// Parse runs the record-level admission steps in order: (1) size,
// (2) canonical header bytes, the version gate, (3) id, (4) body digest and
// size, (5) header decoded from header_jcs alone, and (8) type rules.
// Signatures (6) are checked by package sig and tombstones (7) by the
// store. wantID, when non-empty, is the sender's advisory id; a mismatch is
// rejected. bodyJCS may be nil for a record whose body is absent.
func Parse(headerJCS, bodyJCS []byte, wantID string) (*Record, error) {
	// (1) sizes
	if len(headerJCS) > MaxHeaderBytes {
		return nil, rej(CodeTooLarge, "header is %d bytes, limit %d", len(headerJCS), MaxHeaderBytes)
	}
	if len(bodyJCS) > MaxBodyBytes {
		return nil, rej(CodeTooLarge, "body is %d bytes, limit %d", len(bodyJCS), MaxBodyBytes)
	}
	// (2) malleability: the bytes must already be canonical
	canon, err := jcs.CanonicalizeRecord(headerJCS)
	if err != nil {
		return nil, rej(CodeNotCanonical, "header: %v", err)
	}
	if !bytes.Equal(canon, headerJCS) {
		return nil, rej(CodeNotCanonical, "header bytes are not in canonical form")
	}
	var probe struct {
		V json.RawMessage `json:"v"`
	}
	if err := json.Unmarshal(headerJCS, &probe); err != nil {
		return nil, rej(CodeInvalidHeader, "header is not an object: %v", err)
	}
	var v int64
	if err := json.Unmarshal(probe.V, &v); err != nil || len(probe.V) == 0 {
		return nil, rej(CodeInvalidHeader, "header v is missing or not an integer")
	}
	if v > Version {
		return nil, &Error{Code: CodeUnsupportedVersion, Msg: fmt.Sprintf("header v %d", v), Quarantine: true}
	}
	if v != Version {
		return nil, rej(CodeInvalidHeader, "header v %d", v)
	}
	// (3) id
	id := ContentID(headerJCS)
	if wantID != "" && wantID != id {
		return nil, rej(CodeIDMismatch, "advisory id %s, computed %s", wantID, id)
	}
	// (5) decode the header from header_jcs only, rejecting unknown fields.
	var h Header
	dec := json.NewDecoder(bytes.NewReader(headerJCS))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return nil, rej(CodeUnknownField, "header: %v", err)
	}
	// Re-encoding must give the same bytes: no member name in another case,
	// no empty field written out.
	again, err := jcs.MarshalRecord(&h)
	if err != nil || !bytes.Equal(again, headerJCS) {
		return nil, rej(CodeNotCanonical, "header has fields that encode differently (case or empty values)")
	}
	if !h.Type.Known() {
		return nil, &Error{Code: CodeUnknownKind, Msg: fmt.Sprintf("kind %q", h.Type), Quarantine: true}
	}
	// (4) body digest and size
	if bodyJCS != nil {
		if h.Body == nil {
			return nil, rej(CodeBodyMismatch, "body present but the header has no body reference")
		}
		bc, err := jcs.CanonicalizeRecord(bodyJCS)
		if err != nil {
			return nil, rej(CodeNotCanonical, "body: %v", err)
		}
		if !bytes.Equal(bc, bodyJCS) {
			return nil, rej(CodeNotCanonical, "body bytes are not in canonical form")
		}
		if BodyDigest(bodyJCS) != h.Body.Digest || int64(len(bodyJCS)) != h.Body.Size {
			return nil, rej(CodeBodyMismatch, "body digest or size differs from the header")
		}
	}
	r := &Record{ID: id, HeaderJCS: headerJCS, Header: h, BodyJCS: bodyJCS}
	// (8) type rules
	if err := validateHeader(&h); err != nil {
		return nil, err
	}
	if bodyJCS != nil {
		b, err := decodeBody(&h, bodyJCS)
		if err != nil {
			return nil, err
		}
		if err := validateBody(&h, b); err != nil {
			return nil, err
		}
		r.Body = b
	}
	// Owner-scoped LIDs are checked again by the signature verifier, which
	// knows the signer's owner.
	if lid, ok := ExpectedLID(&h, r.Body, ""); ok && lid != h.LID {
		return nil, rej(CodeLIDMismatch, "lid %s, expected %s", h.LID, lid)
	}
	return r, nil
}

// strictBody reports body types that reject unknown fields: the v1 export
// allowlists and the policy document.
func strictBody(name string) bool {
	return name == "SessionMetaBody" || name == "TaskMetaBody" || name == "PolicyBody"
}

func decodeBody(h *Header, bodyJCS []byte) (any, error) {
	name := BodyTypeName(h.Type, h.Prov)
	b := newBody(name)
	if b == nil {
		return nil, rej(CodeProvNotAllowed, "no body type for %s with prov %s", h.Type, h.Prov)
	}
	dec := json.NewDecoder(bytes.NewReader(bodyJCS))
	if strictBody(name) {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(b); err != nil {
		if strictBody(name) {
			return nil, rej(CodeUnknownField, "%s: %v", name, err)
		}
		return nil, rej(CodeInvalidBody, "%s: %v", name, err)
	}
	// encoding/json matches member names case-insensitively. Every member the
	// typed body re-encodes must exist in the original bytes with the same
	// spelling, or an author could smuggle a field past a reader.
	again, err := json.Marshal(b)
	if err != nil {
		return nil, rej(CodeInvalidBody, "%s: %v", name, err)
	}
	var orig, typed any
	if json.Unmarshal(bodyJCS, &orig) != nil || json.Unmarshal(again, &typed) != nil {
		return nil, rej(CodeInvalidBody, "%s: not an object", name)
	}
	if err := sameSpelling(orig, typed, name); err != nil {
		return nil, err
	}
	if strictBody(name) {
		ac, err := jcs.CanonicalizeRecord(again)
		if err != nil || !bytes.Equal(ac, bodyJCS) {
			return nil, rej(CodeNotCanonical, "%s must match its allowlist byte for byte (no empty fields written)", name)
		}
	}
	return b, nil
}

func sameSpelling(orig, typed any, where string) error {
	switch t := typed.(type) {
	case map[string]any:
		o, ok := orig.(map[string]any)
		if !ok {
			return rej(CodeInvalidBody, "%s: object expected", where)
		}
		for k, tv := range t {
			ov, ok := o[k]
			if !ok {
				return rej(CodeInvalidBody, "%s: member %q is not spelled exactly", where, k)
			}
			if err := sameSpelling(ov, tv, where+"."+k); err != nil {
				return err
			}
		}
	case []any:
		o, ok := orig.([]any)
		if !ok || len(o) != len(t) {
			return rej(CodeInvalidBody, "%s: array mismatch", where)
		}
		for i := range t {
			if err := sameSpelling(o[i], t[i], where); err != nil {
				return err
			}
		}
	}
	return nil
}
