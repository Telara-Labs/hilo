package sync

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

type SignedRecord struct {
	Record *record.Record
	Sigs   []record.Signature
}
type request struct {
	OpID      string            `json:"op_id"`
	Envelopes []record.Envelope `json:"envelopes"`
}

// Operation owns its immutable wire bytes. It never owns a database transaction.
// Authorize must still check signatures, causal key authority and disclosure on
// every send. Preparing an operation is not permission to transmit it.
type Operation struct {
	raw        []byte
	digest, id string
	records    []*record.Record
}

func (o *Operation) Bytes() []byte  { return append([]byte(nil), o.raw...) }
func (o *Operation) Digest() string { return o.digest }
func (o *Operation) OpID() string   { return o.id }

// NewOperation accepts already sealed metadata variants and permitted device
// controls. It never converts arbitrary source text to an export variant.
func NewOperation(opID string, records []SignedRecord) (*Operation, error) {
	if !validOpID(opID) || len(records) < 1 || len(records) > MaxRecords {
		return nil, ErrInvalid
	}
	req := request{OpID: opID}
	total := 0
	seen := map[string]bool{}
	for _, s := range records {
		if s.Record == nil {
			return nil, ErrInvalid
		}
		r, err := record.Parse(s.Record.HeaderJCS, s.Record.BodyJCS, s.Record.ID)
		if err != nil || len(r.BodyJCS) == 0 {
			return nil, ErrInvalid
		}
		if !allowed(r) || seen[r.ID] || len(s.Sigs) < 1 || len(s.Sigs) > 2 || r.Header.Type != record.KindKeyOp && len(s.Sigs) != 1 {
			return nil, ErrInvalid
		}
		for _, signature := range s.Sigs {
			raw, e := decode64(signature.Value, 64)
			if e != nil || len(raw) != 64 || signature.Alg != sig.AlgEd25519 || signature.Ctx != sig.CtxRecord || !record.IsKeyID(signature.KeyID) {
				return nil, ErrInvalid
			}
		}
		seen[r.ID] = true
		total += len(r.HeaderJCS) + len(r.BodyJCS)
		if total > MaxRequestBytes {
			return nil, ErrInvalid
		}
		req.Envelopes = append(req.Envelopes, record.Envelope{V: record.Version, ID: r.ID, Header: b64.EncodeToString(r.HeaderJCS), Sigs: append([]record.Signature(nil), s.Sigs...), Body: &record.EnvelopeBody{Codec: "zstd", Bytes: b64.EncodeToString(rawZstd(r.BodyJCS))}})
	}
	raw, err := json.Marshal(req)
	if err != nil || len(raw) > MaxRequestBytes {
		return nil, ErrInvalid
	}
	return restore(raw, "", false)
}

// RestoreOperation verifies a persisted operation against its separately stored
// digest. Altered bytes cannot silently reuse the old op_id after restart. Only
// the bounded raw-block Zstandard encoding emitted by this package is accepted.
func RestoreOperation(raw []byte, digest string) (*Operation, error) {
	return restore(raw, digest, true)
}
func restore(raw []byte, digest string, check bool) (*Operation, error) {
	if len(raw) == 0 || len(raw) > MaxRequestBytes {
		return nil, ErrInvalid
	}
	h := sha256.Sum256(raw)
	actual := hex.EncodeToString(h[:])
	if check && digest != actual {
		return nil, ErrInvalid
	}
	var req request
	if strictJSON(raw, &req) != nil || !validOpID(req.OpID) || len(req.Envelopes) < 1 || len(req.Envelopes) > MaxRecords {
		return nil, ErrInvalid
	}
	o := &Operation{raw: append([]byte(nil), raw...), digest: actual, id: req.OpID}
	total := 0
	seen := map[string]bool{}
	for _, e := range req.Envelopes {
		if e.V != record.Version || e.Receipt != nil || e.Grant != nil || e.Body == nil || e.Body.Codec != "zstd" || len(e.Sigs) < 1 || len(e.Sigs) > 2 {
			return nil, ErrInvalid
		}
		header, err := decode64(e.Header, record.MaxHeaderBytes)
		if err != nil {
			return nil, ErrInvalid
		}
		compressed, err := decode64(e.Body.Bytes, record.MaxBodyBytes+65536)
		if err != nil {
			return nil, ErrInvalid
		}
		body, err := readRawZstd(compressed)
		if err != nil {
			return nil, ErrInvalid
		}
		total += len(header) + len(body)
		if total > MaxRequestBytes {
			return nil, ErrInvalid
		}
		r, err := record.Parse(header, body, e.ID)
		if err != nil || !allowed(r) || seen[e.ID] {
			return nil, ErrInvalid
		}
		if r.Header.Type != record.KindKeyOp && len(e.Sigs) != 1 {
			return nil, ErrInvalid
		}
		for _, s := range e.Sigs {
			v, err := decode64(s.Value, 64)
			if err != nil || len(v) != 64 || s.Alg != sig.AlgEd25519 || s.Ctx != sig.CtxRecord || !record.IsKeyID(s.KeyID) {
				return nil, ErrInvalid
			}
		}
		seen[e.ID] = true
		o.records = append(o.records, r)
	}
	return o, nil
}
func validOpID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}
func allowed(r *record.Record) bool {
	h := r.Header
	switch h.Type {
	case record.KindSession, record.KindTask:
		return h.Red.Profile == record.ProfilePushMetadata && h.Prov == record.ProvDerived
	case record.KindRetraction, record.KindErasure, record.KindKeyOp:
		typed, err := jcs.MarshalRecord(r.Body)
		if err != nil || !bytes.Equal(typed, r.BodyJCS) {
			return false
		}
		if h.Type == record.KindKeyOp && (!h.Subj.IsZero() || !h.Links.IsZero() || h.Op != "") {
			return false
		}
		return h.Red.Profile == record.ProfileLocal
	}
	return false
}

func strictJSON(raw []byte, out any) error {
	// The shared canonicalizer rejects duplicate members, invalid UTF-8, excessive
	// nesting and unsafe numeric values before the typed decoder sees them.
	if _, err := jcs.CanonicalizeRecord(raw); err != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}

// rawZstd emits RFC 8878 single-segment frames with a 32-bit content size and
// raw blocks only. No dictionary, compression dependency or decompressor is
// needed to transport canonical bodies. The hosted general zstd decoder accepts
// these frames. The restricted restart decoder rejects every other encoding.
func rawZstd(body []byte) []byte {
	out := []byte{0x28, 0xb5, 0x2f, 0xfd, 0xa0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(out[5:], uint32(len(body)))
	for len(body) > 0 {
		n := min(len(body), 128<<10)
		last := uint32(0)
		if n == len(body) {
			last = 1
		}
		v := uint32(n)<<3 | last
		out = append(out, byte(v), byte(v>>8), byte(v>>16))
		out = append(out, body[:n]...)
		body = body[n:]
	}
	return out
}
func readRawZstd(raw []byte) ([]byte, error) {
	if len(raw) < 12 || !bytes.Equal(raw[:5], []byte{0x28, 0xb5, 0x2f, 0xfd, 0xa0}) {
		return nil, ErrInvalid
	}
	size := int(binary.LittleEndian.Uint32(raw[5:9]))
	if size < 1 || size > record.MaxBodyBytes {
		return nil, ErrInvalid
	}
	raw = raw[9:]
	out := make([]byte, 0, size)
	for {
		if len(raw) < 3 {
			return nil, ErrInvalid
		}
		v := uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16
		raw = raw[3:]
		n := int(v >> 3)
		if v&6 != 0 || n < 1 || n > 128<<10 || n > len(raw) || n > size-len(out) {
			return nil, ErrInvalid
		}
		out = append(out, raw[:n]...)
		raw = raw[n:]
		if v&1 != 0 {
			if len(raw) != 0 || len(out) != size {
				return nil, ErrInvalid
			}
			return out, nil
		}
	}
}
