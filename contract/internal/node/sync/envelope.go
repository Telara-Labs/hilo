package sync

import (
	"encoding/base64"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/transport"
)

// RawZstd frames b as one raw-block zstd frame, the transport encoding used
// for envelope bodies and encrypted bundles.
func RawZstd(b []byte) []byte { return rawZstd(b) }

// ReadRawZstd decodes only raw-block frames, refusing a declared content size
// above limit before any allocation.
func ReadRawZstd(raw []byte, limit int) ([]byte, error) { return readRawZstdLimit(raw, limit) }

// Envelope returns the transport envelope of one exact signed record. A record
// without a body has no body member.
func Envelope(headerJCS, bodyJCS []byte, sigs []record.Signature, id string) record.Envelope {
	e := record.Envelope{V: record.Version, ID: id, Header: base64.RawURLEncoding.EncodeToString(headerJCS), Sigs: append([]record.Signature(nil), sigs...)}
	if bodyJCS != nil {
		e.Body = &record.EnvelopeBody{Codec: "zstd", Bytes: base64.RawURLEncoding.EncodeToString(rawZstd(bodyJCS))}
	}
	return e
}

// OpenEnvelope bounds and decodes an envelope body, then checks the transport
// and signed header versions independently. Signatures are not verified here.
func OpenEnvelope(e record.Envelope) (*record.Record, error) {
	var body []byte
	if e.Body != nil {
		if e.Body.Codec != "zstd" || len(e.Body.Bytes) > base64.RawURLEncoding.EncodedLen(record.MaxBodyBytes+9+3*(record.MaxBodyBytes/(128<<10)+1)) {
			return nil, ErrInvalid
		}
		compressed, err := base64.RawURLEncoding.Strict().DecodeString(e.Body.Bytes)
		if err != nil || base64.RawURLEncoding.EncodeToString(compressed) != e.Body.Bytes {
			return nil, ErrInvalid
		}
		if body, err = readRawZstd(compressed); err != nil {
			return nil, ErrInvalid
		}
	}
	r, err := transport.CheckEnvelope(e, body)
	if err != nil {
		return nil, ErrInvalid
	}
	return r, nil
}
