package record

import (
	"fmt"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
)

// Build assembles a record from a header and a typed body (a pointer to one
// of the body types). For a salted kind it computes the salt from saltKey
// over the body without its salt (R1.4) and stores it in the body. It fills
// header.V and header.Body, canonicalizes both parts, and runs Parse on the
// result, so whatever Build returns is admissible apart from its signature.
//
// Build does not redact, bound or sign. It is the last step a sealing
// pipeline runs before signing.
func Build(h Header, body any, saltKey []byte) (*Record, error) {
	if body == nil {
		return nil, fmt.Errorf("build: a body is required")
	}
	if chunk, ok := body.(*ChunkBody); ok {
		for i, e := range chunk.Events {
			if e.Revision == "" {
				v, err := ReviseEvent(e, e.Replaces, saltKey)
				if err != nil {
					return nil, err
				}
				chunk.Events[i] = v
			}
		}
	}
	if salted(h.Type) {
		if !setSalt(body, "") {
			return nil, fmt.Errorf("build: %T is not a salted body", body)
		}
		bare, err := jcs.MarshalRecord(body)
		if err != nil {
			return nil, fmt.Errorf("build: %w", err)
		}
		salt, err := Salt(saltKey, h.Type, h.LID, bare)
		if err != nil {
			return nil, err
		}
		setSalt(body, salt)
	}
	bodyJCS, err := jcs.MarshalRecord(body)
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	h.V = Version
	h.Body = &BodyRef{Digest: BodyDigest(bodyJCS), Size: int64(len(bodyJCS))}
	headerJCS, err := jcs.MarshalRecord(&h)
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	return Parse(headerJCS, bodyJCS, "")
}

// WithoutBody returns a copy of r whose body bytes are absent, as after a
// body purge. The id is unchanged because it covers the body only through
// header.body.digest.
func (r *Record) WithoutBody() *Record {
	c := *r
	c.BodyJCS = nil
	c.Body = nil
	return &c
}
