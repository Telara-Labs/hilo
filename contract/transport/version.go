package transport

import (
	"encoding/base64"
	"errors"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// CheckEnvelope gates transport and signed header versions independently. The
// adapter supplies exactly the bounded decompressed bytes of body.bytes; this
// helper never decompresses, authenticates a route or verifies record signatures.
func CheckEnvelope(e record.Envelope, decodedBody []byte) (*record.Record, error) {
	if e.V != record.Version {
		return nil, errors.New("unsupported envelope version")
	}
	if !record.IsHex64(e.ID) || len(e.Header) > base64.RawURLEncoding.EncodedLen(record.MaxHeaderBytes) {
		return nil, errors.New("invalid or oversized envelope header")
	}
	header, err := base64.RawURLEncoding.Strict().DecodeString(e.Header)
	if err != nil || base64.RawURLEncoding.EncodeToString(header) != e.Header {
		return nil, errors.New("invalid envelope header encoding")
	}
	if e.Body == nil && decodedBody != nil || e.Body != nil && (e.Body.Codec != "zstd" || decodedBody == nil) {
		return nil, errors.New("envelope body mismatch")
	}
	return record.Parse(header, decodedBody, e.ID)
}
func CheckHello(h Hello, r HelloReply) error {
	if h.Contract != record.ContractVersion || r.ContractMin != record.ContractVersion {
		return errors.New("upgrade_required")
	}
	if !record.IsUUID(h.DeviceID) || h.CtlCursor < 0 || h.DataCursor < 0 || h.OutboxDepth < 0 || r.CtlHead < h.CtlCursor || r.DataHead < h.DataCursor || r.ServerTime <= 0 {
		return errors.New("invalid hello state")
	}
	return nil
}
func CheckManifestVersion(m Manifest) error {
	if m.Bundle != "mnc/3" {
		return errors.New("unsupported bundle version")
	}
	return nil
}
