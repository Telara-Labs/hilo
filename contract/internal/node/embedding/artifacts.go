package embedding

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
)

const maxModelBytes int64 = 128 << 20
const maxTokenizerBytes int64 = 16 << 20

// ArtifactExpectation must come from an independently authenticated release
// manifest. This type does not authenticate a manifest or select a model.
type ArtifactExpectation struct {
	ModelID, ModelSHA256, TokenizerSHA256 string
}

// VerifiedArtifacts owns the exact bytes that were checked. It does not prove
// model format, runtime safety, license, policy or erasure properties.
type VerifiedArtifacts struct {
	identity         ArtifactExpectation
	model, tokenizer []byte
}

func (v *VerifiedArtifacts) Identity() ArtifactExpectation { return v.identity }
func (v *VerifiedArtifacts) ModelBytes() []byte            { return bytes.Clone(v.model) }
func (v *VerifiedArtifacts) TokenizerBytes() []byte        { return bytes.Clone(v.tokenizer) }

// VerifyArtifacts makes bounded snapshots from explicitly provided readers and
// verifies both digests before returning either. It never opens paths or makes
// network requests. The caller owns source authentication, cancellation, and
// release-manifest verification; a digest from an untrusted source is not trust.
func VerifyArtifacts(expected ArtifactExpectation, model, tokenizer io.Reader) (*VerifiedArtifacts, error) {
	if !validModelID(expected.ModelID) || model == nil || tokenizer == nil {
		return nil, fmt.Errorf("invalid artifact input")
	}
	modelDigest, err := parseDigest(expected.ModelSHA256)
	if err != nil {
		return nil, err
	}
	tokenDigest, err := parseDigest(expected.TokenizerSHA256)
	if err != nil {
		return nil, err
	}
	weights, err := readArtifact(model, modelDigest, maxModelBytes)
	if err != nil {
		return nil, fmt.Errorf("model artifact: %w", err)
	}
	tokens, err := readArtifact(tokenizer, tokenDigest, maxTokenizerBytes)
	if err != nil {
		return nil, fmt.Errorf("tokenizer artifact: %w", err)
	}
	return &VerifiedArtifacts{identity: expected, model: weights, tokenizer: tokens}, nil
}
func validModelID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
func parseDigest(s string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	if len(s) != sha256.Size*2 {
		return out, fmt.Errorf("invalid sha256")
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return out, fmt.Errorf("invalid sha256")
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("invalid sha256")
	}
	copy(out[:], b)
	return out, nil
}
func readArtifact(src io.Reader, expected [sha256.Size]byte, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(src, limit+1))
	if err != nil {
		return nil, fmt.Errorf("unreadable")
	}
	if len(data) == 0 || int64(len(data)) > limit {
		return nil, fmt.Errorf("empty or oversized")
	}
	got := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(got[:], expected[:]) != 1 {
		return nil, fmt.Errorf("digest mismatch")
	}
	return data, nil
}
