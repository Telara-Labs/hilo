package releaseauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
)

// These are compiled verification authorities, never release/download/config
// inputs. A future key transition requires separately reviewed real inventory.
// The active signing pin remains release-key.pub and is NOT changed here.
type historicalManifest struct{ Build, Sums string }
type historicalAuthority struct {
	Public    ed25519.PublicKey
	Manifests []historicalManifest
}
type verificationPolicy struct {
	active  ed25519.PublicKey
	history []historicalAuthority
}

func policyDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

func newVerificationPolicy(active ed25519.PublicKey, history []historicalAuthority) (verificationPolicy, error) {
	if len(active) != ed25519.PublicKeySize || len(history) > 4 {
		return verificationPolicy{}, ErrInvalid
	}
	p := verificationPolicy{active: append(ed25519.PublicKey(nil), active...)}
	keys := map[string]bool{string(active): true}
	pairs := map[historicalManifest]bool{}
	total := 0
	for _, authority := range history {
		if len(authority.Public) != ed25519.PublicKeySize || keys[string(authority.Public)] || len(authority.Manifests) == 0 || len(authority.Manifests) > 256 || total > 512-len(authority.Manifests) {
			return verificationPolicy{}, ErrInvalid
		}
		keys[string(authority.Public)] = true
		total += len(authority.Manifests)
		copy := historicalAuthority{Public: append(ed25519.PublicKey(nil), authority.Public...)}
		for _, pair := range authority.Manifests {
			if !policyDigest(pair.Build) || !policyDigest(pair.Sums) || pairs[pair] {
				return verificationPolicy{}, ErrInvalid
			}
			pairs[pair] = true
			copy.Manifests = append(copy.Manifests, pair)
		}
		p.history = append(p.history, copy)
	}
	return p, nil
}

// This proposal introduces no new authority. Populating history or changing the
// active public file requires a separate approved pin/bootstrap transition.
func compiledVerificationPolicy() (verificationPolicy, error) {
	active, err := PublicKey()
	if err != nil {
		return verificationPolicy{}, ErrInvalid
	}
	return newVerificationPolicy(active, nil)
}

func (p verificationPolicy) verify(build, sums, signature []byte) error {
	if len(p.active) != ed25519.PublicKeySize || len(build) == 0 || len(build) > 16384 || len(sums) == 0 || len(sums) > 4096 || len(signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	message := payload(build, sums)
	if ed25519.Verify(p.active, message, signature) {
		return nil
	}
	bh, sh := sha256.Sum256(build), sha256.Sum256(sums)
	pair := historicalManifest{Build: hex.EncodeToString(bh[:]), Sums: hex.EncodeToString(sh[:])}
	for _, authority := range p.history {
		for _, allowed := range authority.Manifests {
			if allowed == pair && ed25519.Verify(authority.Public, message, signature) {
				return nil
			}
		}
	}
	return ErrInvalid
}

func verifyReleaseSignature(build, sums, signature []byte, explicit ed25519.PublicKey) error {
	if explicit != nil {
		if len(explicit) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(explicit, payload(build, sums), signature) {
			return ErrInvalid
		}
		return nil
	}
	p, err := compiledVerificationPolicy()
	if err != nil {
		return ErrInvalid
	}
	return p.verify(build, sums, signature)
}
