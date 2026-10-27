package releaseauth

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type recordingSigner struct {
	key         ed25519.PrivateKey
	public      crypto.PublicKey
	message     []byte
	opts        crypto.SignerOpts
	failure     bool
	corrupt     bool
	panicPublic bool
	panicSign   bool
}

func (s *recordingSigner) Public() crypto.PublicKey {
	if s.panicPublic {
		panic("provider public panic")
	}
	return s.public
}
func (s *recordingSigner) Sign(r io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.panicSign {
		panic("provider sign panic")
	}
	s.message = append([]byte(nil), message...)
	s.opts = opts
	if s.failure {
		return nil, errors.New("signing unavailable")
	}
	sig, err := s.key.Sign(r, message, opts)
	if s.corrupt {
		sig[0] ^= 1
	}
	return sig, err
}

func TestSignerReceivesExactRawPayloadForBothFamilies(t *testing.T) {
	for _, prefix := range []string{legacyArtifactPrefix, hiloArtifactPrefix} {
		t.Run(prefix, func(t *testing.T) {
			dir, key := fixtureWithFamily(t, prefix)
			s := &recordingSigner{key: key, public: key.Public()}
			if err := signWithSigner(dir, s, key.Public().(ed25519.PublicKey)); err != nil {
				t.Fatal(err)
			}
			build, err := os.ReadFile(filepath.Join(dir, "BUILD.json"))
			if err != nil {
				t.Fatal(err)
			}
			sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
			if err != nil {
				t.Fatal(err)
			}
			if s.opts == nil || s.opts.HashFunc() != crypto.Hash(0) || !bytes.Equal(s.message, payload(build, sums)) {
				t.Fatal("signer did not receive exact raw release payload")
			}
			if _, err := verify(dir, key.Public().(ed25519.PublicKey)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSignerRefusesMismatchErrorsAndInvalidSignatureBeforeWriting(t *testing.T) {
	for _, kind := range []string{"wrong-key", "wrong-type", "error", "bad-signature", "panic-public", "panic-sign"} {
		t.Run(kind, func(t *testing.T) {
			dir, key := fixture(t)
			before, err := os.ReadFile(filepath.Join(dir, "BUILD.json"))
			if err != nil {
				t.Fatal(err)
			}
			s := &recordingSigner{key: key, public: key.Public()}
			switch kind {
			case "wrong-key":
				_, other := fixture(t)
				s.public = other.Public()
			case "wrong-type":
				s.public = "not an Ed25519 key"
			case "error":
				s.failure = true
			case "bad-signature":
				s.corrupt = true
			case "panic-public":
				s.panicPublic = true
			case "panic-sign":
				s.panicSign = true
			}
			if err := signWithSigner(dir, s, key.Public().(ed25519.PublicKey)); err == nil {
				t.Fatal("invalid signer accepted")
			}
			after, err := os.ReadFile(filepath.Join(dir, "BUILD.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed signer changed build manifest")
			}
			if _, err := os.Lstat(filepath.Join(dir, "RELEASE.sig")); !os.IsNotExist(err) {
				t.Fatal("failed signer wrote signature")
			}
			if (kind == "wrong-key" || kind == "wrong-type") && s.message != nil {
				t.Fatal("untrusted signer was called")
			}
		})
	}
}

func TestSignerPublicPinAndNilRefused(t *testing.T) {
	dir, key := fixture(t)
	if err := SignWithSigner(dir, &recordingSigner{key: key, public: key.Public()}); err == nil {
		t.Fatal("unrelated key accepted against project pin")
	}
	if err := SignWithSigner(dir, nil); err == nil {
		t.Fatal("nil signer accepted")
	}
}

func TestTypedNilSignerRefused(t *testing.T) {
	dir, key := fixture(t)
	var signer *recordingSigner
	if err := signWithSigner(dir, signer, key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("typed nil signer accepted")
	}
}
