package sync

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

var b64 = base64.RawURLEncoding.Strict()

// PublicJWK contains only the RFC 7638 public P-256 key members.
type PublicJWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func jwk(k *ecdsa.PublicKey) (PublicJWK, error) {
	if k == nil || k.Curve != elliptic.P256() || k.X == nil || k.Y == nil || !k.Curve.IsOnCurve(k.X, k.Y) {
		return PublicJWK{}, ErrToken
	}
	return PublicJWK{"P-256", "EC", b64.EncodeToString(k.X.FillBytes(make([]byte, 32))), b64.EncodeToString(k.Y.FillBytes(make([]byte, 32)))}, nil
}
func thumbprint(k *ecdsa.PublicKey) (string, error) {
	j, err := jwk(k)
	if err != nil {
		return "", err
	}
	raw, _ := json.Marshal(j) // RFC 7638 members in lexicographic order.
	h := sha256.Sum256(raw)
	return b64.EncodeToString(h[:]), nil
}

// publicKey validates a keystore's public identity before signing or token use.
func (j PublicJWK) publicKey() (*ecdsa.PublicKey, error) {
	if j.Crv != "P-256" || j.Kty != "EC" {
		return nil, ErrToken
	}
	x, e := decode64(j.X, 32)
	y, e2 := decode64(j.Y, 32)
	if e != nil || e2 != nil || len(x) != 32 || len(y) != 32 {
		return nil, ErrToken
	}
	k := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if _, e = jwk(k); e != nil {
		return nil, e
	}
	return k, nil
}

func signProofJWT(ctx context.Context, key DPoPSigner, j PublicJWK, header, claims any) (string, error) {
	pub, err := j.publicKey()
	if err != nil {
		return "", err
	}
	h, err := json.Marshal(header)
	if err != nil {
		return "", ErrToken
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", ErrToken
	}
	s := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	d := sha256.Sum256([]byte(s))
	signature, err := key.Sign(ctx, d[:])
	if err != nil {
		return "", ErrKeystoreUnavailable
	}
	// Refuse malformed signatures and rotation between identity and signing.
	if len(signature) != 64 || !ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return "", ErrToken
	}
	return s + "." + b64.EncodeToString(signature), nil
}
func proof(ctx context.Context, key DPoPSigner, method, target, token string, iat int64) (string, error) {
	if key == nil {
		return "", ErrKeystoreUnavailable
	}
	j := key.PublicJWK()
	if _, err := j.publicKey(); err != nil {
		return "", err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrToken
	}

	ath := sha256.Sum256([]byte(token))
	return signProofJWT(ctx, key, j, struct {
		Alg string    `json:"alg"`
		Typ string    `json:"typ"`
		JWK PublicJWK `json:"jwk"`
	}{"ES256", "dpop+jwt", j},
		struct {
			HTM string `json:"htm"`
			HTU string `json:"htu"`
			ATH string `json:"ath"`
			JTI string `json:"jti"`
			IAT int64  `json:"iat"`
		}{method, target, b64.EncodeToString(ath[:]), b64.EncodeToString(nonce), iat})
}

// verifyJWT refuses algorithm confusion, private JWKs, header-selected keys and
// noncanonical base64 encodings. Token claims remain untrusted until this passes.
func verifyJWT(token string, key *ecdsa.PublicKey) ([]byte, error) {
	if len(token) > 32768 {
		return nil, ErrToken
	}
	if _, err := jwk(key); err != nil {
		return nil, err
	}
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return nil, ErrToken
	}
	h, err := decode64(p[0], 4096)
	if err != nil {
		return nil, ErrToken
	}
	var head struct {
		Alg string `json:"alg"`
		Typ string `json:"typ,omitempty"`
		Kid string `json:"kid,omitempty"`
	}
	if strictJSON(h, &head) != nil || head.Alg != "ES256" || head.Typ != "JWT" {
		return nil, ErrToken
	}
	c, err := decode64(p[1], 24576)
	if err != nil {
		return nil, ErrToken
	}
	s, err := decode64(p[2], 64)
	if err != nil || len(s) != 64 {
		return nil, ErrToken
	}
	d := sha256.Sum256([]byte(p[0] + "." + p[1]))
	if !ecdsa.Verify(key, d[:], new(big.Int).SetBytes(s[:32]), new(big.Int).SetBytes(s[32:])) {
		return nil, ErrToken
	}
	return c, nil
}
func decode64(s string, limit int) ([]byte, error) {
	if len(s) > b64.EncodedLen(limit) {
		return nil, ErrInvalid
	}
	raw, err := b64.DecodeString(s)
	if err != nil || len(raw) > limit || b64.EncodeToString(raw) != s {
		return nil, fmt.Errorf("%w", ErrInvalid)
	}
	return raw, nil
}

// EnrollmentProof binds a human-authorized enrollment POST to the same native
// device DPoP signer later used for memory sessions. The caller fixes its TLS
// origin and refuses redirects before any token is sent.
func EnrollmentProof(ctx context.Context, key DPoPSigner, target, token string, iat int64) (string, error) {
	return proof(ctx, key, "POST", target, token, iat)
}
