package sync

import "crypto/ecdsa"

// PublicJWKOf returns the public-only RFC 7638 members of a P-256 key.
func PublicJWKOf(k *ecdsa.PublicKey) (PublicJWK, error) { return jwk(k) }

// Thumbprint returns the RFC 7638 SHA-256 thumbprint used as the DPoP jkt.
func Thumbprint(k *ecdsa.PublicKey) (string, error) { return thumbprint(k) }

// PublicKey validates and returns the P-256 public key this JWK names.
func (j PublicJWK) PublicKey() (*ecdsa.PublicKey, error) { return j.publicKey() }
