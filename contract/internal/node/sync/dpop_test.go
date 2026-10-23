package sync

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestKeystoreHandleDeletionAndRotation(t *testing.T) {
	for _, action := range []string{"delete", "rotate"} {
		t.Run(action, func(t *testing.T) {
			f := newFixture(t, 0)
			ctx := context.Background()
			credentials, err := f.keystore.Load(ctx, f.scope)
			if err != nil {
				t.Fatal(err)
			}
			retained := credentials.DPoP
			if _, err = proof(ctx, retained, "POST", f.server.URL, credentials.Refresh, time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			if action == "delete" {
				if err = f.keystore.DeleteTenant(ctx, f.scope); err != nil {
					t.Fatal(err)
				}
			} else {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				f.keystore.tenants[f.scope.Tenant] = fixtureCredentials{credentials.Refresh, key}
			}
			digest := sha256.Sum256([]byte("retained handle attack"))
			if signature, err := retained.Sign(ctx, digest[:]); !errors.Is(err, ErrKeystoreUnavailable) || len(signature) != 0 {
				t.Fatal("old handle signed after revocation", err)
			}
			otherScope := f.scope
			otherScope.Tenant = "tenant-two"
			other, err := f.keystore.Load(ctx, otherScope)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = proof(ctx, other.DPoP, "POST", f.server.URL, other.Refresh, time.Now().Unix()); err != nil {
				t.Fatal("other tenant affected", err)
			}
		})
	}
}

type testSigner struct {
	public PublicJWK
	sign   func(context.Context, []byte) ([]byte, error)
}

func (s testSigner) PublicJWK() PublicJWK { return s.public }
func (s testSigner) Sign(ctx context.Context, d []byte) ([]byte, error) {
	return s.sign(ctx, d)
}

func TestSignerRejectsInvalidPublicIdentitiesBeforeSign(t *testing.T) {
	f := newFixture(t, 0)
	valid, _ := jwk(&f.dpopKey.PublicKey)
	for _, change := range []func(*PublicJWK){
		func(j *PublicJWK) { j.Crv = "P-384" },
		func(j *PublicJWK) { j.Kty = "RSA" },
		func(j *PublicJWK) { j.X = "!" },
		func(j *PublicJWK) { j.Y = "AA" },
		func(j *PublicJWK) { j.X = strings.Repeat("A", 43); j.Y = j.X },
	} {
		j := valid
		change(&j)
		s := testSigner{j, func(context.Context, []byte) ([]byte, error) {
			t.Fatal("signed with invalid public identity")
			return nil, nil
		}}
		if _, err := proof(context.Background(), s, "POST", f.server.URL, "token", time.Now().Unix()); !errors.Is(err, ErrToken) {
			t.Fatal(err)
		}
	}
}

func TestSignerFailuresNeverLeaveKeystoreBoundary(t *testing.T) {
	f := newFixture(t, 0)
	credentials, _ := f.keystore.Load(context.Background(), f.scope)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, mode := range []string{"error", "short", "long", "invalid", "wrong-key"} {
		t.Run(mode, func(t *testing.T) {
			s := testSigner{credentials.DPoP.PublicJWK(), func(_ context.Context, digest []byte) ([]byte, error) {
				if len(digest) != sha256.Size {
					t.Fatal("not a SHA-256 digest")
				}
				switch mode {
				case "error":
					return nil, errors.New("sensitive OS details")
				case "short":
					return make([]byte, 63), nil
				case "long":
					return make([]byte, 65), nil
				case "invalid":
					return make([]byte, 64), nil
				default:
					r, v, _ := ecdsa.Sign(rand.Reader, other, digest)
					return append(r.FillBytes(make([]byte, 32)), v.FillBytes(make([]byte, 32))...), nil
				}
			}}
			want := ErrToken
			if mode == "error" {
				want = ErrKeystoreUnavailable
			}
			if token, err := proof(context.Background(), s, "POST", f.server.URL, "token", time.Now().Unix()); !errors.Is(err, want) || token != "" {
				t.Fatal("unsafe signature accepted", err)
			}
		})
	}
}

func TestSignerReceivesCancellation(t *testing.T) {
	f := newFixture(t, 0)
	credentials, _ := f.keystore.Load(context.Background(), f.scope)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := testSigner{credentials.DPoP.PublicJWK(), func(received context.Context, d []byte) ([]byte, error) {
		if received != ctx || !errors.Is(received.Err(), context.Canceled) {
			t.Fatal("context lost")
		}
		return nil, received.Err()
	}}
	if _, err := proof(ctx, s, "POST", f.server.URL, "token", time.Now().Unix()); !errors.Is(err, ErrKeystoreUnavailable) {
		t.Fatal(err)
	}
}
