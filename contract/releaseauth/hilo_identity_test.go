package releaseauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHiloRenameKeepsAuthenticatedV1ReleaseDomain(t *testing.T) {
	for _, prefix := range []string{hiloArtifactPrefix, legacyArtifactPrefix} {
		t.Run(prefix, func(t *testing.T) {
			dir, key := fixtureWithFamily(t, prefix)
			if err := sign(dir, key); err != nil {
				t.Fatal(err)
			}
			public := key.Public().(ed25519.PublicKey)
			if _, err := verify(dir, public); err != nil {
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
			want := append([]byte("telara-memory-release-v1\x00"), build...)
			want = append(want, 0)
			want = append(want, sums...)
			if !bytes.Equal(payload(build, sums), want) {
				t.Fatal("historical authentication domain changed with product label")
			}
			other := append([]byte("hilo-release-v1\x00"), build...)
			other = append(other, 0)
			other = append(other, sums...)
			wrong := ed25519.Sign(key, other)
			if err := os.WriteFile(filepath.Join(dir, "RELEASE.sig"), []byte(base64.StdEncoding.EncodeToString(wrong)+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := verify(dir, public); err == nil {
				t.Fatal("renamed unauthenticated domain accepted")
			}
		})
	}
}

func TestHiloAuthenticatedManifestRefusesCrossFamilySubstitution(t *testing.T) {
	for _, prefix := range []string{hiloArtifactPrefix, legacyArtifactPrefix} {
		t.Run(prefix, func(t *testing.T) {
			dir, key := fixtureWithFamily(t, prefix)
			if err := sign(dir, key); err != nil {
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
			other := legacyArtifactPrefix
			if prefix == legacyArtifactPrefix {
				other = hiloArtifactPrefix
			}
			mixed := []byte(strings.Replace(string(sums), prefix+"linux-amd64", other+"linux-amd64", 1))
			if bytes.Equal(mixed, sums) {
				t.Fatal("cross-family fixture did not change")
			}
			if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), mixed, 0600); err != nil {
				t.Fatal(err)
			}
			// Sign the malformed set with the legitimate unit-test key. Refusal
			// must come from the closed family contract, not a bad signature.
			signature := ed25519.Sign(key, payload(build, mixed))
			if err := os.WriteFile(filepath.Join(dir, "RELEASE.sig"), []byte(base64.StdEncoding.EncodeToString(signature)+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := manifest(dir, key.Public().(ed25519.PublicKey)); err == nil {
				t.Fatal("validly signed mixed artifact families accepted")
			}
		})
	}
}
