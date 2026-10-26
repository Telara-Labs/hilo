package releaseauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var sums strings.Builder
	for _, platform := range []string{"darwin", "linux", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			n := "telara-memory-" + platform + "-" + arch
			if platform == "windows" {
				n += ".exe"
			}
			b := []byte("synthetic executable " + n)
			h := sha256.Sum256(b)
			if err := os.WriteFile(filepath.Join(dir, n), b, 0600); err != nil {
				t.Fatal(err)
			}
			sums.WriteString(hex.EncodeToString(h[:]) + "  " + n + "\n")
		}
	}
	b, _ := json.Marshal(Provenance{1, "v0.1.0", "go1.26.1", "clean-tag-export-unsigned", false})
	os.WriteFile(filepath.Join(dir, "BUILD.json"), b, 0600)
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0600)
	return dir, key
}

func TestReleaseSignatureBindsEveryArtifactAndProvenance(t *testing.T) {
	for _, file := range []string{"BUILD.json", "SHA256SUMS", "RELEASE.sig", "telara-memory-darwin-arm64", "telara-memory-linux-amd64", "telara-memory-windows-arm64.exe"} {
		t.Run(file, func(t *testing.T) {
			dir, key := fixture(t)
			if err := sign(dir, key); err != nil {
				t.Fatal(err)
			}
			if _, err := verify(dir, key.Public().(ed25519.PublicKey)); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, file)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			b[len(b)/2] ^= 1
			if err = os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = verify(dir, key.Public().(ed25519.PublicKey)); err == nil {
				t.Fatal("tampered release accepted")
			}
		})
	}
}

func TestReleaseRefusesDevelopmentWrongKeyAndUnsafeManifest(t *testing.T) {
	dir, key := fixture(t)
	if err := Sign(dir, key); err == nil {
		t.Fatal("unrelated signing key accepted")
	}
	p := Provenance{1, "", "go1.26.1", "UNVERIFIED-development-unsigned", false}
	b, _ := json.Marshal(p)
	os.WriteFile(filepath.Join(dir, "BUILD.json"), b, 0600)
	if err := sign(dir, key); err == nil {
		t.Fatal("development signed")
	}
	for _, s := range []string{strings.Repeat("0", 64) + "  ../escape\n", strings.Repeat("0", 64) + "  telara-memory-linux-amd64\n", strings.Repeat("0", 64) + "  /absolute\n"} {
		if _, err := artifacts([]byte(s)); err == nil {
			t.Fatal("unsafe manifest accepted")
		}
	}
	if _, err := PublicKey(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticatedTargetBindsInstallerInputs(t *testing.T) {
	dir, key := fixture(t)
	if err := sign(dir, key); err != nil {
		t.Fatal(err)
	}
	path, digest, version, err := target(dir, "windows", "arm64", key.Public().(ed25519.PublicKey))
	if err != nil || path != filepath.Join(dir, "telara-memory-windows-arm64.exe") || len(digest) != 64 || version != "v0.1.0" {
		t.Fatal(path, digest, version, err)
	}
	if _, _, _, err = target(dir, "../escape", "arm64", key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("unknown target accepted")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	b[0] ^= 1
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), b, 0600)
	if _, _, _, err = target(dir, "windows", "arm64", key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("unauthenticated install digest accepted")
	}
}
