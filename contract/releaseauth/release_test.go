package releaseauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func fixture(t *testing.T) (string, ed25519.PrivateKey) {
	return fixtureWithFamily(t, legacyArtifactPrefix)
}

func fixtureWithFamily(t *testing.T, prefix string) (string, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var sums strings.Builder
	for _, platform := range []string{"darwin", "linux", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			n := targetName(prefix, platform, arch)
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
		if _, _, err := artifacts([]byte(s)); err == nil {
			t.Fatal("unsafe manifest accepted")
		}
	}
	if _, err := PublicKey(); err != nil {
		t.Fatal(err)
	}
}

func testSums(prefix string) []byte {
	var sums strings.Builder
	names := make([]string, 0, 6)
	for name := range expectedArtifacts(prefix) {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		sums.WriteString(strings.Repeat("0", 64) + "  " + name + "\n")
	}
	return []byte(sums.String())
}

func TestArtifactsAcceptExactlyOneCompleteTargetFamily(t *testing.T) {
	for _, prefix := range []string{legacyArtifactPrefix, hiloArtifactPrefix} {
		t.Run(prefix, func(t *testing.T) {
			files, family, err := artifacts(testSums(prefix))
			if err != nil || len(files) != 6 || family != prefix {
				t.Fatalf("files=%d family=%q err=%v", len(files), family, err)
			}
		})
	}
}

func TestArtifactsRejectMixedPartialExtraUnknownAndDuplicateNames(t *testing.T) {
	legacy := strings.TrimSuffix(string(testSums(legacyArtifactPrefix)), "\n")
	lines := strings.Split(legacy, "\n")
	first := lines[0]
	last := lines[len(lines)-1]

	partial := strings.Join(lines[:len(lines)-1], "\n") + "\n"
	mixed := strings.Join(append(append([]string{}, lines[:len(lines)-1]...), strings.Replace(last, legacyArtifactPrefix, hiloArtifactPrefix, 1)), "\n") + "\n"
	extra := legacy + "\n" + strings.Repeat("0", 64) + "  hilo-macos-unknown\n"
	duplicate := legacy + "\n" + first + "\n"
	unknown := strings.Join(append(append([]string{}, lines[:len(lines)-1]...), strings.Repeat("0", 64)+"  ../escape"), "\n") + "\n"
	for name, sums := range map[string]string{"partial": partial, "mixed": mixed, "extra": extra, "duplicate": duplicate, "unknown": unknown} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := artifacts([]byte(sums)); err == nil {
				t.Fatalf("%s manifest accepted", name)
			}
		})
	}
}

func TestAuthenticatedTargetBindsInstallerInputs(t *testing.T) {
	dir, key := fixture(t)
	if err := sign(dir, key); err != nil {
		t.Fatal(err)
	}
	path, digest, version, err := target(dir, "windows", "arm64", key.Public().(ed25519.PublicKey))
	wantDigest := sha256.Sum256([]byte("synthetic executable telara-memory-windows-arm64.exe"))
	if err != nil || path != filepath.Join(dir, "telara-memory-windows-arm64.exe") || digest != hex.EncodeToString(wantDigest[:]) || version != "v0.1.0" {
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

func TestAuthenticatedTargetSelectsHiloFamily(t *testing.T) {
	dir, key := fixtureWithFamily(t, hiloArtifactPrefix)
	if err := sign(dir, key); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(dir, key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal("complete Hilo family failed verification:", err)
	}
	path, digest, version, err := target(dir, "windows", "arm64", key.Public().(ed25519.PublicKey))
	wantDigest := sha256.Sum256([]byte("synthetic executable hilo-windows-arm64.exe"))
	if err != nil || path != filepath.Join(dir, "hilo-windows-arm64.exe") || digest != hex.EncodeToString(wantDigest[:]) || version != "v0.1.0" {
		t.Fatal(path, digest, version, err)
	}
	if _, _, _, err = target(dir, "windows", "unknown", key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("unknown target accepted")
	}
}

func TestAuthenticatedTargetRejectsTamperedArtifactNameAndHashManifest(t *testing.T) {
	for _, mutate := range []struct {
		name string
		fn   func([]byte) []byte
	}{
		{name: "filename", fn: func(b []byte) []byte {
			return []byte(strings.Replace(string(b), "telara-memory-linux-amd64", "hilo-linux-amd64", 1))
		}},
		{name: "hash", fn: func(b []byte) []byte {
			if b[0] == 'f' {
				b[0] = 'e'
			} else {
				b[0] = 'f'
			}
			return b
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			dir, key := fixture(t)
			if err := sign(dir, key); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "SHA256SUMS")
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, mutate.fn(b), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err = target(dir, "windows", "arm64", key.Public().(ed25519.PublicKey)); err == nil {
				t.Fatal("tampered signed filename or digest accepted")
			}
		})
	}
}
