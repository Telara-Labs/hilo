package releaseauth

// This file is a TEST-ONLY cross-language oracle. The deterministic seed is
// public fixture material, never a project release signing key. The production
// Sign/Verify APIs must reject its key. Run only through the admitted CI job:
// go test -p 1 ./releaseauth -run '^TestNPMFixtureCorpusGoOracle$' -count=1 -v
// Extract the single NPM_RELEASE_AUTH_CORPUS_V1 base64 JSON log record into
// npm/test/fixtures/go-release-auth-v1.json. Node never generates signatures.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type npmFixture struct {
	Name       string            `json:"name"`
	Family     string            `json:"family"`
	Version    string            `json:"version"`
	Build      []byte            `json:"build"`
	Sums       []byte            `json:"sums"`
	Signature  []byte            `json:"signature"`
	Artifacts  map[string][]byte `json:"artifacts"`
	Hashes     map[string]string `json:"hashes"`
	GoAccept   bool              `json:"goAccept"`
	NodeAccept bool              `json:"nodeAccept"`
}

type npmCorpus struct {
	Schema             string       `json:"schema"`
	TestOnlySeedRecipe string       `json:"testOnlySeedRecipe"`
	PublicKeyPEM       string       `json:"publicKeyPEM"`
	ProductionKeyHash  string       `json:"productionKeySha256"`
	Fixtures           []npmFixture `json:"fixtures"`
}

func npmHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestNPMFixtureCorpusGoOracle(t *testing.T) {
	const recipe = "telara-memory npm fixture TEST ONLY v1; NEVER RELEASE"
	seed := sha256.Sum256([]byte(recipe))
	key := ed25519.NewKeyFromSeed(seed[:])
	pub := key.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	corpus := npmCorpus{
		Schema: "telara.npm.releaseauth.go-fixtures.v1", TestOnlySeedRecipe: "SHA256(ASCII(" + recipe + "))",
		PublicKeyPEM:      string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		ProductionKeyHash: npmHash(publicKeyPEM),
	}
	// emit independently verifies every candidate through the actual private Go
	// verifier, including artifact bytes, before recording its expectation.
	emit := func(f npmFixture, wantGo, wantNode bool) {
		t.Helper()
		dir := t.TempDir()
		for name, body := range map[string][]byte{"BUILD.json": f.Build, "SHA256SUMS": f.Sums, "RELEASE.sig": f.Signature} {
			if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
				t.Fatal(err)
			}
		}
		for name, body := range f.Artifacts {
			if err := os.WriteFile(filepath.Join(dir, name), body, 0700); err != nil {
				t.Fatal(err)
			}
		}
		verified, verifyErr := verify(dir, pub)
		if (verifyErr == nil) != wantGo {
			t.Fatalf("%s Go oracle got %v want acceptance %v", f.Name, verifyErr, wantGo)
		}
		if wantGo {
			if _, err := Verify(dir); err == nil {
				t.Fatal("production verifier admitted public TEST-ONLY signing key")
			}
			for _, platform := range []string{"darwin", "linux", "windows"} {
				for _, arch := range []string{"amd64", "arm64"} {
					path, digest, version, err := target(dir, platform, arch, pub)
					if err != nil || version != verified.Source || digest != npmHash(f.Artifacts[filepath.Base(path)]) {
						t.Fatalf("%s target %s/%s failed: %v", f.Name, platform, arch, err)
					}
				}
			}
		}
		f.GoAccept, f.NodeAccept = wantGo, wantNode
		f.Hashes = map[string]string{"build": npmHash(f.Build), "sums": npmHash(f.Sums), "signature": npmHash(f.Signature)}
		corpus.Fixtures = append(corpus.Fixtures, f)
	}
	resign := func(f *npmFixture) {
		f.Signature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload(f.Build, f.Sums))) + "\n")
	}
	for _, family := range []struct{ label, prefix string }{{"legacy", legacyArtifactPrefix}, {"hilo", hiloArtifactPrefix}} {
		dir := t.TempDir()
		f := npmFixture{Name: family.label + "-valid", Family: family.label, Version: "1.2.3", Artifacts: map[string][]byte{}}
		var sums strings.Builder
		for _, platform := range []string{"darwin", "linux", "windows"} {
			for _, arch := range []string{"amd64", "arm64"} {
				name := targetName(family.prefix, platform, arch)
				body := []byte("TEST-ONLY native artifact " + platform + "/" + arch + "\n")
				f.Artifacts[name] = body
				fmt.Fprintf(&sums, "%s  %s\n", npmHash(body), name)
				if err := os.WriteFile(filepath.Join(dir, name), body, 0700); err != nil {
					t.Fatal(err)
				}
			}
		}
		f.Sums = []byte(sums.String())
		unsigned, err := json.MarshalIndent(Provenance{1, "v1.2.3", "go1.26.1", "clean-tag-export-unsigned", false}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "BUILD.json"), append(unsigned, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), f.Sums, 0600); err != nil {
			t.Fatal(err)
		}
		if err := Sign(dir, key); err == nil {
			t.Fatal("production signer admitted TEST-ONLY key")
		}
		if err := sign(dir, key); err != nil {
			t.Fatal(err)
		}
		f.Build, err = os.ReadFile(filepath.Join(dir, "BUILD.json"))
		if err != nil {
			t.Fatal(err)
		}
		f.Signature, err = os.ReadFile(filepath.Join(dir, "RELEASE.sig"))
		if err != nil {
			t.Fatal(err)
		}
		emit(f, true, true)
		for _, mutation := range []struct {
			name, from, to string
			goAccept       bool
		}{
			{"wrong-source", "v1.2.3", "v9.9.9", true},
			{"invalid-source", "v1.2.3", "v1.2.3+metadata", false},
			{"wrong-toolchain", "go1.26.1", "go1.99.0", false},
			{"wrong-format", "\"format\": 1", "\"format\": 2", false},
			{"signed-false", "\"signed\": true", "\"signed\": false", false},
			{"development", "clean-tag-export-signed", "UNVERIFIED-development-signed", false},
			{"noncanonical-json", "  \"format\": 1,", " \"format\": 1,", true},
			{"duplicate-json", "  \"format\": 1,", "  \"format\": 1,\n  \"format\": 1,", true},
			{"case-json", "\"format\"", "\"Format\"", true},
			{"unknown-json", "  \"format\": 1,", "  \"extra\": 0,\n  \"format\": 1,", false},
		} {
			bad := f
			bad.Name = family.label + "-" + mutation.name
			bad.Build = bytes.Replace(f.Build, []byte(mutation.from), []byte(mutation.to), 1)
			if bytes.Equal(bad.Build, f.Build) {
				t.Fatal("fixture mutation did not change BUILD")
			}
			resign(&bad)
			emit(bad, mutation.goAccept, false)
		}
		lines := strings.Split(strings.TrimSuffix(string(f.Sums), "\n"), "\n")
		otherPrefix := hiloArtifactPrefix
		if family.label == "hilo" {
			otherPrefix = legacyArtifactPrefix
		}
		for _, mutation := range []struct{ name, sums string }{
			{"partial", strings.Join(lines[:5], "\n") + "\n"},
			{"duplicate", strings.Join(append(append([]string{}, lines[:5]...), lines[0]), "\n") + "\n"},
			{"extra", string(f.Sums) + lines[0] + "\n"},
			{"traversal", strings.Replace(string(f.Sums), family.prefix+"darwin-amd64", "../darwin-amd64", 1)},
			{"wrong-suffix", strings.Replace(string(f.Sums), family.prefix+"darwin-amd64", family.prefix+"darwin-amd64.exe", 1)},
			{"mixed", strings.Replace(string(f.Sums), family.prefix+"darwin-amd64", otherPrefix+"darwin-amd64", 1)},
			{"unknown", strings.Replace(string(f.Sums), family.prefix+"darwin-amd64", family.prefix+"freebsd-amd64", 1)},
			{"twelve", string(f.Sums) + strings.ReplaceAll(string(f.Sums), family.prefix, otherPrefix)},
		} {
			bad := f
			bad.Name, bad.Sums = family.label+"-"+mutation.name, []byte(mutation.sums)
			resign(&bad)
			emit(bad, false, false)
		}
		bad := f
		bad.Name = family.label + "-wrong-domain"
		bad.Signature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("wrong-domain\x00"), payload(f.Build, f.Sums)...))) + "\n")
		emit(bad, false, false)
		bad = f
		bad.Name = family.label + "-base64-whitespace"
		bad.Signature = append([]byte(" \n"), f.Signature...)
		emit(bad, true, false)
		bad = f
		bad.Name = family.label + "-base64-pad-bits"
		bad.Signature = append([]byte{}, f.Signature...)
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		// The final sextet contains only two data bits. Go's non-Strict decoder
		// admits nonzero padding bits; the npm canonical round-trip rejects them.
		last := strings.IndexByte(alphabet, bad.Signature[85])
		if last < 0 || last&15 != 0 {
			t.Fatal("unexpected canonical signature encoding")
		}
		bad.Signature[85] = alphabet[last|1]
		emit(bad, true, false)
		bad = f
		bad.Name = family.label + "-wrong-key"
		otherSeed := sha256.Sum256([]byte(recipe + " different key"))
		bad.Signature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(otherSeed[:]), payload(f.Build, f.Sums))) + "\n")
		emit(bad, false, false)
	}
	encoded, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("NPM_RELEASE_AUTH_CORPUS_V1 " + base64.StdEncoding.EncodeToString(encoded))
}
