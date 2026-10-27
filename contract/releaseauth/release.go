// Package releaseauth authenticates release manifests against the project key.
package releaseauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed release-key.pub
var publicKeyPEM []byte

var ErrInvalid = errors.New("release_verification_failed")

type Provenance struct {
	Format       int    `json:"format"`
	Source       string `json:"source"`
	Toolchain    string `json:"toolchain"`
	Verification string `json:"verification"`
	Signed       bool   `json:"signed"`
}

func PublicKey() (ed25519.PublicKey, error) {
	b, rest := pem.Decode(publicKeyPEM)
	if b == nil || len(rest) != 0 {
		return nil, ErrInvalid
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	pub, ok := k.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, ErrInvalid
	}
	return pub, nil
}

func read(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > limit {
		return nil, ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalid
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, ErrInvalid
	}
	return b, nil
}

func payload(build, sums []byte) []byte {
	b := append([]byte("telara-memory-release-v1\x00"), build...)
	b = append(b, 0)
	return append(b, sums...)
}

const (
	legacyArtifactPrefix = "telara-memory-"
	hiloArtifactPrefix   = "hilo-"
)

func targetName(prefix, platform, arch string) string {
	name := prefix + platform + "-" + arch
	if platform == "windows" {
		name += ".exe"
	}
	return name
}

func expectedArtifacts(prefix string) map[string]bool {
	want := map[string]bool{}
	for _, platform := range []string{"darwin", "linux", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			want[targetName(prefix, platform, arch)] = true
		}
	}
	return want
}

func artifacts(sums []byte) (map[string]string, string, error) {
	legacy := expectedArtifacts(legacyArtifactPrefix)
	hilo := expectedArtifacts(hiloArtifactPrefix)
	out := map[string]string{}
	family := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(sums), "\n"), "\n") {
		p := strings.Split(line, "  ")
		if len(p) != 2 || out[p[1]] != "" || len(p[0]) != 64 {
			return nil, "", ErrInvalid
		}
		lineFamily := ""
		if legacy[p[1]] {
			lineFamily = legacyArtifactPrefix
		} else if hilo[p[1]] {
			lineFamily = hiloArtifactPrefix
		}
		if lineFamily == "" || (family != "" && family != lineFamily) {
			return nil, "", ErrInvalid
		}
		if _, err := hex.DecodeString(p[0]); err != nil {
			return nil, "", ErrInvalid
		}
		family = lineFamily
		out[p[1]] = p[0]
	}
	if len(out) != 6 || family == "" {
		return nil, "", ErrInvalid
	}
	return out, family, nil
}

// Verify authenticates the exact source manifest and every release binary.
// The public key is compiled into this package; a key supplied with a download
// cannot replace it. Artifact names are a closed six-target set.
func Verify(dir string) (Provenance, error) {
	return verify(dir, nil)
}

func manifest(dir string, key ed25519.PublicKey) (Provenance, map[string]string, string, error) {
	var p Provenance
	build, e := read(filepath.Join(dir, "BUILD.json"), 16384)
	if e != nil {
		return p, nil, "", e
	}
	sums, e := read(filepath.Join(dir, "SHA256SUMS"), 4096)
	if e != nil {
		return p, nil, "", e
	}
	sig, e := read(filepath.Join(dir, "RELEASE.sig"), 256)
	if e != nil {
		return p, nil, "", e
	}
	raw, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if e != nil {
		return p, nil, "", ErrInvalid
	}
	if key == nil {
		key, e = PublicKey()
		if e != nil {
			return p, nil, "", e
		}
	}
	if !ed25519.Verify(key, payload(build, sums), raw) {
		return p, nil, "", ErrInvalid
	}
	d := json.NewDecoder(strings.NewReader(string(build)))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Format != 1 || !p.Signed || p.Verification != "clean-tag-export-signed" || p.Toolchain != "go1.26.1" || !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$`).MatchString(p.Source) {
		return Provenance{}, nil, "", ErrInvalid
	}
	files, family, e := artifacts(sums)
	if e != nil {
		return Provenance{}, nil, "", e
	}
	return p, files, family, nil
}

func checkFiles(dir string, files map[string]string) error {
	for name, want := range files {
		f, e := os.Open(filepath.Join(dir, name))
		if e != nil {
			return ErrInvalid
		}
		info, e := f.Stat()
		before, le := os.Lstat(filepath.Join(dir, name))
		if e != nil || le != nil || !info.Mode().IsRegular() || !before.Mode().IsRegular() || !os.SameFile(info, before) {
			f.Close()
			return ErrInvalid
		}
		h := sha256.New()
		_, e = io.Copy(h, io.LimitReader(f, 512<<20))
		ce := f.Close()
		if e != nil || ce != nil || info.Size() > 512<<20 || hex.EncodeToString(h.Sum(nil)) != want {
			return ErrInvalid
		}
	}
	return nil
}

func verify(dir string, key ed25519.PublicKey) (Provenance, error) {
	p, files, _, err := manifest(dir, key)
	if err != nil {
		return Provenance{}, err
	}
	if err = checkFiles(dir, files); err != nil {
		return Provenance{}, err
	}
	return p, nil
}

// Target returns an authenticated install input. The installer must compare
// copied bytes to the returned digest, rather than trust the mutable path.
func Target(dir, platform, arch string) (path, digest, version string, err error) {
	return target(dir, platform, arch, nil)
}
func target(dir, platform, arch string, key ed25519.PublicKey) (string, string, string, error) {
	p, files, family, err := manifest(dir, key)
	if err != nil {
		return "", "", "", err
	}
	name := targetName(family, platform, arch)
	digest, ok := files[name]
	if !ok {
		return "", "", "", ErrInvalid
	}
	path, err := filepath.Abs(filepath.Join(dir, name))
	if err != nil {
		return "", "", "", ErrInvalid
	}
	return path, digest, p.Source, nil
}

// Sign seals only a complete clean-tag release. Development builds are refused.
// The private key must match the public key compiled into this source tree.
func Sign(dir string, key ed25519.PrivateKey) error {
	pub, e := PublicKey()
	if e != nil || len(key) != ed25519.PrivateKeySize || !key.Public().(ed25519.PublicKey).Equal(pub) {
		return ErrInvalid
	}
	return sign(dir, key)
}

func sign(dir string, key ed25519.PrivateKey) error {
	b, e := read(filepath.Join(dir, "BUILD.json"), 16384)
	if e != nil {
		return e
	}
	var p Provenance
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Format != 1 || p.Signed || p.Verification != "clean-tag-export-unsigned" {
		return ErrInvalid
	}
	sums, e := read(filepath.Join(dir, "SHA256SUMS"), 4096)
	if e != nil {
		return e
	}
	files, _, e := artifacts(sums)
	if e != nil {
		return e
	}
	if e = checkFiles(dir, files); e != nil {
		return e
	}
	p.Signed = true
	p.Verification = "clean-tag-export-signed"
	b, e = json.MarshalIndent(p, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	if e = os.WriteFile(filepath.Join(dir, "BUILD.json"), b, 0600); e != nil {
		return e
	}
	signature := ed25519.Sign(key, payload(b, sums))
	if e = os.WriteFile(filepath.Join(dir, "RELEASE.sig"), []byte(base64.StdEncoding.EncodeToString(signature)+"\n"), 0600); e != nil {
		return e
	}
	_, e = verify(dir, key.Public().(ed25519.PublicKey))
	return e
}
