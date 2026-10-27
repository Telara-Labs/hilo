// Package releaseauth authenticates release manifests against the project key.
package releaseauth

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
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
	"reflect"
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

// The v1 domain is an immutable authentication-format identifier. Hilo keeps
// it so historical signed artifacts remain verifiable; it is not a product name.
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
	if verifyReleaseSignature(build, sums, raw, key) != nil {
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

// Sign retains the file-key API for callers holding an Ed25519 private key.
func Sign(dir string, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return ErrInvalid
	}
	return SignWithSigner(dir, key)
}

// SignWithSigner signs the exact release payload with a crypto.Signer whose
// Ed25519 public key matches the compiled project pin. It does not establish
// hardware custody; that requires a separately provisioned and audited signer.
func SignWithSigner(dir string, signer crypto.Signer) error {
	pub, err := PublicKey()
	if err != nil {
		return ErrInvalid
	}
	return signWithSigner(dir, signer, pub)
}

// sign keeps the existing synthetic-key test seam.
func sign(dir string, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return ErrInvalid
	}
	return signWithSigner(dir, key, key.Public().(ed25519.PublicKey))
}

// Provider boundaries refuse typed nils and convert provider panics to errors.
// They do not establish the custody or trustworthiness of a provider.
func nilSigner(signer crypto.Signer) bool {
	if signer == nil {
		return true
	}
	v := reflect.ValueOf(signer)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func signerPublic(signer crypto.Signer) (public crypto.PublicKey, err error) {
	defer func() {
		if recover() != nil {
			public, err = nil, ErrInvalid
		}
	}()
	return signer.Public(), nil
}

func signerSign(signer crypto.Signer, message []byte) (signature []byte, err error) {
	defer func() {
		if recover() != nil {
			signature, err = nil, ErrInvalid
		}
	}()
	return signer.Sign(rand.Reader, append([]byte(nil), message...), crypto.Hash(0))
}

func signWithSigner(dir string, signer crypto.Signer, expected ed25519.PublicKey) error {
	if nilSigner(signer) || len(expected) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	public, err := signerPublic(signer)
	if err != nil {
		return ErrInvalid
	}
	pub, ok := public.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize || !pub.Equal(expected) {
		return ErrInvalid
	}
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
	message := payload(b, sums)
	signature, e := signerSign(signer, message)
	if e != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(expected, message, signature) {
		return ErrInvalid
	}
	if e = os.WriteFile(filepath.Join(dir, "BUILD.json"), b, 0600); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "RELEASE.sig"), []byte(base64.StdEncoding.EncodeToString(signature)+"\n"), 0600); e != nil {
		return e
	}
	_, e = verify(dir, expected)
	return e
}
