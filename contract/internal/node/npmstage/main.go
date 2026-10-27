// Command npmstage prepares a private npm package from a complete authenticated
// release. It is local-only and never downloads, executes, publishes or signs.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/releaseauth"
)

const repository = "Telara-Labs/telara-memory"
const publicKeyHash = "8f56b2313dfb0ce37156cec349393b230d4055bc01501fb2adfa1f3cd6c5f492"

var errUnsafe = errors.New("npm_staging_unsafe_or_changed_path")
var errMetadata = errors.New("npm_staging_metadata_verification_failed")
var sourceFiles = []string{"README.md", "LICENSE", "bin/hilo.cjs", "lib/release-auth.cjs", "lib/runner.cjs"}
var packageFiles = []string{"bin/hilo.cjs", "lib/release-auth.cjs", "lib/runner.cjs", "release/BUILD.json", "release/SHA256SUMS", "release/RELEASE.sig", "release/release-key.pub", "release-spec.json", "README.md", "LICENSE"}
var tagPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$`)
var sumPattern = regexp.MustCompile(`^([0-9a-f]{64})  ([A-Za-z0-9.-]+)$`)

type config struct{ Release, Package, Out, Family string }
type releaseSpec struct {
	Version    string `json:"version"`
	Family     string `json:"family"`
	Tag        string `json:"tag"`
	Repository string `json:"repository"`
}
type rawMetadata struct{ Build, Sums, Signature []byte }
type metadataSnapshot struct {
	Raw   rawMetadata
	Files []snapshot
}
type prepared struct {
	Spec  releaseSpec
	Files map[string][]byte
}
type snapshot struct {
	Path string
	Info os.FileInfo
}
type directoryGuard struct {
	Root  string
	Owner uint64
	Dirs  []snapshot
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, report io.Writer) error {
	flags := flag.NewFlagSet("npmstage", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var c config
	flags.StringVar(&c.Release, "release", "", "Complete signed six-artifact release directory")
	flags.StringVar(&c.Package, "package", "", "Reviewed source npm package directory")
	flags.StringVar(&c.Out, "out", "", "New output package directory")
	flags.StringVar(&c.Family, "family", "", "Signed artifact family, hilo or legacy")
	if flags.Parse(args) != nil || flags.NArg() != 0 || c.Release == "" || c.Package == "" || c.Out == "" || (c.Family != "hilo" && c.Family != "legacy") {
		return errors.New("usage npmstage --release DIR --package DIR --out NEW_DIR --family hilo|legacy")
	}
	// Unix permission/ownership checks cannot establish a Windows DACL. Staging
	// on Windows remains unavailable until an equivalent host proof is added.
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("npm_staging_host_acl_unverified")
	}
	var err error
	for _, p := range []*string{&c.Release, &c.Package, &c.Out} {
		*p, err = filepath.Abs(*p)
		if err != nil {
			return errUnsafe
		}
	}
	if within(c.Package, c.Out) || within(c.Release, c.Out) || within(c.Out, c.Package) || within(c.Out, c.Release) {
		return errors.New("npm staging output must be separate from both inputs")
	}
	if _, err := os.Lstat(c.Out); !os.IsNotExist(err) {
		return errors.New("npm staging output must not exist")
	}
	input, err := prepare(c)
	if err != nil {
		return err
	}
	if err := publish(input, c.Out); err != nil {
		return err
	}
	hashes := map[string]string{}
	for name, data := range input.Files {
		h := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(h[:])
	}
	return json.NewEncoder(report).Encode(struct {
		Output string            `json:"output"`
		Spec   releaseSpec       `json:"release"`
		Files  map[string]string `json:"sha256"`
	}{c.Out, input.Spec, hashes})
}

func prefix(family string) (string, error) {
	switch family {
	case "hilo":
		return "hilo-", nil
	case "legacy":
		return "telara-memory-", nil
	}
	return "", errMetadata
}
func artifactName(family, platform, arch string) string {
	p, _ := prefix(family)
	name := p + platform + "-" + arch
	if platform == "windows" {
		name += ".exe"
	}
	return name
}

func prepare(c config) (prepared, error) {
	var out prepared
	releaseGuard, err := guardDirectory(c.Release)
	if err != nil {
		return out, err
	}
	key, keyBytes, err := pinnedKey()
	if err != nil {
		return out, err
	}
	// Freeze the exact bytes and file identities before any independent metadata
	// reads. Ordinary concurrent producers must not change this snapshot while
	// Target and the single complete Verify operate on the release directory.
	metadata, err := captureMetadata(releaseGuard)
	if err != nil {
		return out, err
	}
	// Target authenticates only metadata. Validate every selected file path,
	// then Verify supplies the separate complete six-binary content check.
	targets := map[string]string{}
	tag := ""
	for _, platform := range []string{"darwin", "linux", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			path, digest, source, err := releaseauth.Target(c.Release, platform, arch)
			name := artifactName(c.Family, platform, arch)
			if err != nil || path != filepath.Join(c.Release, name) || (tag != "" && source != tag) {
				return out, errMetadata
			}
			if _, err := releaseGuard.fileInfo(path, 512<<20); err != nil {
				return out, err
			}
			targets[name], tag = digest, source
		}
	}
	var captured releaseauth.Provenance
	if json.Unmarshal(metadata.Raw.Build, &captured) != nil || captured.Source != tag || authenticateCopiedMetadata(metadata.Raw, captured, targets, key) != nil {
		return out, errMetadata
	}
	verified, err := verifySnapshot(releaseGuard, metadata, func() (releaseauth.Provenance, error) {
		return releaseauth.Verify(c.Release)
	})
	if err != nil || verified != captured {
		return out, errMetadata
	}
	// An optional release-supplied key can detect a staging mismatch but can
	// never replace the compiled key or authorize metadata.
	if _, err := os.Lstat(filepath.Join(c.Release, "release-key.pub")); err == nil {
		b, err := releaseGuard.read("release-key.pub", 1024)
		if err != nil || !bytes.Equal(b, keyBytes) {
			return out, errMetadata
		}
	} else if !os.IsNotExist(err) {
		return out, errUnsafe
	}
	raw := metadata.Raw
	// Recheck the retained snapshot's exact signature, not reserialized data or
	// metadata reopened by Verify/Target. No second full native hash pass.
	if err := authenticateCopiedMetadata(raw, verified, targets, key); err != nil {
		return out, err
	}
	packageGuard, err := guardDirectory(c.Package)
	if err != nil {
		return out, err
	}
	out = prepared{Spec: releaseSpec{strings.TrimPrefix(tag, "v"), c.Family, tag, repository}, Files: map[string][]byte{}}
	for _, name := range sourceFiles {
		b, err := packageGuard.read(name, 1<<20)
		if err != nil {
			return prepared{}, err
		}
		out.Files[name] = b
	}
	pin := "const PINNED_PUBLIC_KEY = '" + strings.ReplaceAll(string(keyBytes), "\n", `\n`) + "';\n"
	if bytes.Count(out.Files["lib/release-auth.cjs"], []byte("const PINNED_PUBLIC_KEY =")) != 1 || !bytes.Contains(out.Files["lib/release-auth.cjs"], []byte(pin)) {
		return prepared{}, errors.New("npm source verifier key does not match compiled release key")
	}
	pkg, err := packageGuard.read("package.json", 65536)
	if err != nil {
		return prepared{}, err
	}
	out.Files["package.json"], err = versionedPackage(pkg, out.Spec.Version)
	if err != nil {
		return prepared{}, err
	}
	out.Files["release/BUILD.json"], out.Files["release/SHA256SUMS"], out.Files["release/RELEASE.sig"] = raw.Build, raw.Sums, raw.Signature
	out.Files["release/release-key.pub"] = keyBytes
	out.Files["release-spec.json"], err = canonicalJSON(out.Spec)
	if err != nil || packageGuard.check() != nil || metadata.check(releaseGuard) != nil {
		return prepared{}, errUnsafe
	}
	return out, nil
}

// Metadata stability is a trusted-workspace check, not snapshot isolation
// against hostile same-principal mutation or restoration of every observed
// inode/timestamp (ABA). Raw bytes plus inode/mode/size/mtime/ctime detect normal
// concurrent producers, including same-tag changes and ordinary byte restoration.
func metadataParts(raw *rawMetadata) []struct {
	name  string
	limit int64
	data  *[]byte
} {
	return []struct {
		name  string
		limit int64
		data  *[]byte
	}{
		{"BUILD.json", 16384, &raw.Build}, {"SHA256SUMS", 4096, &raw.Sums}, {"RELEASE.sig", 256, &raw.Signature},
	}
}
func captureMetadata(g *directoryGuard) (metadataSnapshot, error) {
	var s metadataSnapshot
	for _, part := range metadataParts(&s.Raw) {
		b, err := g.read(part.name, part.limit)
		if err != nil {
			return metadataSnapshot{}, err
		}
		info, err := g.fileInfo(filepath.Join(g.Root, part.name), part.limit)
		if err != nil {
			return metadataSnapshot{}, err
		}
		*part.data = b
		s.Files = append(s.Files, snapshot{filepath.Join(g.Root, part.name), info})
	}
	if err := s.check(g); err != nil {
		return metadataSnapshot{}, err
	}
	return s, nil
}
func metadataChangeTime(info os.FileInfo) ([2]int64, bool) {
	var out [2]int64
	v := reflect.ValueOf(info.Sys())
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return out, false
	}
	for _, name := range []string{"Ctim", "Ctimespec"} {
		field := v.FieldByName(name)
		if !field.IsValid() || field.Kind() != reflect.Struct {
			continue
		}
		sec, nsec := field.FieldByName("Sec"), field.FieldByName("Nsec")
		if sec.IsValid() && nsec.IsValid() && sec.CanInt() && nsec.CanInt() {
			return [2]int64{sec.Int(), nsec.Int()}, true
		}
	}
	return out, false
}
func sameMetadataFile(a, b os.FileInfo) bool {
	ac, aok := metadataChangeTime(a)
	bc, bok := metadataChangeTime(b)
	return aok && bok && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && ac == bc
}
func (s metadataSnapshot) check(g *directoryGuard) error {
	parts := metadataParts(&s.Raw)
	if len(s.Files) != len(parts) || g.check() != nil {
		return errUnsafe
	}
	for i, part := range parts {
		path := filepath.Join(g.Root, part.name)
		saved := s.Files[i]
		before, err := g.fileInfo(path, part.limit)
		if err != nil || saved.Path != path || !sameMetadataFile(saved.Info, before) {
			return errUnsafe
		}
		b, err := g.read(part.name, part.limit)
		if err != nil || !bytes.Equal(b, *part.data) {
			return errUnsafe
		}
		after, err := g.fileInfo(path, part.limit)
		if err != nil || !sameMetadataFile(saved.Info, after) {
			return errUnsafe
		}
	}
	return g.check()
}

// The callback is private test isolation for ordering/mutation tests. Production
// supplies only releaseauth.Verify, once, with its compiled production key.
func verifySnapshot(g *directoryGuard, s metadataSnapshot, verify func() (releaseauth.Provenance, error)) (releaseauth.Provenance, error) {
	if err := s.check(g); err != nil {
		return releaseauth.Provenance{}, err
	}
	verified, err := verify()
	if err != nil {
		return releaseauth.Provenance{}, err
	}
	if err := s.check(g); err != nil {
		return releaseauth.Provenance{}, err
	}
	return verified, nil
}

func pinnedKey() (ed25519.PublicKey, []byte, error) {
	key, err := releaseauth.PublicKey()
	if err != nil {
		return nil, nil, errMetadata
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, nil, errMetadata
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	h := sha256.Sum256(encoded)
	if hex.EncodeToString(h[:]) != publicKeyHash {
		return nil, nil, errMetadata
	}
	return key, encoded, nil
}

// Private helper accepts a key only to isolate raw-byte profile tests. The CLI
// always obtains it from pinnedKey after public Verify/Target succeed.
func authenticateCopiedMetadata(raw rawMetadata, verified releaseauth.Provenance, targets map[string]string, key ed25519.PublicKey) error {
	if len(raw.Build) == 0 || len(raw.Build) > 16384 || len(raw.Sums) == 0 || len(raw.Sums) > 4096 || len(raw.Signature) == 0 || len(raw.Signature) > 256 || len(key) != ed25519.PublicKeySize || len(targets) != 6 {
		return errMetadata
	}
	if verified.Format != 1 || !verified.Signed || verified.Toolchain != "go1.26.1" || verified.Verification != "clean-tag-export-signed" || !validVersion(strings.TrimPrefix(verified.Source, "v")) || !strings.HasPrefix(verified.Source, "v") {
		return errMetadata
	}
	canonical, err := canonicalJSON(verified)
	if err != nil || !bytes.Equal(canonical, raw.Build) {
		return errMetadata
	}
	encoded := strings.TrimSuffix(string(raw.Signature), "\n")
	sig, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != encoded {
		return errMetadata
	}
	payload := append([]byte("telara-memory-release-v1\x00"), raw.Build...)
	payload = append(payload, 0)
	payload = append(payload, raw.Sums...)
	if !ed25519.Verify(key, payload, sig) {
		return errMetadata
	}
	seen := map[string]bool{}
	lines := strings.Split(strings.TrimSuffix(string(raw.Sums), "\n"), "\n")
	if len(lines) != 6 {
		return errMetadata
	}
	for _, line := range lines {
		m := sumPattern.FindStringSubmatch(line)
		if m == nil || seen[m[2]] || targets[m[2]] != m[1] {
			return errMetadata
		}
		seen[m[2]] = true
	}
	return nil
}

func canonicalJSON(value any) ([]byte, error) {
	b, err := json.MarshalIndent(value, "", "  ")
	return append(b, '\n'), err
}

// Versions are ASCII by grammar, so Go byte length equals Node string length.
func validVersion(version string) bool {
	return len(version) <= 1024 && tagPattern.MatchString("v"+version)
}
func versionedPackage(raw []byte, version string) ([]byte, error) {
	if !validVersion(version) || uniqueJSON(raw) != nil {
		return nil, errors.New("npm source package metadata invalid")
	}
	var p map[string]json.RawMessage
	if json.Unmarshal(raw, &p) != nil {
		return nil, errors.New("npm source package metadata invalid")
	}
	if _, hasScripts := p["scripts"]; hasScripts {
		return nil, errors.New("npm source package lifecycle scripts are forbidden")
	}
	allowed := map[string]bool{"name": true, "private": true, "description": true, "license": true, "engines": true, "bin": true, "files": true, "repository": true}
	for name := range p {
		if !allowed[name] {
			return nil, errors.New("npm source package has unreviewed fields or a version")
		}
	}
	var name, license string
	var private bool
	var engines, bin map[string]string
	var files []string
	if json.Unmarshal(p["name"], &name) != nil || name != "@telaralabs/hilo" || json.Unmarshal(p["private"], &private) != nil || !private ||
		json.Unmarshal(p["license"], &license) != nil || license != "Apache-2.0" || json.Unmarshal(p["engines"], &engines) != nil || len(engines) != 1 || (engines["node"] != ">=22" && engines["node"] != ">=22.0.0") ||
		json.Unmarshal(p["bin"], &bin) != nil || len(bin) != 2 || (bin["hilo"] != "bin/hilo.cjs" && bin["hilo"] != "./bin/hilo.cjs") || bin["telara-memory"] != bin["hilo"] ||
		json.Unmarshal(p["files"], &files) != nil || !equalSet(files, packageFiles) {
		return nil, errors.New("npm source package contract mismatch")
	}
	if raw, ok := p["description"]; ok {
		var description string
		if json.Unmarshal(raw, &description) != nil || len(description) > 1024 {
			return nil, errors.New("npm source package description invalid")
		}
	}
	if raw, ok := p["repository"]; ok {
		var url string
		if json.Unmarshal(raw, &url) != nil {
			var repo map[string]string
			if json.Unmarshal(raw, &repo) != nil || len(repo) != 2 || repo["type"] != "git" || repo["url"] == "" {
				return nil, errors.New("npm source package repository invalid")
			}
			url = repo["url"]
		}
		if url != "https://github.com/"+repository && url != "https://github.com/"+repository+".git" && url != "git+https://github.com/"+repository+".git" {
			return nil, errors.New("npm source package repository mismatch")
		}
	}
	p["version"], _ = json.Marshal(version)
	return canonicalJSON(p)
}
func equalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// Reject duplicate object keys (including nested scripts/bin objects), trailing
// values and excessive nesting before ordinary JSON decoding loses information.
func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errMetadata
		}
		token, err := d.Token()
		if err != nil {
			return errMetadata
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		seen := map[string]bool{}
		for d.More() {
			if delim == '{' {
				k, err := d.Token()
				key, ok := k.(string)
				if err != nil || !ok || seen[key] {
					return errMetadata
				}
				seen[key] = true
			}
			if err := value(depth + 1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
			return errMetadata
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errMetadata
	}
	return nil
}

func statNumber(info os.FileInfo, name string) (uint64, bool) {
	v := reflect.ValueOf(info.Sys())
	if !v.IsValid() {
		return 0, false
	}
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0, false
	}
	x := v.FieldByName(name)
	if !x.IsValid() || !x.CanUint() {
		return 0, false
	}
	return x.Uint(), true
}
func safeMode(info os.FileInfo) bool {
	return info.Mode().Perm()&0022 == 0 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}
func safeDirectory(info os.FileInfo, stickyRoot bool) bool {
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return false
	}
	if info.Mode()&os.ModeSticky != 0 {
		return stickyRoot
	}
	return info.Mode().Perm()&0022 == 0
}
func within(root, name string) bool {
	rel, err := filepath.Rel(root, name)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func guardDirectory(dir string) (*directoryGuard, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, errUnsafe
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errUnsafe
	}
	owner, ok := statNumber(info, "Uid")
	if !ok {
		return nil, errUnsafe
	}
	g := &directoryGuard{Root: dir, Owner: owner}
	var paths []string
	for p := dir; ; p = filepath.Dir(p) {
		paths = append(paths, p)
		if filepath.Dir(p) == p {
			break
		}
	}
	for i := len(paths) - 1; i >= 0; i-- {
		p := paths[i]
		st, err := os.Lstat(p)
		uid, ok := uint64(0), false
		if err == nil {
			uid, ok = statNumber(st, "Uid")
		}
		stickyRoot := p != dir && uid == 0 && st != nil && st.Mode()&os.ModeSticky != 0
		if err != nil || !ok || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (uid != 0 && uid != owner) || !safeDirectory(st, stickyRoot) {
			return nil, errUnsafe
		}
		g.Dirs = append(g.Dirs, snapshot{p, st})
	}
	return g, nil
}
func (g *directoryGuard) checkThrough(name string) error {
	for _, s := range g.Dirs {
		if name != "" && s.Path != name && !within(s.Path, filepath.Dir(name)) {
			continue
		}
		st, err := os.Lstat(s.Path)
		if err != nil || !os.SameFile(s.Info, st) || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errUnsafe
		}
		uid, ok := statNumber(st, "Uid")
		oldUID, _ := statNumber(s.Info, "Uid")
		stickyRoot := uid == 0 && st.Mode()&os.ModeSticky != 0 && s.Path != g.Root && !within(g.Root, s.Path)
		if !ok || uid != oldUID || !safeDirectory(st, stickyRoot) {
			return errUnsafe
		}
	}
	return nil
}
func (g *directoryGuard) check() error { return g.checkThrough("") }
func (g *directoryGuard) addDirectory(dir string) error {
	if !within(g.Root, dir) || dir == g.Root {
		return errUnsafe
	}
	if err := g.check(); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || !safeMode(st) || st.Mode()&(os.ModeSymlink|os.ModeSticky) != 0 {
		return errUnsafe
	}
	uid, ok := statNumber(st, "Uid")
	if !ok || uid != g.Owner {
		return errUnsafe
	}
	g.Dirs = append(g.Dirs, snapshot{dir, st})
	return nil
}
func (g *directoryGuard) fileInfo(path string, limit int64) (os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !within(g.Root, path) || path == g.Root {
		return nil, errUnsafe
	}
	if err := g.check(); err != nil {
		return nil, err
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || !safeMode(st) || st.Size() < 0 || st.Size() > limit {
		return nil, errUnsafe
	}
	uid, ok := statNumber(st, "Uid")
	links, linkOK := statNumber(st, "Nlink")
	if !ok || !linkOK || uid != g.Owner || links != 1 {
		return nil, errUnsafe
	}
	return st, nil
}
func (g *directoryGuard) read(name string, limit int64) ([]byte, error) {
	root := g.Root
	// Every caller supplies a fixed reviewed name. Resolve its intermediate
	// directory explicitly rather than allowing symlink traversal by Open.
	if !filepath.IsLocal(name) || filepath.Clean(name) != name {
		return nil, errUnsafe
	}
	path := filepath.Join(root, name)
	for p := filepath.Dir(name); p != "."; p = filepath.Dir(p) {
		if err := g.addDirectory(filepath.Join(root, p)); err != nil {
			return nil, err
		}
	}
	before, err := g.fileInfo(path, limit)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errUnsafe
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errUnsafe
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	current, currentErr := g.fileInfo(path, limit)
	if err != nil || statErr != nil || currentErr != nil || int64(len(b)) != before.Size() || !os.SameFile(before, after) || !os.SameFile(after, current) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, errUnsafe
	}
	return b, nil
}

// publish reserves output before writing. package.json is the final commit
// marker. There is no rename over an existing destination, even an empty one.
func publish(input prepared, output string) error {
	return publishWithDirectorySync(input, output, syncGuardedDirectory)
}

// The private callback permits deterministic sync-failure tests. The CLI has no
// sync override and always uses validated real directory descriptors.
func publishWithDirectorySync(input prepared, output string, syncDir func(*directoryGuard, string) error) (result error) {
	want := map[string]bool{"package.json": true, "release-spec.json": true, "release/BUILD.json": true, "release/SHA256SUMS": true, "release/RELEASE.sig": true, "release/release-key.pub": true}
	for _, name := range sourceFiles {
		want[name] = true
	}
	if len(input.Files) != len(want) {
		return errors.New("npm staging output allowlist mismatch")
	}
	for name, data := range input.Files {
		if !want[name] || len(data) == 0 || len(data) > 1<<20 {
			return errors.New("npm staging output allowlist mismatch")
		}
	}
	parent, err := guardDirectory(filepath.Dir(output))
	if err != nil {
		return err
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return errors.New("npm staging output already exists or cannot be reserved")
	}
	guard, err := guardDirectory(output)
	if err != nil {
		return err
	}
	created := []snapshot{{output, guard.Dirs[len(guard.Dirs)-1].Info}}
	committed := false
	defer func() {
		if committed {
			return
		}
		rollbackCreated(parent, guard, created)
	}()
	for _, dir := range []string{"bin", "lib", "release"} {
		p := filepath.Join(output, dir)
		if parent.check() != nil || guard.check() != nil || os.Mkdir(p, 0700) != nil {
			return errUnsafe
		}
		if err := guard.addDirectory(p); err != nil {
			return err
		}
		created = append(created, guard.Dirs[len(guard.Dirs)-1])
	}
	var names []string
	for name := range input.Files {
		if name != "package.json" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	names = append(names, "package.json")
	for _, name := range names {
		if !filepath.IsLocal(name) || filepath.Clean(name) != name || parent.check() != nil || guard.check() != nil {
			return errUnsafe
		}
		p := filepath.Join(output, name)
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errUnsafe
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return errUnsafe
		}
		created = append(created, snapshot{p, info})
		_, writeErr := f.Write(input.Files[name])
		mode := os.FileMode(0444)
		if name == "bin/hilo.cjs" {
			mode = 0555
		}
		if writeErr == nil {
			writeErr = f.Chmod(mode)
		}
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		st, statErr := guard.fileInfo(p, 1<<20)
		if writeErr != nil || closeErr != nil || statErr != nil || !os.SameFile(info, st) || st.Size() != int64(len(input.Files[name])) {
			return errUnsafe
		}
	}
	for i := len(guard.Dirs) - 1; i >= 0; i-- {
		dir := guard.Dirs[i].Path
		if !within(output, dir) {
			continue
		}
		if guard.check() != nil || os.Chmod(dir, 0755) != nil {
			return errUnsafe
		}
		if err := syncDir(guard, dir); err != nil {
			return err
		}
	}
	// The output directory's own sync does not commit its name in the parent.
	// Failure leaves committed false and invokes only identity-scoped cleanup;
	// cleanup durability after failure is not claimed.
	if err := syncDir(parent, parent.Root); err != nil {
		return err
	}
	if parent.check() != nil || guard.check() != nil {
		return errUnsafe
	}
	committed = true
	return nil
}

func syncGuardedDirectory(g *directoryGuard, dir string) error {
	if g.check() != nil {
		return errUnsafe
	}
	var saved os.FileInfo
	for _, s := range g.Dirs {
		if s.Path == dir {
			saved = s.Info
			break
		}
	}
	if saved == nil {
		return errUnsafe
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	opened, statErr := f.Stat()
	if statErr != nil || !os.SameFile(saved, opened) || !opened.IsDir() || g.check() != nil {
		_ = f.Close()
		return errUnsafe
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil || closeErr != nil {
		return errors.Join(syncErr, closeErr)
	}
	return g.check()
}

func rollbackCreated(parent, guard *directoryGuard, created []snapshot) {
	for i := len(created) - 1; i >= 0; i-- {
		s := created[i]
		if parent.check() != nil || guard.checkThrough(s.Path) != nil {
			continue
		}
		st, err := os.Lstat(s.Path)
		if err == nil && os.SameFile(s.Info, st) {
			// Remove only this attempt's exact inode. A foreign extra file
			// makes directory removal fail; it is never recursively erased.
			_ = os.Remove(s.Path)
		}
	}
}
