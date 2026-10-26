// Command release builds unsigned local artifacts only. It never publishes,
// signs, changes Git, or reads a signing key. Production input is a clean tag
// exported through git archive. --development explicitly produces UNVERIFIED
// artifacts from a source directory for local gates before a lead commits it.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/releaseauth"
)

type target struct{ OS, Arch string }

var targets = []target{{"darwin", "amd64"}, {"darwin", "arm64"}, {"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}}

type config struct {
	Source, Out string
	Development bool
	Tag         string
}
type provenance struct {
	Format       int    `json:"format"`
	Source       string `json:"source"`
	Toolchain    string `json:"toolchain"`
	Verification string `json:"verification"`
	Signed       bool   `json:"signed"`
}

func main() {
	if e := run(context.Background(), os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("release", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	c := config{}
	verify := f.String("verify", "", "Verify a release directory against the compiled project key")
	signingKey := f.String("signing-key", "", "Private PKCS8 Ed25519 project release key")
	f.StringVar(&c.Source, "source", ".", "Repository root, or module root with --development")
	f.StringVar(&c.Out, "out", "", "New output directory")
	f.StringVar(&c.Tag, "tag", "", "Exact release tag to export")
	f.BoolVar(&c.Development, "development", false, "Unsigned UNVERIFIED build of uncommitted source")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return errors.New("invalid release arguments")
	}
	if *verify != "" {
		if c.Out != "" || *signingKey != "" || c.Tag != "" || c.Development {
			return errors.New("verification cannot build or sign")
		}
		p, err := releaseauth.Verify(*verify)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(p)
	}
	if c.Out == "" || c.Development && *signingKey != "" {
		return errors.New("usage release --source DIR --out NEW_DIR --tag TAG, or --development")
	}
	var e error
	c.Source, e = filepath.Abs(c.Source)
	if e != nil {
		return e
	}
	c.Out, e = filepath.Abs(c.Out)
	if e != nil {
		return e
	}
	if inside(c.Source, c.Out) {
		return errors.New("output must be outside source")
	}
	if c.Development {
		if c.Tag != "" {
			return errors.New("development builds cannot claim a release tag")
		}
		// Verify and compile a private source copy. Go module commands cannot
		// modify the caller's development checkout even when checksums are missing.
		dir, e := os.MkdirTemp("", "memory-release-development-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(dir)
		if e = copySource(c.Source, dir); e != nil {
			return e
		}
		c.Source = dir
	} else {
		if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$`).MatchString(c.Tag) {
			return errors.New("exact version tag required")
		}
		var cleanup func()
		c.Source, cleanup, e = exportTag(ctx, c.Source, c.Tag)
		if e != nil {
			return e
		}
		defer cleanup()
	}
	if e = build(ctx, c); e != nil {
		return e
	}
	if *signingKey != "" {
		if e = signRelease(c.Out, *signingKey); e != nil {
			return e
		}
	}
	return json.NewEncoder(out).Encode(map[string]any{"out": c.Out, "artifacts": 6, "signed": *signingKey != "", "development": c.Development})
}

func signRelease(dir, path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return errors.New("private project signing key required")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("signing key changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return errors.New("invalid signing key")
	}
	defer clear(b)
	p, rest := pem.Decode(b)
	if p == nil || len(rest) != 0 {
		return errors.New("invalid signing key")
	}
	defer clear(p.Bytes)
	k, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return errors.New("invalid signing key")
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return errors.New("Ed25519 signing key required")
	}
	defer clear(key)
	return releaseauth.Sign(dir, key)
}
func copySource(source, target string) error {
	return filepath.WalkDir(source, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		r, e := filepath.Rel(source, path)
		if e != nil {
			return e
		}
		out := filepath.Join(target, r)
		if d.IsDir() {
			return os.MkdirAll(out, 0700)
		}
		if !d.Type().IsRegular() {
			return os.ErrInvalid
		}
		in, e := os.Open(path)
		if e != nil {
			return e
		}
		defer in.Close()
		f, e := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = io.Copy(f, in)
		ce := f.Close()
		if e != nil {
			return e
		}
		return ce
	})
}

func inside(parent, child string) bool {
	r, e := filepath.Rel(parent, child)
	return e == nil && (r == "." || r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)))
}
func git(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Stderr = io.Discard
	b, e := cmd.Output()
	if e != nil {
		return nil, errors.New("source verification failed")
	}
	return b, nil
}
func exportTag(ctx context.Context, repo, tag string) (string, func(), error) {
	b, e := git(ctx, repo, "status", "--porcelain", "--untracked-files=all")
	if e != nil || len(b) != 0 {
		return "", nil, errors.New("release requires clean tagged source")
	}
	head, e := git(ctx, repo, "rev-parse", "HEAD")
	if e != nil {
		return "", nil, e
	}
	commit, e := git(ctx, repo, "rev-parse", "refs/tags/"+tag+"^{commit}")
	if e != nil || !bytes.Equal(head, commit) {
		return "", nil, errors.New("release tag must name clean HEAD")
	}
	archive, e := git(ctx, repo, "archive", "--format=tar", "refs/tags/"+tag)
	if e != nil {
		return "", nil, e
	}
	dir, e := os.MkdirTemp("", "memory-release-source-")
	if e != nil {
		return "", nil, e
	}
	cleanup := func() { os.RemoveAll(dir) }
	if e = extract(archive, dir); e != nil {
		cleanup()
		return "", nil, e
	}
	return filepath.Join(dir, "contract"), cleanup, nil
}
func extract(data []byte, dir string) error {
	t := tar.NewReader(bytes.NewReader(data))
	var total int64
	for {
		h, e := t.Next()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		name := filepath.FromSlash(h.Name)
		path := filepath.Join(dir, name)
		if !inside(dir, path) || filepath.IsAbs(name) || strings.Contains(name, "\\") || h.Size < 0 || h.Size > 64<<20 {
			return errors.New("unsafe source archive")
		}
		total += h.Size
		if total > 512<<20 {
			return errors.New("source archive too large")
		}
		switch h.Typeflag {
		case tar.TypeXGlobalHeader:
			// git archive records its commit ID in a global PAX comment.
			// This header creates no filesystem entry.
			continue
		case tar.TypeDir:
			if e = os.MkdirAll(path, 0755); e != nil {
				return e
			}
		case tar.TypeReg:
			if e = os.MkdirAll(filepath.Dir(path), 0755); e != nil {
				return e
			}
			f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if e != nil {
				return e
			}
			_, e = io.CopyN(f, t, h.Size)
			ce := f.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		default:
			return errors.New("source archive contains a link or special file")
		}
	}
}

// Release toolchain selection is explicit and independent of caller and saved
// Go configuration. Updating this pin requires a release-source review.
const releaseToolchain = "go1.26.1"

func compilerRoot() string {
	if runtime.GOOS == "windows" {
		return `C:\Program Files\Go`
	}
	return "/usr/local/go"
}
func goEnv(platform, arch, inputs string) []string {
	vars := map[string]string{
		"GOENV": "off", "GOTOOLCHAIN": "local", "GOROOT": compilerRoot(),
		"GOWORK": "off", "GOOS": platform, "GOARCH": arch, "CGO_ENABLED": "0",
		"GOFLAGS": "-mod=readonly", "GOEXPERIMENT": "", "GOAMD64": "v1", "GOARM64": "v8.0",
		"GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org",
		"GONOSUMDB": "none", "GONOPROXY": "none", "GOPRIVATE": "none", "GOVCS": "*:off", "GOAUTH": "off",
		"GOMODCACHE": filepath.Join(inputs, "modules"), "GOCACHE": filepath.Join(inputs, "build-cache"),
		"GOPATH": filepath.Join(inputs, "gopath"), "GOTMPDIR": filepath.Join(inputs, "tmp"),
	}
	// Allow OS necessities only, never arbitrary module, compiler or overlay inputs.
	env := []string{}
	for _, k := range []string{"HOME", "USERPROFILE", "SystemRoot", "WINDIR", "TMPDIR", "TEMP", "TMP"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	vars["PATH"] = filepath.Join(compilerRoot(), "bin") + string(os.PathListSeparator) + "/usr/bin" + string(os.PathListSeparator) + "/bin"
	keys := []string{}
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+vars[k])
	}
	return env
}
func goCommand(ctx context.Context, source string, env []string, args ...string) ([]byte, error) {
	path := filepath.Join(compilerRoot(), "bin", "go")
	if runtime.GOOS == "windows" {
		path += ".exe"
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = source
	cmd.Env = env
	return cmd.CombinedOutput()
}

// Module downloads make cache trees read-only. Restore permissions only inside
// the private directory allocated by this build; never follow cache symlinks.
func removeInputs(dir string) error {
	if e := filepath.WalkDir(dir, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return os.Chmod(path, 0700)
		}
		if d.Type().IsRegular() {
			return os.Chmod(path, 0600)
		}
		return nil
	}); e != nil {
		return e
	}
	return os.RemoveAll(dir)
}
func verifyModules(ctx context.Context, source, inputs string) error {
	env := goEnv(runtime.GOOS, runtime.GOARCH, inputs)
	b, e := goCommand(ctx, source, env, "version")
	if e != nil || strings.TrimSpace(string(b)) != "go version "+releaseToolchain+" "+runtime.GOOS+"/"+runtime.GOARCH {
		return errors.New("pinned release compiler required")
	}
	original := map[string][]byte{}
	for _, name := range []string{"go.mod", "go.sum"} {
		b, e := os.ReadFile(filepath.Join(source, name))
		if e != nil {
			return e
		}
		original[name] = b
	}
	// Fresh private module and build caches never consume the caller's extracted
	// trees, ziphash metadata, objects or a caller-selected file proxy.
	b, e = goCommand(ctx, source, env, "mod", "download", "-json")
	if e != nil {
		return fmt.Errorf("pinned module download failed: %s", b)
	}
	if e = verifyModuleReceipts(b, original["go.sum"]); e != nil {
		return e
	}

	if b, e = goCommand(ctx, source, env, "mod", "verify"); e != nil {
		return fmt.Errorf("module verification failed: %s", b)
	}
	for name, want := range original {
		got, e := os.ReadFile(filepath.Join(source, name))
		if e != nil || !bytes.Equal(got, want) {
			return errors.New("module pins changed during verification")
		}
	}
	return nil
}
func verifyModuleReceipts(data, pins []byte) error {
	sums := map[string]string{}
	for _, line := range strings.Split(string(pins), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 {
			key := f[0] + " " + f[1]
			if old, ok := sums[key]; ok && old != f[2] {
				return errors.New("conflicting module checksums")
			}
			sums[key] = f[2]
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var m struct {
			Path, Version, Sum, GoModSum string
			Error                        *json.RawMessage
		}
		e := decoder.Decode(&m)
		if e == io.EOF {
			break
		}
		if e != nil {
			return errors.New("invalid module download receipt")
		}
		if m.Error != nil || m.Sum == "" || m.GoModSum == "" || sums[m.Path+" "+m.Version] != m.Sum || sums[m.Path+" "+m.Version+"/go.mod"] != m.GoModSum {
			return fmt.Errorf("module input missing from pinned go.sum: %s %s", m.Path, m.Version)
		}
	}
	return nil
}
func build(ctx context.Context, c config) error {
	for _, file := range []string{"go.mod", "go.sum"} {
		if st, e := os.Stat(filepath.Join(c.Source, file)); e != nil || !st.Mode().IsRegular() {
			return errors.New("pinned module files required")
		}
	}
	mod, e := os.ReadFile(filepath.Join(c.Source, "go.mod"))
	if e != nil {
		return e
	}
	// Replacement and moving local module inputs cannot enter a release.
	for _, line := range strings.Split(string(mod), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "//", 2)[0])
		words := strings.Fields(line)
		if len(words) > 0 && (words[0] == "replace" || strings.HasPrefix(words[0], "replace(")) {
			return errors.New("module replacements forbidden")
		}
	}
	if _, e = os.Lstat(c.Out); !os.IsNotExist(e) {
		return errors.New("output directory must not exist")
	}
	if e = os.Mkdir(c.Out, 0700); e != nil {
		return e
	}
	complete := false
	defer func() {
		if !complete {
			os.RemoveAll(c.Out)
		}
	}()
	inputs, e := os.MkdirTemp("", "memory-release-inputs-")
	if e != nil {
		return e
	}
	defer removeInputs(inputs)
	if e = os.Mkdir(filepath.Join(inputs, "tmp"), 0700); e != nil {
		return e
	}
	if e = verifyModules(ctx, c.Source, inputs); e != nil {
		return e
	}
	var sums strings.Builder
	for _, t := range targets {
		name := "telara-memory-" + t.OS + "-" + t.Arch
		if t.OS == "windows" {
			name += ".exe"
		}
		path := filepath.Join(c.Out, name)
		b, e := goCommand(ctx, c.Source, goEnv(t.OS, t.Arch, inputs), "build", "-p", "2", "-trimpath", "-buildvcs=false", "-mod=readonly", "-ldflags=-buildid=", "-o", path, "./cmd/telara-memory")
		if e != nil {
			return fmt.Errorf("build %s/%s failed: %s", t.OS, t.Arch, b)
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		h := sha256.New()
		_, e = io.Copy(h, f)
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h.Sum(nil)), name)
	}
	if e = os.WriteFile(filepath.Join(c.Out, "SHA256SUMS"), []byte(sums.String()), 0600); e != nil {
		return e
	}
	state := "clean-tag-export-unsigned"
	if c.Development {
		state = "UNVERIFIED-development-unsigned"
	}
	b, e := json.MarshalIndent(provenance{1, c.Tag, releaseToolchain, state, false}, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(c.Out, "BUILD.json"), append(b, '\n'), 0600); e != nil {
		return e
	}
	complete = true
	return nil
}
