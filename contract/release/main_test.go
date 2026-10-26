package main

import (
	"archive/tar"
	"bytes"
	"context"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var reproSource = flag.String("release-source", "", "Frozen module source for real six-target, two-build reproducibility gate")

func TestReproducibleRelease(t *testing.T) {
	if *reproSource == "" {
		t.Skip("explicit -release-source module snapshot required")
	}
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	copyRoot := filepath.Join(dir, "independent-source-path")
	if e := os.Mkdir(copyRoot, 0700); e != nil {
		t.Fatal(e)
	}
	if e := copySource(*reproSource, copyRoot); e != nil {
		t.Fatal(e)
	}
	for i, out := range []string{first, second} {
		source := *reproSource
		if i == 1 {
			source = copyRoot
		}
		var report bytes.Buffer
		if e := run(context.Background(), []string{"--development", "--source", source, "--out", out}, &report); e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(report.String(), `"signed":false`) {
			t.Fatal(report.String())
		}
	}
	a, e := os.ReadFile(filepath.Join(first, "SHA256SUMS"))
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(second, "SHA256SUMS"))
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("reproducibility mismatch\n%s\n%s", a, b)
	}
	if len(strings.Split(strings.TrimSpace(string(a)), "\n")) != 6 {
		t.Fatal("missing target")
	}
	t.Logf("two builds, identical six-target sums\n%s", a)
}

func TestRejectReplacementAndExistingOutput(t *testing.T) {
	for _, replacement := range []string{"replace foo => ../foo", "replace\tfoo => ../foo", "replace (\nfoo => ../foo\n)"} {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, "go.mod"), []byte("module fixture\n\n"+replacement), 0600)
		os.WriteFile(filepath.Join(d, "go.sum"), nil, 0600)
		if e := build(context.Background(), config{Source: d, Out: filepath.Join(d, "out")}); e == nil || !strings.Contains(e.Error(), "replacements") {
			t.Fatal(e)
		}
	}
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "go.mod"), []byte("module fixture\n"), 0600)
	os.WriteFile(filepath.Join(d, "go.sum"), nil, 0600)
	if e := build(context.Background(), config{Source: d, Out: d}); e == nil {
		t.Fatal("overwrote existing output")
	}
}

func TestExtractRejectsArchiveAttacks(t *testing.T) {
	for _, h := range []tar.Header{{Name: "../escape", Typeflag: tar.TypeReg}, {Name: "/absolute", Typeflag: tar.TypeReg}, {Name: "C:/absolute", Typeflag: tar.TypeReg}, {Name: "C:relative", Typeflag: tar.TypeReg}, {Name: `\absolute`, Typeflag: tar.TypeReg}, {Name: `\\server\share`, Typeflag: tar.TypeReg}, {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/tmp"}, {Name: "hard", Typeflag: tar.TypeLink, Linkname: "other"}, {Name: "pipe", Typeflag: tar.TypeFifo}} {
		var b bytes.Buffer
		w := tar.NewWriter(&b)
		if e := w.WriteHeader(&h); e != nil {
			t.Fatal(e)
		}
		w.Close()
		if e := extract(b.Bytes(), t.TempDir()); e == nil {
			t.Fatalf("accepted %#v", h)
		}
	}
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	w.WriteHeader(&tar.Header{Name: "contract/go.mod", Typeflag: tar.TypeReg, Size: 4})
	w.Write([]byte("test"))
	w.Close()
	d := t.TempDir()
	if e := extract(b.Bytes(), d); e != nil {
		t.Fatal(e)
	}
	if x, e := os.ReadFile(filepath.Join(d, "contract", "go.mod")); e != nil || string(x) != "test" {
		t.Fatal(e)
	}
}
func TestReleaseArgumentsAndInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"--tag", "not-a-tag", "--out", "/tmp/out"}, {"--development", "--tag", "v1.2.3", "--out", "/tmp/out"}, {"--development", "--source", ".", "--out", "./out"}} {
		if e := run(context.Background(), args, &bytes.Buffer{}); e == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	d := t.TempDir()
	if e := build(context.Background(), config{Source: d, Out: filepath.Join(d, "out")}); e == nil {
		t.Fatal("accepted missing module")
	}
}
func TestGoToolchainControls(t *testing.T) {
	seen := map[string]string{}
	for _, s := range goEnv("windows", "arm64", t.TempDir()) {
		k, v, _ := strings.Cut(s, "=")
		if _, ok := seen[k]; ok {
			t.Fatal("duplicate env", k)
		}
		seen[k] = v
	}
	for k, v := range map[string]string{"GOWORK": "off", "GOOS": "windows", "GOARCH": "arm64", "CGO_ENABLED": "0", "GOAMD64": "v1", "GOARM64": "v8.0"} {
		if seen[k] != v {
			t.Fatal(k, seen[k])
		}
	}
}

var cleanTagCommit = flag.String("release-commit", "HEAD", "Existing commit to reuse in the clean-tag fixture")

var cleanTagRepo = flag.String("release-repository", "", "Existing repository whose HEAD is used for an isolated clean-tag fixture")

// This fixture reuses an existing commit object. It never creates a commit,
// changes the shared index/refs, or checks out another implementation tree.
func cleanTagFixture(t *testing.T, repo string) string {
	t.Helper()
	ctx := context.Background()
	head, e := git(ctx, repo, "rev-parse", *cleanTagCommit+"^{commit}")
	if e != nil {
		t.Fatal(e)
	}
	objects, e := git(ctx, repo, "rev-parse", "--git-path", "objects")
	if e != nil {
		t.Fatal(e)
	}
	objectPath := strings.TrimSpace(string(objects))
	if !filepath.IsAbs(objectPath) {
		objectPath = filepath.Join(repo, objectPath)
	}
	archive, e := git(ctx, repo, "archive", "--format=tar", strings.TrimSpace(string(head)))
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	if e = extract(archive, dir); e != nil {
		t.Fatal(e)
	}
	gd := filepath.Join(dir, ".git")
	for _, sub := range []string{"objects/info", "refs/tags"} {
		if e = os.MkdirAll(filepath.Join(gd, sub), 0700); e != nil {
			t.Fatal(e)
		}
	}
	for name, b := range map[string][]byte{"HEAD": head, "refs/tags/v0.0.0-adversarial": head, "objects/info/alternates": []byte(objectPath + "\n"), "config": []byte("[core]\n repositoryformatversion = 0\n bare = false\n autocrlf = false\n")} {
		if e = os.WriteFile(filepath.Join(gd, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	// Populate only the temporary fixture index, without checkout or commit.
	if _, e = git(ctx, dir, "read-tree", strings.TrimSpace(string(head))); e != nil {
		t.Fatal(e)
	}
	if b, e := git(ctx, dir, "status", "--porcelain", "--untracked-files=all"); e != nil || len(b) != 0 {
		t.Fatalf("unclean fixture %v %s", e, b)
	}
	t.Logf("clean-tag fixture reuses existing commit %s", strings.TrimSpace(string(head)))
	return dir
}
func TestAdversarialCleanTagRelease(t *testing.T) {
	if *cleanTagRepo == "" {
		t.Skip("explicit -release-repository required")
	}
	repo := cleanTagFixture(t, *cleanTagRepo)
	outRoot := t.TempDir()
	baseline := filepath.Join(outRoot, "baseline")
	if e := run(context.Background(), []string{"--source", repo, "--tag", "v0.0.0-adversarial", "--out", baseline}, io.Discard); e != nil {
		t.Fatal(e)
	}
	attack := t.TempDir()
	// An extracted module cache is trusted by ordinary go build without rehashing
	// it. Poison a dependency that is in the daemon's actual import graph.
	cache := filepath.Join(attack, "cache")
	poisoned := filepath.Join(cache, "golang.org/x/sys@v0.48.0", "unix")
	if e := os.MkdirAll(poisoned, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(poisoned, "poison.go"), []byte("package unix\nthis is poisoned module source\n"), 0600); e != nil {
		t.Fatal(e)
	}
	alternate := filepath.Join(attack, "alternate.mod")
	if e := os.WriteFile(alternate, []byte("module hostile\ngo 1.26.0\nreplace golang.org/x/sys => "+filepath.Dir(poisoned)+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	overlay := filepath.Join(attack, "overlay.json")
	if e := os.WriteFile(overlay, []byte(`{"Replace":{}}`), 0600); e != nil {
		t.Fatal(e)
	}
	flags := "-modfile=" + alternate + " -overlay=" + overlay + " -toolexec=" + filepath.Join(attack, "hostile-tool")
	saved := filepath.Join(attack, "goenv")
	if e := os.WriteFile(saved, []byte("GOFLAGS="+flags+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("GOENV", saved)
	t.Setenv("GOFLAGS", "") // Reproduces saved-GOFLAGS fallback in the original builder.
	// Confirm this is an effective saved-config attack, not an inert fixture.
	probe := exec.Command(filepath.Join(compilerRoot(), "bin", "go"), "env", "GOFLAGS")
	probe.Env = os.Environ()
	b, e := probe.Output()
	if e != nil || strings.TrimSpace(string(b)) != flags {
		t.Fatalf("ineffective poison fixture %s %v", b, e)
	}
	for k, v := range map[string]string{"GOMODCACHE": cache, "GOCACHE": filepath.Join(attack, "objects"), "GOPROXY": "file://" + cache, "GONOSUMDB": "*", "GOPRIVATE": "*", "GONOPROXY": "*", "GOSUMDB": "off", "GOWORK": filepath.Join(attack, "go.work"), "CGO_ENABLED": "1", "GOTOOLCHAIN": "hostile", "GOROOT": attack, "GOEXPERIMENT": "hostile", "GOAMD64": "v4", "GOARM64": "v9.0"} {
		t.Setenv(k, v)
	}
	attacked := filepath.Join(outRoot, "attacked")
	if e = run(context.Background(), []string{"--source", repo, "--tag", "v0.0.0-adversarial", "--out", attacked}, io.Discard); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"SHA256SUMS", "BUILD.json"} {
		a, e := os.ReadFile(filepath.Join(baseline, name))
		if e != nil {
			t.Fatal(e)
		}
		b, e := os.ReadFile(filepath.Join(attacked, name))
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("poison changed %s\n%s\n%s", name, a, b)
		}
		t.Logf("identical clean-tag %s\n%s", name, a)
	}
	// Exercise hostile process flags too. The allowlist must remove them even
	// when nonempty; saved config alone was exercised by the actual builds.
	t.Setenv("GOFLAGS", flags)
	for _, entry := range goEnv(runtime.GOOS, runtime.GOARCH, t.TempDir()) {
		if strings.HasPrefix(entry, "GOFLAGS=") && entry != "GOFLAGS=-mod=readonly" {
			t.Fatal(entry)
		}
	}
}
func TestGoEnvironmentIgnoresExternalControls(t *testing.T) {
	for k, v := range map[string]string{"GOENV": "hostile", "GOROOT": "hostile", "GOTOOLCHAIN": "hostile", "GOFLAGS": "-modfile=hostile -overlay=hostile -toolexec=hostile", "GOMODCACHE": "hostile", "GOPROXY": "file:///hostile", "GONOSUMDB": "*", "GOSUMDB": "off", "CGO_ENABLED": "1", "GOWORK": "hostile", "CC": "hostile", "GOGCCFLAGS": "hostile"} {
		t.Setenv(k, v)
	}
	inputs := t.TempDir()
	m := map[string]string{}
	for _, entry := range goEnv("linux", "amd64", inputs) {
		k, v, _ := strings.Cut(entry, "=")
		m[k] = v
		if strings.Contains(v, "hostile") {
			t.Fatal("inherited external input", entry)
		}
	}
	for k, want := range map[string]string{"GOENV": "off", "GOTOOLCHAIN": "local", "GOROOT": compilerRoot(), "GOFLAGS": "-mod=readonly", "GOWORK": "off", "CGO_ENABLED": "0", "GOPROXY": "https://proxy.golang.org", "GONOSUMDB": "none", "GOSUMDB": "sum.golang.org", "GOMODCACHE": filepath.Join(inputs, "modules")} {
		if m[k] != want {
			t.Fatal(k, m[k])
		}
	}
}

func TestModuleReceiptsRequireBothPinnedChecksums(t *testing.T) {
	pins := []byte("example.org/dep v1.0.0 h1:archive\nexample.org/dep v1.0.0/go.mod h1:modfile\n")
	good := `{"Path":"example.org/dep","Version":"v1.0.0","Sum":"h1:archive","GoModSum":"h1:modfile"}`
	if e := verifyModuleReceipts([]byte(good), pins); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(good, "h1:archive", "h1:poison", 1), strings.Replace(good, "h1:modfile", "h1:poison", 1), strings.Replace(good, "v1.0.0", "v1.0.1", 1), `{"Path":"example.org/dep","Error":{"Err":"download failed"}}`, "not-json"} {
		if e := verifyModuleReceipts([]byte(bad), pins); e == nil {
			t.Fatal("accepted unchecked input", bad)
		}
	}
	if e := verifyModuleReceipts([]byte(good), append(pins, []byte("example.org/dep v1.0.0 h1:poison\n")...)); e == nil {
		t.Fatal("accepted conflicting pin")
	}
}

func TestRemovePrivateReadOnlyModuleCache(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "inputs")
	module := filepath.Join(cache, "modules", "example.org/dep@v1.0.0", "nested")
	if e := os.MkdirAll(module, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(module, "source.go"), []byte("package dep\n"), 0400); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(root, "unrelated")
	if e := os.Mkdir(outside, 0700); e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(outside, "keep")
	t.Cleanup(func() { _ = os.Chmod(marker, 0600) })
	if e := os.WriteFile(marker, []byte("unchanged"), 0400); e != nil {
		t.Fatal(e)
	}
	if runtime.GOOS != "windows" {
		if e := os.Symlink(outside, filepath.Join(cache, "link")); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Chmod(module, 0500); e != nil {
		t.Fatal(e)
	}
	if e := removeInputs(cache); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(cache); !os.IsNotExist(e) {
		t.Fatal("retained cache", e)
	}
	if b, e := os.ReadFile(marker); e != nil || string(b) != "unchanged" {
		t.Fatal("changed external target", e)
	}
	if st, e := os.Stat(marker); e != nil || st.Mode().Perm()&0200 != 0 {
		t.Fatal("followed cache symlink", e)
	}
}
