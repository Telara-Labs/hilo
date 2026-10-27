package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

var reproSource = flag.String("release-source", "", "Frozen runtime module source for real six-target, two-build reproducibility gate")

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

func TestDualFamilyRequiresSignedRelease(t *testing.T) {
	for _, args := range [][]string{
		{"--dual-family", "--development", "--out", filepath.Join(t.TempDir(), "out")},
		{"--dual-family", "--tag", "v1.2.3", "--out", filepath.Join(t.TempDir(), "out")},
		{"--dual-family", "--verify", t.TempDir()},
	} {
		if err := run(context.Background(), args, io.Discard); err == nil {
			t.Fatalf("accepted unsigned or incompatible dual-family arguments %v", args)
		}
	}
}

func TestWriteFamilyCreatesSeparateSixTargetSetsWithIdenticalBinaries(t *testing.T) {
	root := t.TempDir()
	buildDir := filepath.Join(root, "built")
	if err := os.Mkdir(buildDir, 0700); err != nil {
		t.Fatal(err)
	}
	buildManifest := []byte("{\"format\":1,\"source\":\"v1.2.3\",\"toolchain\":\"go1.26.1\",\"verification\":\"clean-tag-export-unsigned\",\"signed\":false}\n")
	if err := os.WriteFile(filepath.Join(buildDir, "BUILD.json"), buildManifest, 0600); err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		name := familyArtifactName("telara-memory-", target)
		path := filepath.Join(buildDir, name)
		if err := os.WriteFile(path, []byte("one built binary "+target.OS+"/"+target.Arch), 0777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0777); err != nil {
			t.Fatal(err)
		}
	}
	legacyDir := filepath.Join(root, "legacy")
	hiloDir := filepath.Join(root, "hilo")
	legacyDigests, err := writeFamily(buildDir, legacyDir, "telara-memory-")
	if err != nil {
		t.Fatal(err)
	}
	hiloDigests, err := writeFamily(buildDir, hiloDir, "hilo-")
	if err != nil {
		t.Fatal(err)
	}
	if !sameDigests(legacyDigests, hiloDigests) {
		t.Fatal("family copies differ")
	}
	for _, target := range targets {
		legacyName := familyArtifactName("telara-memory-", target)
		hiloName := familyArtifactName("hilo-", target)
		legacyBytes, err := os.ReadFile(filepath.Join(legacyDir, legacyName))
		if err != nil {
			t.Fatal(err)
		}
		hiloBytes, err := os.ReadFile(filepath.Join(hiloDir, hiloName))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(legacyBytes, hiloBytes) {
			t.Fatalf("binary bytes differ for %s/%s", target.OS, target.Arch)
		}
		if runtime.GOOS != "windows" {
			for _, path := range []string{filepath.Join(legacyDir, legacyName), filepath.Join(hiloDir, hiloName)} {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0755 {
					t.Fatalf("copied artifact mode %04o, want safe executable mode 0755", info.Mode().Perm())
				}
			}
		}
	}
	legacyBuild, err := os.ReadFile(filepath.Join(legacyDir, "BUILD.json"))
	if err != nil {
		t.Fatal(err)
	}
	hiloBuild, err := os.ReadFile(filepath.Join(hiloDir, "BUILD.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legacyBuild, buildManifest) || !bytes.Equal(hiloBuild, buildManifest) || !bytes.Equal(legacyBuild, hiloBuild) {
		t.Fatal("family provenance differs")
	}
	var legacyProvenance, hiloProvenance provenance
	if err := json.Unmarshal(legacyBuild, &legacyProvenance); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(hiloBuild, &hiloProvenance); err != nil {
		t.Fatal(err)
	}
	if legacyProvenance != hiloProvenance || legacyProvenance.Source != "v1.2.3" {
		t.Fatal("family release version or provenance differs")
	}
	for _, family := range []struct {
		dir    string
		prefix string
	}{{legacyDir, "telara-memory-"}, {hiloDir, "hilo-"}} {
		checksums, err := os.ReadFile(filepath.Join(family.dir, "SHA256SUMS"))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(checksums)), "\n")
		if len(lines) != len(targets) {
			t.Fatalf("%s family has %d manifest entries", family.prefix, len(lines))
		}
		allowed := make(map[string]bool, len(targets))
		for _, target := range targets {
			allowed[familyArtifactName(family.prefix, target)] = true
		}
		seen := make(map[string]bool, len(targets))
		for _, line := range lines {
			parts := strings.SplitN(line, "  ", 2)
			if len(parts) != 2 || len(parts[0]) != 64 || !allowed[parts[1]] || seen[parts[1]] {
				t.Fatalf("invalid %s manifest line %q", family.prefix, line)
			}
			manifestDigest, err := hex.DecodeString(parts[0])
			if err != nil {
				t.Fatalf("invalid digest in %s manifest: %v", family.prefix, err)
			}
			artifact, err := os.ReadFile(filepath.Join(family.dir, parts[1]))
			if err != nil {
				t.Fatal(err)
			}
			actualDigest := sha256.Sum256(artifact)
			if !bytes.Equal(manifestDigest, actualDigest[:]) {
				t.Fatalf("manifest digest mismatch for %s", parts[1])
			}
			seen[parts[1]] = true
		}
		if len(seen) != len(targets) {
			t.Fatalf("incomplete %s manifest", family.prefix)
		}
		entries, err := os.ReadDir(family.dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != len(targets)+2 {
			t.Fatalf("%s family contains unexpected files", family.prefix)
		}
		if _, err := os.Stat(filepath.Join(family.dir, "RELEASE.sig")); !os.IsNotExist(err) {
			t.Fatal("family staging unexpectedly signed before finalization")
		}
	}
}

func makeStagedSignedFamilies(t *testing.T, stageRoot string, omit string) {
	t.Helper()
	for _, family := range []struct {
		name   string
		prefix string
	}{{"legacy", "telara-memory-"}, {"hilo", "hilo-"}} {
		if family.name == omit {
			continue
		}
		dir := filepath.Join(stageRoot, family.name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, target := range targets {
			path := filepath.Join(dir, familyArtifactName(family.prefix, target))
			if err := os.WriteFile(path, []byte("signed fixture "+family.name), 0700); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range []string{"BUILD.json", "SHA256SUMS", "RELEASE.sig"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture "+name), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestPublishDualFamilyPreservesSeparateFinalizedDirectories(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	makeStagedSignedFamilies(t, stage, "")
	output := filepath.Join(root, "release")
	if err := publishDualFamily(stage, output); err != nil {
		t.Fatal(err)
	}
	for _, family := range []struct {
		name   string
		prefix string
	}{{"legacy", "telara-memory-"}, {"hilo", "hilo-"}} {
		dir := filepath.Join(output, family.name)
		files, err := familyFiles(dir, family.prefix)
		if err != nil || len(files) != len(targets)+3 {
			t.Fatalf("%s family files=%d err=%v", family.name, len(files), err)
		}
		for _, name := range []string{"BUILD.json", "SHA256SUMS", "RELEASE.sig"} {
			got, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || string(got) != "fixture "+name {
				t.Fatalf("%s %s was not retained: %q %v", family.name, name, got, err)
			}
		}
		binary := filepath.Join(dir, familyArtifactName(family.prefix, targets[0]))
		if _, err := os.Stat(binary); err != nil {
			t.Fatalf("%s family binary missing: %v", family.name, err)
		}
		if runtime.GOOS != "windows" {
			info, err := os.Stat(binary)
			if err != nil || info.Mode().Perm()&0100 == 0 || info.Mode().Perm()&0022 != 0 {
				t.Fatalf("%s output binary mode is not safely executable: %v %v", family.name, info, err)
			}
		}
	}
}

func TestFinalizeDualFamilyPublishesOnlyAfterBothFinalizersSucceed(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	makeStagedSignedFamilies(t, stage, "")
	output := filepath.Join(root, "release")
	want := provenance{Format: 1, Source: "v1.2.3", Toolchain: releaseToolchain, Verification: "clean-tag-export-signed", Signed: true}
	calls := []string{}
	err := finalizeDualFamily(stage, output, "v1.2.3", "unused-test-key", func(dir, key string) (provenance, error) {
		if key != "unused-test-key" {
			t.Fatalf("unexpected signing key argument %q", key)
		}
		calls = append(calls, filepath.Base(dir))
		return want, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(calls, []string{"legacy", "hilo"}) {
		t.Fatalf("verified families %v", calls)
	}
	for _, family := range []struct {
		name   string
		prefix string
	}{{"legacy", "telara-memory-"}, {"hilo", "hilo-"}} {
		if _, err := familyFiles(filepath.Join(output, family.name), family.prefix); err != nil {
			t.Fatalf("%s output missing after both finalizers succeeded: %v", family.name, err)
		}
	}
}

func TestFinalizeDualFamilyDoesNotPublishWhenEitherFamilyFails(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprintf("family-%d", failAt), func(t *testing.T) {
			root := t.TempDir()
			stage := filepath.Join(root, "stage")
			if err := os.Mkdir(stage, 0700); err != nil {
				t.Fatal(err)
			}
			makeStagedSignedFamilies(t, stage, "")
			output := filepath.Join(root, "release")
			calls := 0
			err := finalizeDualFamily(stage, output, "v1.2.3", "unused-test-key", func(dir, key string) (provenance, error) {
				calls++
				if calls == failAt {
					return provenance{}, errors.New("fixture family verification failed")
				}
				return provenance{Format: 1, Source: "v1.2.3", Toolchain: releaseToolchain, Verification: "clean-tag-export-signed", Signed: true}, nil
			})
			if err == nil || calls != failAt {
				t.Fatalf("failAt=%d calls=%d err=%v", failAt, calls, err)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("final output exists after family failure: %v", err)
			}
		})
	}
}

func TestFinalizeDualFamilyDoesNotPublishOnProvenanceMismatch(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	makeStagedSignedFamilies(t, stage, "")
	output := filepath.Join(root, "release")
	calls := 0
	err := finalizeDualFamily(stage, output, "v1.2.3", "unused-test-key", func(dir, key string) (provenance, error) {
		calls++
		source := "v1.2.3"
		if calls == 2 {
			source = "v1.2.4"
		}
		return provenance{Format: 1, Source: source, Toolchain: releaseToolchain, Verification: "clean-tag-export-signed", Signed: true}, nil
	})
	if err == nil || calls != 2 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("final output exists after provenance mismatch: %v", err)
	}
}

func TestPublishDualFamilyRefusesConcurrentDestinationWithoutClobber(t *testing.T) {
	for _, kind := range []string{"empty directory", "nonempty directory", "file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			stage := filepath.Join(root, "stage")
			if err := os.Mkdir(stage, 0700); err != nil {
				t.Fatal(err)
			}
			makeStagedSignedFamilies(t, stage, "")
			output := filepath.Join(root, "release")
			// Simulate another actor creating the destination after staging and
			// before the builder makes its final ownership claim.
			switch kind {
			case "empty directory":
				if err := os.Mkdir(output, 0700); err != nil {
					t.Fatal(err)
				}
			case "nonempty directory":
				if err := os.Mkdir(output, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(output, "keep"), []byte("owned elsewhere"), 0600); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(output, []byte("owned elsewhere"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(root, "link-target")
				if err := os.WriteFile(target, []byte("owned elsewhere"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, output); err != nil {
					t.Skipf("symlink fixture unavailable: %v", err)
				}
			}
			if err := publishDualFamily(stage, output); err == nil {
				t.Fatal("published over a concurrently created destination")
			}
			info, err := os.Lstat(output)
			if err != nil {
				t.Fatalf("conflicting destination was removed: %v", err)
			}
			if kind == "symlink" && info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("conflicting symlink was replaced")
			}
			if kind == "file" {
				got, err := os.ReadFile(output)
				if err != nil || string(got) != "owned elsewhere" {
					t.Fatalf("conflicting file changed: %q %v", got, err)
				}
			}
			if kind == "nonempty directory" {
				got, err := os.ReadFile(filepath.Join(output, "keep"))
				if err != nil || string(got) != "owned elsewhere" {
					t.Fatalf("conflicting directory changed: %q %v", got, err)
				}
			}
			if kind == "empty directory" {
				entries, err := os.ReadDir(output)
				if err != nil || len(entries) != 0 {
					t.Fatalf("conflicting empty directory changed: %v %v", entries, err)
				}
			}
		})
	}
}

func TestPublishDualFamilyDoesNotCreateOutputWhenEitherFamilyIsMissing(t *testing.T) {
	for _, missing := range []string{"legacy", "hilo"} {
		t.Run(missing, func(t *testing.T) {
			root := t.TempDir()
			stage := filepath.Join(root, "stage")
			if err := os.Mkdir(stage, 0700); err != nil {
				t.Fatal(err)
			}
			makeStagedSignedFamilies(t, stage, missing)
			output := filepath.Join(root, "release")
			if err := publishDualFamily(stage, output); err == nil {
				t.Fatal("published with an incomplete family set")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("partial output exists after family failure: %v", err)
			}
		})
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

func TestReleaseTargetNativeCustodyEnvironment(t *testing.T) {
	for _, platform := range []string{"darwin", "linux", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			env := map[string]string{}
			for _, item := range goEnv(platform, arch, t.TempDir()) {
				k, v, _ := strings.Cut(item, "=")
				env[k] = v
			}
			want := "0"
			if platform == "darwin" {
				want = "1"
			}
			if env["CGO_ENABLED"] != want || env["GOOS"] != platform || env["GOARCH"] != arch {
				t.Fatal(platform, arch, env)
			}
			for _, forbidden := range []string{"CC", "CXX", "SDKROOT", "DEVELOPER_DIR", "CGO_CFLAGS", "CGO_LDFLAGS"} {
				if _, ok := env[forbidden]; ok {
					t.Fatal("caller compiler control", forbidden)
				}
			}
		}
	}
}

func TestReleaseDarwinUnavailableOnNonNativeHost(t *testing.T) {
	if err := requireNativeCompiler(context.Background(), "linux"); !errors.Is(err, ErrNativeReleaseUnavailable) {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" {
		t.Skip("non-native release refusal executes on Linux/Windows")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	out := filepath.Join(dir, "release")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"go.mod": "module example.org/native-release\n", "go.sum": ""} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := build(context.Background(), config{Source: source, Out: out}); !errors.Is(err, ErrNativeReleaseUnavailable) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatal("unavailable native build published output", err)
	}
}

func TestReleaseSourceRootsDistinguishRepositoryAndRuntime(t *testing.T) {
	repository := t.TempDir()
	node := filepath.Join(repository, "contract", "internal", "node")
	if got := runtimeSourceRoot(repository); got != node || got == filepath.Join(repository, "contract") {
		t.Fatal("clean repository export selected the pure module", got)
	}
	// Development copies the runtime module directly, without ancestor lookup.
	if err := os.MkdirAll(node, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"go.mod": "module github.com/Telara-Labs/telara-memory/contract/internal/node\n", "go.sum": "existing real sums\n"} {
		if err := os.WriteFile(filepath.Join(node, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	copy := t.TempDir()
	if err := copySource(node, copy); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(copy, "go.mod")); err != nil || string(got) != "module github.com/Telara-Labs/telara-memory/contract/internal/node\n" {
		t.Fatal("runtime source root was not copied directly", err)
	}
	if _, err := os.Stat(filepath.Join(copy, "contract")); !os.IsNotExist(err) {
		t.Fatal("nested source root reintroduced a checkout dependency", err)
	}
}
