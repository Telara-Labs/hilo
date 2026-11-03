package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Telara-Labs/hilo/contract/releaseauth"
)

func privateDir(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}
func write(t *testing.T, dir, name string, body []byte) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, body, 0600); err != nil {
		t.Fatal(err)
	}
}
func canonical(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}
func signFixture(raw *rawMetadata, key ed25519.PrivateKey) {
	payload := append([]byte("telara-memory-release-v1\x00"), raw.Build...)
	payload = append(payload, 0)
	payload = append(payload, raw.Sums...)
	raw.Signature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload)) + "\n")
}

// These signatures exercise only the private copied-byte helper. They cannot
// authorize public Verify/Target or the production CLI, and never claim a full
// production-key release PASS. They are deliberately public TEST-ONLY material.
func copiedFixture(t *testing.T, family string) (rawMetadata, releaseauth.Provenance, map[string]string, ed25519.PrivateKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("npmstage private helper TEST ONLY; NEVER RELEASE"))
	key := ed25519.NewKeyFromSeed(seed[:])
	p := releaseauth.Provenance{Format: 1, Source: "v1.2.3", Toolchain: "go1.26.1", Verification: "clean-tag-export-signed", Signed: true}
	raw := rawMetadata{Build: canonical(t, p)}
	targets := map[string]string{}
	var sums strings.Builder
	for _, platform := range []string{"darwin", "linux", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			name := artifactName(family, platform, arch)
			h := sha256.Sum256([]byte("TEST-ONLY bytes " + name))
			digest := hex.EncodeToString(h[:])
			targets[name] = digest
			fmt.Fprintf(&sums, "%s  %s\n", digest, name)
		}
	}
	raw.Sums = []byte(sums.String())
	signFixture(&raw, key)
	return raw, p, targets, key
}
func packageFixture(t *testing.T) []byte {
	t.Helper()
	// Independent source contract fixture; no version or lifecycle scripts, and
	// source bin aliases share one launcher.
	return canonical(t, map[string]any{
		"name": "@telaralabs/hilo", "private": true, "description": "TEST-ONLY private staging template", "license": "Apache-2.0",
		"engines": map[string]string{"node": ">=22"},
		"bin":     map[string]string{"hilo": "bin/hilo.cjs"},
		"files":   []string{"bin/hilo.cjs", "README.md", "LICENSE", "lib/release-auth.cjs", "lib/runner.cjs", "release/BUILD.json", "release/SHA256SUMS", "release/RELEASE.sig", "release/release-key.pub", "release-spec.json"},
	})
}
func preparedFixture(t *testing.T) prepared {
	t.Helper()
	raw, p, targets, key := copiedFixture(t, "hilo")
	if err := authenticateCopiedMetadata(raw, p, targets, key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	pkg, err := versionedPackage(packageFixture(t), "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	_, pub, err := pinnedKey()
	if err != nil {
		t.Fatal(err)
	}
	spec := releaseSpec{"1.2.3", "hilo", "v1.2.3", repository}
	return prepared{spec, map[string][]byte{
		"package.json": pkg, "README.md": []byte("TEST-ONLY README\n"), "LICENSE": []byte("TEST-ONLY legal placeholder\n"),
		"bin/hilo.cjs":         []byte("TEST-ONLY launcher fixture\n"),
		"lib/release-auth.cjs": []byte("TEST-ONLY source fixture\n"), "lib/runner.cjs": []byte("TEST-ONLY runner fixture\n"),
		"release/BUILD.json": raw.Build, "release/SHA256SUMS": raw.Sums, "release/RELEASE.sig": raw.Signature,
		"release/release-key.pub": pub, "release-spec.json": canonical(t, spec),
	}}
}

func TestNPMStagePublicCLIRefusesTestKeyAndMissingInputs(t *testing.T) {
	key, encoded, err := pinnedKey()
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatal(err)
	}
	h := sha256.Sum256(encoded)
	if hex.EncodeToString(h[:]) != "8f56b2313dfb0ce37156cec349393b230d4055bc01501fb2adfa1f3cd6c5f492" {
		t.Fatal("public key encoding drift")
	}
	for _, family := range []string{"legacy", "hilo"} {
		raw, _, _, fixtureKey := copiedFixture(t, family)
		if fixtureKey.Public().(ed25519.PublicKey).Equal(key) {
			t.Fatal("TEST-ONLY key unexpectedly equals production")
		}
		release, pkg, output := privateDir(t), privateDir(t), filepath.Join(privateDir(t), "new-output")
		write(t, release, "BUILD.json", raw.Build)
		write(t, release, "SHA256SUMS", raw.Sums)
		write(t, release, "RELEASE.sig", raw.Signature)
		for _, platform := range []string{"darwin", "linux", "windows"} {
			for _, arch := range []string{"amd64", "arm64"} {
				name := artifactName(family, platform, arch)
				write(t, release, name, []byte("TEST-ONLY bytes "+name))
			}
		}
		if _, err := releaseauth.Verify(release); err == nil {
			t.Fatal("production Verify admitted TEST-ONLY release")
		}
		var report bytes.Buffer
		args := []string{"--release", release, "--package", pkg, "--out", output, "--family", family}
		if err := run(args, &report); err == nil || report.Len() != 0 {
			t.Fatal("production staging admitted test key", err, report.String())
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatal("failed authentication created output", err)
		}
	}
	for _, args := range [][]string{nil, {"--version", "1.2.3"}, {"--key", "test"}, {"--skip-verify"}, {"--development"}, {"--family", "other"}} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatal("unreviewed CLI accepted", args)
		}
	}
}

func TestNPMStageCopiedBytesStrictProfile(t *testing.T) {
	for _, family := range []string{"legacy", "hilo"} {
		t.Run(family, func(t *testing.T) {
			raw, p, targets, key := copiedFixture(t, family)
			pub := key.Public().(ed25519.PublicKey)
			if err := authenticateCopiedMetadata(raw, p, targets, pub); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"build", "sums", "signature"} {
				bad := rawMetadata{append([]byte{}, raw.Build...), append([]byte{}, raw.Sums...), append([]byte{}, raw.Signature...)}
				switch field {
				case "build":
					bad.Build[0] ^= 1
				case "sums":
					bad.Sums[0] ^= 1
				case "signature":
					bad.Signature[0] ^= 1
				}
				if err := authenticateCopiedMetadata(bad, p, targets, pub); !errors.Is(err, errMetadata) {
					t.Fatal("raw mutation accepted", field, err)
				}
			}
			mutations := []func(*rawMetadata){
				func(r *rawMetadata) {
					r.Build = bytes.Replace(r.Build, []byte(`  "format": 1,`), []byte(` "format": 1,`), 1)
				},
				func(r *rawMetadata) {
					r.Build = bytes.Replace(r.Build, []byte(`  "format": 1,`), []byte("  \"format\": 1,\n  \"format\": 1,"), 1)
				},
				func(r *rawMetadata) { r.Build = bytes.Replace(r.Build, []byte(`"format"`), []byte(`"Format"`), 1) },
				func(r *rawMetadata) { r.Build = bytes.Replace(r.Build, []byte("go1.26.1"), []byte("go9.9.9"), 1) },
				func(r *rawMetadata) {
					r.Build = bytes.Replace(r.Build, []byte("clean-tag-export-signed"), []byte("UNVERIFIED-development-signed"), 1)
				},
				func(r *rawMetadata) { r.Sums = append(r.Sums, '\n') },
				func(r *rawMetadata) { r.Sums = bytes.Replace(r.Sums, []byte("  "), []byte(" \t"), 1) },
				func(r *rawMetadata) {
					r.Sums = bytes.Replace(r.Sums, []byte(familyPrefix(t, family)+"darwin-amd64"), []byte("../escape"), 1)
				},
			}
			for i, mutate := range mutations {
				bad := rawMetadata{append([]byte{}, raw.Build...), append([]byte{}, raw.Sums...), nil}
				mutate(&bad)
				signFixture(&bad, key)
				if err := authenticateCopiedMetadata(bad, p, targets, pub); !errors.Is(err, errMetadata) {
					t.Fatal("signed noncanonical or malformed bytes accepted", i, err)
				}
			}
			for _, sig := range [][]byte{append([]byte(" "), raw.Signature...), append(append([]byte{}, raw.Signature...), '\n'), bytes.Repeat([]byte{'A'}, 257)} {
				bad := raw
				bad.Signature = sig
				if err := authenticateCopiedMetadata(bad, p, targets, pub); err == nil {
					t.Fatal("noncanonical signature accepted")
				}
			}
			wrongKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey)
			if err := authenticateCopiedMetadata(raw, p, targets, wrongKey); err == nil {
				t.Fatal("substituted key accepted")
			}
			changedTargets := map[string]string{}
			for name, digest := range targets {
				changedTargets[name] = digest
			}
			changedTargets[artifactName(family, "linux", "amd64")] = strings.Repeat("0", 64)
			if err := authenticateCopiedMetadata(raw, p, changedTargets, pub); err == nil {
				t.Fatal("reread metadata disagreed with Target identity")
			}
		})
	}
}
func familyPrefix(t *testing.T, family string) string {
	t.Helper()
	p, err := prefix(family)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNPMStagePackageVersionOnlyFromAuthenticatedTag(t *testing.T) {
	out, err := versionedPackage(packageFixture(t), "2.4.6-rc.1")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if json.Unmarshal(out, &got) != nil || got["version"] != "2.4.6-rc.1" || got["private"] != true {
		t.Fatal("wrong staged version/private state", string(out))
	}
	if _, ok := got["scripts"]; ok {
		t.Fatal("staged package unexpectedly contains lifecycle scripts", string(out))
	}
	for _, mutation := range []func(map[string]any){
		func(p map[string]any) { p["version"] = "0.0.0" }, func(p map[string]any) { p["private"] = false },
		func(p map[string]any) { p["name"] = "@other/package" }, func(p map[string]any) { p["dependencies"] = map[string]string{"extra": "*"} },
		func(p map[string]any) {
			p["bin"] = map[string]string{"hilo": "bin/hilo.cjs", "telara-memory": "other.cjs"}
		},
		func(p map[string]any) { p["files"] = []string{"test", ".cache", "secret.key"} },
		func(p map[string]any) { p["engines"] = map[string]string{"node": ">=20"} },
		func(p map[string]any) { p["repository"] = "https://attacker.invalid/repo" },
	} {
		var p map[string]any
		json.Unmarshal(packageFixture(t), &p)
		mutation(p)
		if _, err := versionedPackage(canonical(t, p), "1.2.3"); err == nil {
			t.Fatal("unsafe source metadata admitted", p)
		}
	}
	for _, scripts := range []any{
		map[string]any{}, nil, "unsafe", []any{},
		map[string]any{"preinstall": "node setup.cjs"},
		map[string]any{"install": "node setup.cjs"},
		map[string]any{"postinstall": "node postinstall.cjs"},
		map[string]any{"postinstall": "node setup.cjs"},
		map[string]any{"postinstall": "node postinstall.cjs", "preinstall": "run setup"},
		map[string]any{"prepare": "node setup.cjs"},
		map[string]any{"prepublish": "node setup.cjs"},
	} {
		var p map[string]any
		if json.Unmarshal(packageFixture(t), &p) != nil {
			t.Fatal("invalid package fixture")
		}
		p["scripts"] = scripts
		if _, err := versionedPackage(canonical(t, p), "1.2.3"); err == nil {
			t.Fatal("package lifecycle scripts admitted", scripts)
		}
	}
	for _, raw := range []string{`{"name":"x","name":"x"}`, `{"scripts":{"postinstall":"one","postinstall":"two"}}`, string(packageFixture(t)) + `{}`, `null`} {
		if _, err := versionedPackage([]byte(raw), "1.2.3"); err == nil {
			t.Fatal("ambiguous JSON accepted", raw)
		}
	}
	for _, version := range []string{"", "v1.2.3", "1.2.3+extra", "latest", "1.2.3\n"} {
		if _, err := versionedPackage(packageFixture(t), version); err == nil {
			t.Fatal("non-tag version accepted", version)
		}
	}
}

func TestNPMStageGuardedFixedFilesAndPathChanges(t *testing.T) {
	for _, attack := range []string{"symlink", "hardlink", "directory", "writable", "oversize", "parent-symlink", "parent-replaced"} {
		t.Run(attack, func(t *testing.T) {
			dir := privateDir(t)
			write(t, dir, "lib/one.cjs", []byte("one"))
			write(t, dir, "lib/two.cjs", []byte("two"))
			g, err := guardDirectory(dir)
			if err != nil {
				t.Fatal(err)
			}
			if b, err := g.read("lib/one.cjs", 1024); err != nil || string(b) != "one" {
				t.Fatal("first fixed child read", err)
			}
			if b, err := g.read("lib/two.cjs", 1024); err != nil || string(b) != "two" {
				t.Fatal("original root lost after registering child", err)
			}
			p := filepath.Join(dir, "lib/one.cjs")
			switch attack {
			case "symlink":
				os.Rename(p, p+".saved")
				os.Symlink(p+".saved", p)
			case "hardlink":
				os.Link(p, p+".linked")
			case "directory":
				os.Remove(p)
				os.Mkdir(p, 0700)
			case "writable":
				os.Chmod(p, 0666)
			case "oversize":
				os.WriteFile(p, bytes.Repeat([]byte{'x'}, 1025), 0600)
			case "parent-symlink":
				os.Rename(filepath.Join(dir, "lib"), filepath.Join(dir, "saved"))
				os.Symlink(filepath.Join(dir, "saved"), filepath.Join(dir, "lib"))
			case "parent-replaced":
				os.Rename(filepath.Join(dir, "lib"), filepath.Join(dir, "saved"))
				os.Mkdir(filepath.Join(dir, "lib"), 0700)
			}
			if _, err := g.read("lib/one.cjs", 1024); err == nil {
				t.Fatal("unsafe or replaced path accepted", attack)
			}
		})
	}
}

func TestNPMStageFilesystemPublishOnlyNotFullReleaseAcceptance(t *testing.T) {
	input := preparedFixture(t)
	output := filepath.Join(privateDir(t), "new-package")
	if err := publish(input, output); err != nil {
		t.Fatal(err)
	}
	var names []string
	err := filepath.WalkDir(output, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(output, p)
		names = append(names, filepath.ToSlash(rel))
		b, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(b, input.Files[filepath.ToSlash(rel)]) {
			return errors.New("staged bytes differ")
		}
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		mode := os.FileMode(0444)
		if filepath.ToSlash(rel) == "bin/hilo.cjs" {
			mode = 0555
		}
		if st.Mode().Perm() != mode {
			return errors.New("unsafe staged mode")
		}
		return nil
	})
	if err != nil || len(names) != 11 {
		t.Fatal(names, err)
	}
	for _, name := range names {
		if name == "postinstall.cjs" {
			t.Fatal("private helper was included in staged package", names)
		}
	}
	var spec releaseSpec
	if json.Unmarshal(input.Files["release-spec.json"], &spec) != nil || spec.Repository != "Telara-Labs/hilo" || !bytes.Equal(input.Files["release-spec.json"], []byte("{\n  \"version\": \"1.2.3\",\n  \"family\": \"hilo\",\n  \"tag\": \"v1.2.3\",\n  \"repository\": \"Telara-Labs/hilo\"\n}\n")) {
		t.Fatal("runner spec byte contract drift")
	}
}

func TestNPMStageRejectsExistingAndConcurrentOutput(t *testing.T) {
	input := preparedFixture(t)
	for _, kind := range []string{"directory", "file", "symlink", "dangling-symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := privateDir(t)
			output := filepath.Join(root, "existing")
			switch kind {
			case "directory":
				os.Mkdir(output, 0700)
			case "file":
				os.WriteFile(output, []byte("foreign"), 0600)
			case "symlink":
				os.Symlink(root, output)
			case "dangling-symlink":
				os.Symlink(filepath.Join(root, "missing"), output)
			}
			before, err := os.Lstat(output)
			if err != nil {
				t.Fatal(err)
			}
			if err := publish(input, output); err == nil {
				t.Fatal("existing output replaced")
			}
			after, err := os.Lstat(output)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("existing output changed", err)
			}
		})
	}
	output := filepath.Join(privateDir(t), "concurrent")
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- publish(input, output) }()
	}
	wg.Wait()
	close(results)
	passed := 0
	for err := range results {
		if err == nil {
			passed++
		}
	}
	if passed != 1 {
		t.Fatal("exclusive publication winners", passed)
	}
	for name, want := range input.Files {
		got, err := os.ReadFile(filepath.Join(output, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("concurrent winner incomplete or overwritten", name, err)
		}
	}
}

func TestNPMStageRollbackRetainsForeignAndReplacedInodes(t *testing.T) {
	parentDir := privateDir(t)
	parent, err := guardDirectory(parentDir)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(parentDir, "claimed")
	os.Mkdir(output, 0700)
	guard, err := guardDirectory(output)
	if err != nil {
		t.Fatal(err)
	}
	created := []snapshot{{output, guard.Dirs[len(guard.Dirs)-1].Info}}
	for _, name := range []string{"owned", "replaced"} {
		write(t, output, name, []byte(name))
		info, _ := os.Lstat(filepath.Join(output, name))
		created = append(created, snapshot{filepath.Join(output, name), info})
	}
	os.Rename(filepath.Join(output, "replaced"), filepath.Join(output, "retained-original"))
	write(t, output, "replaced", []byte("foreign replacement"))
	write(t, output, "foreign", []byte("foreign extra"))
	rollbackCreated(parent, guard, created)
	if _, err := os.Lstat(filepath.Join(output, "owned")); !os.IsNotExist(err) {
		t.Fatal("owned exact file retained", err)
	}
	for name, want := range map[string]string{"replaced": "foreign replacement", "foreign": "foreign extra", "retained-original": "replaced"} {
		got, err := os.ReadFile(filepath.Join(output, name))
		if err != nil || string(got) != want {
			t.Fatal("foreign or ambiguous state erased", name, err)
		}
	}
	// A package replacement must also prevent any path-based cleanup there.
	info, _ := os.Lstat(output)
	os.Rename(output, output+"-old")
	os.Mkdir(output, 0700)
	write(t, output, "foreign", []byte("new directory owner"))
	rollbackCreated(parent, guard, []snapshot{{output, info}})
	if got, _ := os.ReadFile(filepath.Join(output, "foreign")); string(got) != "new directory owner" {
		t.Fatal("replacement directory erased")
	}
}

func TestNPMStageOutputAllowlistRejectsUnexpectedOrIncompleteFiles(t *testing.T) {
	for _, attack := range []string{"extra", "missing", "empty", "oversize", "traversal"} {
		input := preparedFixture(t)
		switch attack {
		case "extra":
			input.Files["test/private-key"] = []byte("TEST-ONLY must not ship")
		case "missing":
			delete(input.Files, "lib/runner.cjs")
		case "empty":
			input.Files["README.md"] = nil
		case "oversize":
			input.Files["README.md"] = bytes.Repeat([]byte{'x'}, (1<<20)+1)
		case "traversal":
			delete(input.Files, "README.md")
			input.Files["../README.md"] = []byte("escape")
		}
		output := filepath.Join(privateDir(t), "out")
		if err := publish(input, output); err == nil {
			t.Fatal("unsafe output allowed", attack)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatal("allowlist failure created output", attack, err)
		}
	}
}

func TestNPMStageUniqueJSONAndSetChecks(t *testing.T) {
	if uniqueJSON([]byte(`{"one":[{"two":3},4]}`)) != nil {
		t.Fatal("valid bounded unique JSON refused")
	}
	for _, raw := range []string{`{"x":1,"x":2}`, `{"x":{"y":1,"y":2}}`, `{"x":1} {}`, strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18)} {
		if uniqueJSON([]byte(raw)) == nil {
			t.Fatal("ambiguous or unbounded JSON accepted", raw)
		}
	}
	if !equalSet([]string{"b", "a"}, []string{"a", "b"}) || equalSet([]string{"a", "a"}, []string{"a", "b"}) {
		t.Fatal("allowlist set contract")
	}
}

func TestNPMStageNodeVersionLengthBoundary(t *testing.T) {
	for _, length := range []int{1024, 1025} {
		version := "1.2.3-" + strings.Repeat("a", length-len("1.2.3-"))
		for _, family := range []string{"legacy", "hilo"} {
			raw, provenance, targets, key := copiedFixture(t, family)
			provenance.Source = "v" + version
			raw.Build = canonical(t, provenance)
			signFixture(&raw, key)
			metadataErr := authenticateCopiedMetadata(raw, provenance, targets, key.Public().(ed25519.PublicKey))
			_, packageErr := versionedPackage(packageFixture(t), version)
			if length == 1024 {
				if metadataErr != nil || packageErr != nil {
					t.Fatal("Node-compatible boundary refused", family, metadataErr, packageErr)
				}
			} else if metadataErr == nil || packageErr == nil {
				t.Fatal("Node-incompatible version admitted", family, metadataErr, packageErr)
			}
		}
	}
}

func writeMetadataFixture(t *testing.T, dir string, raw rawMetadata) {
	t.Helper()
	for _, part := range metadataParts(&raw) {
		write(t, dir, part.name, *part.data)
	}
}

// The private callback establishes stability ordering only. It does not replace
// production full native Verify, authorize a test key in the CLI, or claim a
// complete production-key release staging success.
func TestNPMStageSnapshotRejectsConcurrentSameTagProducer(t *testing.T) {
	for _, change := range []string{"unchanged", "before-verify", "during-verify", "replace-identical", "restore-bytes"} {
		t.Run(change, func(t *testing.T) {
			dir := privateDir(t)
			rawA, provenance, targetsB, key := copiedFixture(t, "hilo")
			rawB := rawMetadata{Build: append([]byte{}, rawA.Build...), Sums: append([]byte{}, rawA.Sums...)}
			oldDigest := targetsB[artifactName("hilo", "linux", "amd64")]
			newDigest := strings.Repeat("a", 64)
			if oldDigest == newDigest {
				t.Fatal("fixture digest did not change")
			}
			rawB.Sums = bytes.Replace(rawB.Sums, []byte(oldDigest), []byte(newDigest), 1)
			targetsB[artifactName("hilo", "linux", "amd64")] = newDigest
			signFixture(&rawB, key)
			if err := authenticateCopiedMetadata(rawB, provenance, targetsB, key.Public().(ed25519.PublicKey)); err != nil {
				t.Fatal("alternate same-tag signed profile fixture", err)
			}
			writeMetadataFixture(t, dir, rawA)
			guard, err := guardDirectory(dir)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := captureMetadata(guard)
			if err != nil {
				t.Fatal(err)
			}
			if change == "before-verify" {
				writeMetadataFixture(t, dir, rawB)
			}
			calls := 0
			got, err := verifySnapshot(guard, snapshot, func() (releaseauth.Provenance, error) {
				calls++
				switch change {
				case "during-verify":
					writeMetadataFixture(t, dir, rawB)
				case "replace-identical":
					old := filepath.Join(dir, "SHA256SUMS")
					if err := os.Rename(old, old+".prior"); err != nil {
						t.Fatal(err)
					}
					write(t, dir, "SHA256SUMS", rawA.Sums)
				case "restore-bytes":
					// Restore identical bytes and mtime on the same inode. Normal writes
					// still change ctime; this is not hostile restoration of all stat data.
					file := filepath.Join(dir, "SHA256SUMS")
					info, err := os.Stat(file)
					if err != nil {
						t.Fatal(err)
					}
					write(t, dir, "SHA256SUMS", rawB.Sums)
					write(t, dir, "SHA256SUMS", rawA.Sums)
					if err := os.Chtimes(file, info.ModTime(), info.ModTime()); err != nil {
						t.Fatal(err)
					}
				}
				return provenance, nil
			})
			if change == "unchanged" {
				if err != nil || calls != 1 || got != provenance || !bytes.Equal(snapshot.Raw.Sums, rawA.Sums) {
					t.Fatal("stable snapshot or single verification changed", calls, err)
				}
			} else if err == nil || (change == "before-verify" && calls != 0) || (change != "before-verify" && calls != 1) {
				t.Fatal("concurrent snapshot mutation admitted or verification ordering wrong", calls, err)
			}
		})
	}
}

func TestNPMStageSnapshotGuardsEveryRawMetadataFile(t *testing.T) {
	for _, name := range []string{"BUILD.json", "SHA256SUMS", "RELEASE.sig"} {
		t.Run(name, func(t *testing.T) {
			dir := privateDir(t)
			raw, provenance, _, _ := copiedFixture(t, "legacy")
			writeMetadataFixture(t, dir, raw)
			guard, err := guardDirectory(dir)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := captureMetadata(guard)
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifySnapshot(guard, snapshot, func() (releaseauth.Provenance, error) {
				file := filepath.Join(dir, name)
				info, err := os.Stat(file)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(file, 0400); err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() == 0400 {
					t.Fatal("fixture mode did not change")
				}
				return provenance, nil
			})
			if err == nil {
				t.Fatal("metadata interval mode change admitted", name)
			}
		})
	}
}

func TestNPMStageParentSyncOrderingAndFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			input := preparedFixture(t)
			parent := privateDir(t)
			output := filepath.Join(parent, "new-package")
			sentinel := errors.New("TEST ONLY parent sync failure")
			var calls []string
			err := publishWithDirectorySync(input, output, func(guard *directoryGuard, dir string) error {
				calls = append(calls, dir)
				if dir == parent {
					// Parent durability may be acknowledged only after the entire candidate
					// and all output directories have reached their final state.
					if len(calls) != 5 || calls[3] != output {
						t.Fatal("parent sync before descendants/root", calls)
					}
					for name, want := range input.Files {
						got, err := os.ReadFile(filepath.Join(output, name))
						if err != nil || !bytes.Equal(got, want) {
							t.Fatal("parent sync saw incomplete package", name, err)
						}
					}
					for _, name := range []string{"", "bin", "lib", "release"} {
						info, err := os.Stat(filepath.Join(output, name))
						if err != nil || info.Mode().Perm() != 0755 {
							t.Fatal("parent sync before final directory modes", name, err)
						}
					}
					if fail {
						return sentinel
					}
				}
				return syncGuardedDirectory(guard, dir)
			})
			if len(calls) != 5 || calls[4] != parent {
				t.Fatal("missing final parent sync", calls)
			}
			if fail {
				if !errors.Is(err, sentinel) {
					t.Fatal("parent sync failure hidden", err)
				}
				if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
					t.Fatal("failed uncommitted output retained", statErr)
				}
			} else if err != nil {
				t.Fatal("durable publication failed", err)
			}
		})
	}
}

func TestNPMStageDirectorySyncRejectsReplacedParent(t *testing.T) {
	root := privateDir(t)
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	guard, err := guardDirectory(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent, parent+".prior"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	write(t, parent, "foreign", []byte("must survive"))
	if err := syncGuardedDirectory(guard, parent); err == nil {
		t.Fatal("replacement parent descriptor accepted")
	}
	if got, err := os.ReadFile(filepath.Join(parent, "foreign")); err != nil || string(got) != "must survive" {
		t.Fatal("replacement parent altered", err)
	}
}
