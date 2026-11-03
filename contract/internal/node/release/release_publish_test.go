//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/releaseauth"
)

// Synthetic keys exercise real signature/hash binding in publication tests.
// They are never an override for the production compiled release authority.
func signedReleaseFixture(t *testing.T, dual bool) ([]string, func(string) (releaseauth.Provenance, error)) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	prefixes := []string{"hilo-"}
	if dual {
		prefixes = []string{"telara-memory-", "hilo-"}
	}
	for _, prefix := range prefixes {
		dir := t.TempDir()
		var sums strings.Builder
		for _, target := range targets {
			name := familyArtifactName(prefix, target)
			body := bytes.Repeat([]byte(target.OS+target.Arch), 24000)
			if os.WriteFile(filepath.Join(dir, name), body, 0700) != nil {
				t.Fatal("fixture artifact")
			}
			digest := sha256.Sum256(body)
			fmt.Fprintf(&sums, "%x  %s\n", digest, name)
		}
		build, e := json.MarshalIndent(provenance{1, "v1.2.3", releaseToolchain, "clean-tag-export-signed", true}, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		build = append(build, '\n')
		payload := append([]byte(releasePublicationDomain), build...)
		payload = append(payload, 0)
		payload = append(payload, []byte(sums.String())...)
		signature := ed25519.Sign(private, payload)
		for name, body := range map[string][]byte{"BUILD.json": build, "SHA256SUMS": []byte(sums.String()), "RELEASE.sig": []byte(base64.StdEncoding.EncodeToString(signature) + "\n")} {
			if os.WriteFile(filepath.Join(dir, name), body, 0600) != nil {
				t.Fatal("fixture metadata")
			}
		}
		dirs = append(dirs, dir)
	}
	verify := func(dir string) (releaseauth.Provenance, error) {
		fail := func() (releaseauth.Provenance, error) {
			return releaseauth.Provenance{}, errors.New("synthetic verification failed")
		}
		build, e := os.ReadFile(filepath.Join(dir, "BUILD.json"))
		if e != nil {
			return fail()
		}
		sums, e := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
		if e != nil {
			return fail()
		}
		encoded, e := os.ReadFile(filepath.Join(dir, "RELEASE.sig"))
		sig, se := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		message := append([]byte(releasePublicationDomain), build...)
		message = append(message, 0)
		message = append(message, sums...)
		if e != nil || se != nil || !ed25519.Verify(public, message, sig) {
			return fail()
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(sums), "\n"), "\n") {
			pair := strings.Split(line, "  ")
			if len(pair) != 2 || filepath.Base(pair[1]) != pair[1] {
				return fail()
			}
			body, e := os.ReadFile(filepath.Join(dir, pair[1]))
			hash := sha256.Sum256(body)
			if e != nil || hex.EncodeToString(hash[:]) != pair[0] {
				return fail()
			}
		}
		var p releaseauth.Provenance
		if json.Unmarshal(build, &p) != nil {
			return fail()
		}
		return p, nil
	}
	return dirs, verify
}

func TestReleasePublicationIndependentInodesAndBothFamilies(t *testing.T) {
	for _, dual := range []bool{false, true} {
		dirs, verify := signedReleaseFixture(t, dual)
		out := filepath.Join(t.TempDir(), "published")
		if err := publishReleaseTrees(context.Background(), dirs, out, "v1.2.3", verify, nil); err != nil {
			t.Fatal(err)
		}
		for i, source := range dirs {
			destination := out
			if dual {
				destination = filepath.Join(out, []string{"legacy", "hilo"}[i])
			}
			entries, e := os.ReadDir(source)
			if e != nil {
				t.Fatal(e)
			}
			for _, entry := range entries {
				src, dst := filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name())
				a, ae := os.Stat(src)
				b, be := os.Stat(dst)
				if ae != nil || be != nil || os.SameFile(a, b) {
					t.Fatal("published inode aliases source")
				}
				if os.WriteFile(src, []byte("changed source after publication"), 0600) != nil {
					t.Fatal("source mutation fixture")
				}
			}
			if _, err := verify(destination); err != nil {
				t.Fatal("source mutation changed independent published bytes")
			}
		}
	}
}

func TestReleasePublicationRejectsSourceReplacementAndMutation(t *testing.T) {
	for _, mode := range []string{"replace", "mutate"} {
		t.Run(mode, func(t *testing.T) {
			dirs, verify := signedReleaseFixture(t, false)
			out := filepath.Join(t.TempDir(), "published")
			changed := false
			hook := func(phase, source, _ string) {
				if changed || !strings.HasPrefix(filepath.Base(source), "hilo-") {
					return
				}
				if mode == "replace" && phase == "opened" {
					changed = true
					body, e := os.ReadFile(source)
					if e != nil || os.Rename(source, source+".retained") != nil || os.WriteFile(source, body, 0700) != nil {
						t.Fatal("replacement fixture")
					}
				}
				if mode == "mutate" && phase == "copied-chunk" {
					changed = true
					if os.WriteFile(source, []byte("changed while descriptor copy is in progress"), 0700) != nil {
						t.Fatal("mutation fixture")
					}
				}
			}
			if publishReleaseTrees(context.Background(), dirs, out, "v1.2.3", verify, hook) == nil || !changed {
				t.Fatal("changed source was published")
			}
			if _, e := os.Lstat(out); !os.IsNotExist(e) {
				t.Fatal("incomplete output exposed")
			}
		})
	}
}

func TestReleasePublicationPreservesForeignReplacements(t *testing.T) {
	for _, mode := range []string{"destination-file", "commit-target", "staging-tree", "committed-tree"} {
		t.Run(mode, func(t *testing.T) {
			dirs, verify := signedReleaseFixture(t, false)
			out := filepath.Join(t.TempDir(), "published")
			foreign, changed := "", false
			hook := func(phase, source, destination string) {
				if changed {
					return
				}
				if mode == "destination-file" && phase == "opened" {
					changed, foreign = true, destination
					if os.Rename(destination, destination+".retained") != nil || os.WriteFile(foreign, []byte("foreign"), 0600) != nil {
						t.Fatal("destination fixture")
					}
				}
				if mode == "commit-target" && phase == "before-commit" {
					changed, foreign = true, filepath.Join(destination, "foreign")
					if os.Mkdir(destination, 0700) != nil || os.WriteFile(foreign, []byte("foreign"), 0600) != nil {
						t.Fatal("commit fixture")
					}
				}
				if mode == "staging-tree" && phase == "before-commit" || mode == "committed-tree" && phase == "committed" {
					path := source
					if mode == "committed-tree" {
						path = destination
					}
					changed, foreign = true, filepath.Join(path, "foreign")
					if os.Rename(path, path+".retained") != nil || os.Mkdir(path, 0700) != nil || os.WriteFile(foreign, []byte("foreign"), 0600) != nil {
						t.Fatal("tree fixture")
					}
				}
			}
			if publishReleaseTrees(context.Background(), dirs, out, "v1.2.3", verify, hook) == nil || !changed {
				t.Fatal("replacement accepted")
			}
			body, e := os.ReadFile(foreign)
			if e != nil || string(body) != "foreign" {
				t.Fatal("cleanup deleted foreign replacement")
			}
		})
	}
}

func TestReleasePublicationVerificationFailureCleansOnlyOwnedStage(t *testing.T) {
	dirs, _ := signedReleaseFixture(t, false)
	parent := t.TempDir()
	out := filepath.Join(parent, "published")
	verify := func(string) (releaseauth.Provenance, error) {
		return releaseauth.Provenance{}, errors.New("verification refused")
	}
	if publishReleaseTrees(context.Background(), dirs, out, "v1.2.3", verify, nil) == nil {
		t.Fatal("verification failure published")
	}
	entries, e := os.ReadDir(parent)
	if e != nil || len(entries) != 0 {
		t.Fatal("owned stage retained on ordinary verification failure")
	}
}
