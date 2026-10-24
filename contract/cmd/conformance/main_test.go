package main

import (
	contractdata "github.com/Telara-Labs/telara-memory/contract"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryAndFixturesArePinned(t *testing.T) {
	root := "../.."
	raw := contractdata.ConformanceRegistry()
	if _, err := validateRegistry(root, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := validateRegistry(root, append(raw, ' ')); err == nil {
		t.Fatal("mutated registry accepted")
	}
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "testdata"), 0700)
	if _, err := validateRegistry(dir, raw); err == nil {
		t.Fatal("missing fixtures accepted")
	}
	// A complete staging fixture tree with one changed byte must fail pinning.
	r, err := validateRegistry(root, raw)
	if err != nil {
		t.Fatal(err)
	}
	for n := range r.FixtureDigests {
		b, e := os.ReadFile(filepath.Join(root, "testdata", n))
		if e != nil {
			t.Fatal(e)
		}
		os.WriteFile(filepath.Join(dir, "testdata", n), b, 0600)
	}
	os.WriteFile(filepath.Join(dir, "testdata", "v03-records.json"), []byte("changed"), 0600)
	if _, err := validateRegistry(dir, raw); err == nil {
		t.Fatal("changed fixture accepted")
	}
}
func TestConformanceForcesWorkspaceOff(t *testing.T) {
	out := workOff([]string{"PATH=/bin", "GOWORK=/other/work", "GOWORK=auto"})
	count := 0
	for _, v := range out {
		if strings.HasPrefix(v, "GOWORK=") {
			count++
			if v != "GOWORK=off" {
				t.Fatal("workspace leaked")
			}
		}
	}
	if count != 1 {
		t.Fatal("ambiguous workspace env")
	}
}
