package store

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPrivatePublicationNoReplacePreservesExisting(t *testing.T) {
	dir := t.TempDir()
	target, source := filepath.Join(dir, "target"), filepath.Join(dir, "source")
	if err := os.WriteFile(target, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("candidate"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishPrivateRecord(source, target, false); err == nil {
		t.Fatal("no-replace overwrote existing record")
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "existing" {
		t.Fatalf("target changed: %q %v", b, err)
	}
	if err := publishPrivateRecord(source, target, true); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "candidate" {
		t.Fatalf("explicit replacement failed: %q %v", b, err)
	}
}

func TestPrivatePublicationConcurrentNoReplaceSingleWinner(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	paths := []string{filepath.Join(dir, "first"), filepath.Join(dir, "second")}
	for _, p := range paths {
		if err := os.WriteFile(p, []byte(filepath.Base(p)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan error, len(paths))
	var wg sync.WaitGroup
	for _, p := range paths {
		wg.Add(1)
		go func(p string) { defer wg.Done(); <-start; results <- publishPrivateRecord(p, target, false) }(p)
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("committed publishers=%d, want one", winners)
	}
	b, err := os.ReadFile(target)
	if err != nil || (string(b) != "first" && string(b) != "second") {
		t.Fatalf("invalid publication: %q %v", b, err)
	}
}
