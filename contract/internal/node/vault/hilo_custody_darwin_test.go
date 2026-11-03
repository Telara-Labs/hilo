//go:build darwin && cgo

package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/custodyguard"
)

// Journal and retained-image compatibility only. Actual native keychain access
// remains covered by the separate native custody acceptance tests.
func TestHiloCustodyJournalPreservesLegacyAndCurrentImageFamilies(t *testing.T) {
	if service != "dev.telara.memory.runtime" {
		t.Fatal("immutable native lookup and lock namespace changed")
	}
	for _, name := range []string{"hilo", "telara-memory"} {
		t.Run(name, func(t *testing.T) {
			m := fixtureProfileHandoff(t)
			m.Source.Executable = filepath.Join(m.Source.Dir, "bin", m.Source.SHA256, name)
			m.Entries[0].Source.Image = m.Source.Executable
			m.Entries[0].Target.Image = filepath.Join(m.Source.Dir, "bin", m.Target, name)
			if handoffTarget(m.Source, m.Source.SHA256) != m.Source.Executable || handoffTarget(m.Source, m.Target) != m.Entries[0].Target.Image {
				t.Fatal("custody image family changed")
			}
			if err := writeProfileHandoff(m); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(m.Source.DataDir, custodyguard.ProfileJournal)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := readProfileHandoff(m.Source.DataDir)
			if err != nil || !reflect.DeepEqual(got, m) {
				t.Fatal("journal changed native handles/generation/creator pins", err)
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
				t.Fatal("journal read rewrote retained authority", err)
			}
			if got.Generation != m.Generation || got.Entries[0].Reference != m.Entries[0].Reference || got.Entries[0].Source.Namespace != m.Entries[0].Source.Namespace {
				t.Fatal("custody identity drift")
			}
			bad := m
			bad.Source.Executable = filepath.Join(m.Source.Dir, "bin", m.Source.SHA256, "hilo-other")
			if err := bad.validate(); err == nil {
				t.Fatal("unknown retained helper family accepted")
			}
			bad = m
			bad.Generation = ""
			if err := bad.validate(); err == nil {
				t.Fatal("missing custody generation accepted")
			}
		})
	}
}
