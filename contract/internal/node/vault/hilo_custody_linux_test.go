//go:build linux

package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

// Persisted binding validation only. This never opens a user's Secret Service
// or creates a credential. Native bus/collection acceptance is a separate gate.
func TestHiloCustodyLocationKeepsRecordedLegacyAlias(t *testing.T) {
	if collectionAlias != "hilo" || legacyCollectionAlias != "telara-memory" || service != "dev.telara.memory.runtime" {
		t.Fatal("new label or immutable custody namespace drift")
	}
	for _, alias := range []string{"hilo", "telara-memory", "default", ""} {
		t.Run("alias-"+alias, func(t *testing.T) {
			data, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := ipc.ValidateDir(data, true); err != nil {
				t.Fatal(err)
			}
			m := secretServiceLocation{Version: 1, Collection: "/org/freedesktop/secrets/collection/owned", Alias: alias, Item: "/org/freedesktop/secrets/collection/owned/item1", Handle: strings.Repeat("a", 32), Creation: strings.Repeat("b", 32), Bus: strings.Repeat("c", 32), Owner: ":1.42", State: "ready"}
			if !validLinuxLocation(m) {
				t.Fatal("recorded collection alias rejected")
			}
			if err := writeLinuxLocation(data, m); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(data, custodyLocationFile)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := readLinuxLocation(data)
			if err != nil || !reflect.DeepEqual(got, &m) {
				t.Fatal("recorded collection identity changed", err)
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
				t.Fatal("reading legacy collection rewrote the binding", err)
			}
			for _, badAlias := range []string{"Hilo", "telara-memory-other", "hilo-other"} {
				bad := m
				bad.Alias = badAlias
				if validLinuxLocation(bad) {
					t.Fatal("unknown alias accepted")
				}
			}
		})
	}
}
