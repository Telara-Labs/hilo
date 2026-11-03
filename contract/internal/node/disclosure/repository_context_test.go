//go:build linux || darwin

package disclosure_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/store"
)

func TestRepositoryContextTypedPendingInventory(t *testing.T) {
	for _, phase := range []string{"unstarted", "creating", "created", "retiring-empty", "removed", "active-unstarted", "unknown-phase", "duplicate", "wrong-owner"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			data := filepath.Join(dir, "data")
			vault := &unitVault{}
			if err = disclosure.BootstrapInstalled(ctx, data, "Context inventory", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{}, vault); err != nil {
				t.Fatal(err)
			}
			owner, machine, err := store.InstalledIdentity(data)
			if err != nil {
				t.Fatal(err)
			}
			c := disclosure.RepositoryContext{ID: strings.Repeat("a", 32), Binding: strings.Repeat("b", 64), Generation: 1, Handle: strings.Repeat("c", 32), State: "pending", Native: phase}
			invalid := false
			want := 1
			switch phase {
			case "unstarted":
				want = 0
			case "creating":
			case "created":
				c.State = "active"
				c.Credential = "22222222-2222-4222-8222-222222222222"
			case "retiring-empty":
				c.State = "retiring"
				c.Native = "unstarted"
				want = 0
			case "removed":
				c.State = "removed"
				c.Handle = ""
				c.Native = "unstarted"
				want = 0
			case "active-unstarted":
				c.State = "active"
				c.Native = "unstarted"
				c.Credential = "22222222-2222-4222-8222-222222222222"
				invalid = true
			case "unknown-phase":
				invalid = true
			case "duplicate":
				c.Native = "creating"
				invalid = true
			case "wrong-owner":
				c.Native = "creating"
				owner = strings.Repeat("e", 32)
				invalid = true
			}
			contexts := []disclosure.RepositoryContext{c}
			if phase == "duplicate" {
				contexts = append(contexts, c)
			}
			raw, err := json.Marshal(map[string]any{"version": 1, "owner": owner, "machine": machine, "contexts": contexts})
			if err != nil {
				t.Fatal(err)
			}
			if err = store.WriteProfileRecord(data, store.RepositoryContextsName, raw); err != nil {
				t.Fatal(err)
			}
			handles, err := disclosure.OwnedCredentialHandles(data)
			if invalid {
				if err == nil {
					t.Fatal("invalid descriptor accepted")
				}
				return
			}
			if err != nil || len(handles) != want {
				t.Fatal("native inventory phase", phase, len(handles), err)
			}
			// An unstarted descriptor does not claim an OS object merely because an
			// opaque handle was reserved. Upgrade still hashes the descriptor itself.
			if len(vault.values) != 1 {
				t.Fatal("inventory accessed or created credential slots")
			}
			if err = os.Chmod(filepath.Join(data, store.RepositoryContextsName), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err = disclosure.OwnedCredentialHandles(data); err == nil {
				t.Fatal("public context descriptor accepted")
			}
		})
	}
}
