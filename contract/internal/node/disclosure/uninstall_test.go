package disclosure_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
)

func TestDeleteInstalledSecretValidatesManifestAndRetainsData(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite privacy adapter lacks Windows runtime acceptance")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	ctx := context.Background()
	v := &unitVault{}
	if err := disclosure.DeleteInstalledSecret(ctx, data, v); err == nil {
		t.Fatal("absent profile accepted")
	}
	if err := disclosure.BootstrapInstalled(ctx, data, "Uninstall test", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{}, v); err != nil {
		t.Fatal(err)
	}
	before, err := store.ReadInstalledRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(data, "installed-authority.json")
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err = disclosure.DeleteInstalledSecret(ctx, data, v); err == nil {
		t.Fatal("unsafe manifest accepted")
	}
	if len(v.values) != 1 {
		t.Fatal("unsafe deletion changed vault")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = disclosure.DeleteInstalledSecret(ctx, data, v); err != nil {
		t.Fatal(err)
	}
	if len(v.values) != 0 {
		t.Fatal("secret retained")
	}
	if err = disclosure.DeleteInstalledSecret(ctx, data, v); err != nil {
		t.Fatal("not idempotent", err)
	}
	after, err := store.ReadInstalledRecord(data)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("manifest changed", err)
	}
	if _, err = os.Stat(filepath.Join(data, "memory.sqlite")); err != nil {
		t.Fatal("retained data removed", err)
	}
}
