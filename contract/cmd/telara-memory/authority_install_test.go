package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/vault"
)

type creatorTestVault struct {
	serviceVault
	creator                  install.Record
	data                     string
	refuseRead, refuseDelete bool
	puts                     int
}

func (v *creatorTestVault) Custodian(context.Context) (install.Record, error) { return v.creator, nil }
func (v *creatorTestVault) Put(ctx context.Context, h string, b []byte) error {
	p, e := readPending(v.data)
	if e != nil || p.Handle != h || p.Creator == nil || *p.Creator != v.creator {
		return errors.New("custody entered before creator persistence")
	}
	v.puts++
	return v.serviceVault.Put(ctx, h, b)
}
func (v *creatorTestVault) Get(ctx context.Context, h string) ([]byte, error) {
	if v.refuseRead {
		return nil, errors.New("target readback unavailable")
	}
	return v.serviceVault.Get(ctx, h)
}
func (v *creatorTestVault) Delete(ctx context.Context, h string) error {
	if v.refuseDelete {
		return errors.New("owning image unavailable")
	}
	return v.serviceVault.Delete(ctx, h)
}
func TestBootstrapPersistsCreatorBeforeEveryNativePutAndRequiresReadback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite native privacy acceptance is separate")
	}
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(root, "data")
	dir := filepath.Join(root, "install")
	digest := strings.Repeat("a", 64)
	creator := install.Record{Dir: dir, DataDir: data, SHA256: digest, Executable: filepath.Join(dir, "bin", digest, "telara-memory")}
	v := &creatorTestVault{creator: creator, data: data, refuseRead: true}
	ctx := context.Background()
	if e = provisionAuthority(ctx, data, v, nil); e == nil {
		t.Fatal("published authority without target readback")
	}
	p, e := readPending(data)
	if e != nil || p.Phase != "provisioning" || p.Handle == "" || p.Creator == nil || *p.Creator != creator || len(v.values) != 1 || v.puts != 2 {
		t.Fatal("creator/recovery fence lost", p, e, v.puts)
	}
	before, e := os.ReadFile(filepath.Join(data, "memory.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	// A failed owner-image delete must preserve the handle and creator for retry.
	v.refuseDelete = true
	if e = deleteNeverAdmittedAuthority(ctx, data, v); e == nil {
		t.Fatal("unverified deletion completed")
	}
	after, e := readPending(data)
	if e != nil || after.Handle != p.Handle || after.Creator == nil || *after.Creator != creator {
		t.Fatal("deletion failure lost custody evidence", e)
	}
	v.refuseRead = false
	v.refuseDelete = false
	if e = provisionAuthority(ctx, data, v, nil); e != nil {
		t.Fatal("target readback retry", e)
	}
	after, e = readPending(data)
	if e != nil || after.Phase != "complete" || v.puts != 2 {
		t.Fatal("retry recreated authority", e)
	}
	retained, e := os.ReadFile(filepath.Join(data, "memory.sqlite"))
	if e != nil || !bytes.Equal(retained, before) {
		t.Fatal("readback retry changed committed profile", e)
	}
}
func TestCreatorRecordRejectsRedirection(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(root, "data")
	if e = ipc.ValidateDir(data, true); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "install")
	digest := strings.Repeat("a", 64)
	creator := install.Record{Dir: dir, DataDir: data, SHA256: digest, Executable: filepath.Join(dir, "bin", digest, "telara-memory")}
	for _, mutate := range []func(*install.Record){
		func(r *install.Record) { r.DataDir += "/other" },
		func(r *install.Record) { r.Executable = "/other" },
		func(r *install.Record) { r.SHA256 = strings.Repeat("A", 64) },
		func(r *install.Record) { r.Dir = "relative" },
	} {
		bad := creator
		mutate(&bad)
		if e = writePending(data, pendingProfile{Version: 1, Creator: &bad}); e != nil {
			t.Fatal(e)
		}
		if _, e = readPending(data); e == nil {
			t.Fatal("redirected creator accepted", bad)
		}
	}
}
func TestReadinessRequiresWiredStore(t *testing.T) {
	for _, result := range []any{nil, map[string]any{"state": "running"}, map[string]any{"state": "running", "store_wired": false}, map[string]any{"state": "running", "store_wired": "true"}, map[string]any{"state": "stopped", "store_wired": true}} {
		if authorityReady(daemon.Response{Result: result}) {
			t.Fatal("unwired status accepted", result)
		}
	}
	if !authorityReady(daemon.Response{Result: map[string]any{"state": "running", "store_wired": true}}) {
		t.Fatal("wired running store refused")
	}
}
func TestInstallationVaultRefusesMissingReceiptBeforeNativeMutation(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	v := installationVault{vault.New(), filepath.Join(root, "missing"), filepath.Join(root, "data")}
	ctx := context.Background()
	h := strings.Repeat("a", 32)
	if e = v.Put(ctx, h, []byte("must not enter native custody")); e == nil {
		t.Fatal("put without installed owner")
	}
	if _, e = v.Get(ctx, h); e == nil {
		t.Fatal("get without installed owner")
	}
	if e = v.Delete(ctx, h); e == nil {
		t.Fatal("delete without installed owner")
	}
}

// A unit OS-custody double exercises dispatch only. The native three-build
// fixture separately checks that real Keychain namespaces are actually erased.
type deletionTestCustody struct {
	serviceVault
	installed, created int
	refuseLegacyRead   bool
	data               string
	creatorAtDelete    bool
}

func (v *deletionTestCustody) ReadForInstall(ctx context.Context, _ install.Record, h string) ([]byte, error) {
	if v.refuseLegacyRead {
		return nil, vault.ErrNotFound
	}
	return v.serviceVault.Get(ctx, h)
}
func (v *deletionTestCustody) DeleteForInstall(ctx context.Context, r install.Record, h string) error {
	if v.data != "" {
		p, e := readPending(v.data)
		v.creatorAtDelete = e == nil && p.Creator != nil && *p.Creator == r
	}
	v.installed++
	return v.serviceVault.Delete(ctx, h)
}
func (v *deletionTestCustody) DeleteCreatedForInstall(ctx context.Context, _ install.Record, h string) error {
	v.created++
	return v.serviceVault.Delete(ctx, h)
}
func TestInterruptedProvisionWithManifestUsesStagingAwareUninstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite native privacy acceptance is separate")
	}
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(root, "data")
	dir := filepath.Join(root, "install")
	digest := strings.Repeat("a", 64)
	creator := install.Record{Dir: dir, DataDir: data, SHA256: digest, Executable: filepath.Join(dir, "bin", digest, "telara-memory")}
	v := &deletionTestCustody{}
	ctx := context.Background()
	if e = provisionAuthority(ctx, data, v, nil); e != nil {
		t.Fatal(e)
	}
	p, e := readPending(data)
	if e != nil {
		t.Fatal(e)
	}
	p.Phase = "provisioning"
	p.Creator = &creator
	if e = writePending(data, p); e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(data, "custody-upgrade.json")
	if e = os.WriteFile(marker, []byte("unit staging sentinel, native backend owns validation"), 0600); e != nil {
		t.Fatal(e)
	}
	// The production native backend validates and cleans staging. CLI must reach
	// that backend rather than treating every provisioning marker as manifestless.
	if e = deleteNeverAdmittedAuthority(ctx, data, installedDeletionVault{v, creator}); e != nil {
		t.Fatal(e)
	}
	if v.installed != 1 || v.created != 0 || len(v.values) != 0 {
		t.Fatal("staging cleanup bypassed", v.installed, v.created)
	}
	if _, e = readPending(data); !os.IsNotExist(e) {
		t.Fatal("bootstrap evidence retained after successful native deletion", e)
	}
	// Without a manifest there is no authenticated transfer. Unexpected staging
	// must preserve both recovery records and refuse exact-creator deletion.
	if e = os.Remove(filepath.Join(data, "installed-authority.json")); e != nil {
		t.Fatal(e)
	}
	if e = writePending(data, p); e != nil {
		t.Fatal(e)
	}
	if e = deleteNeverAdmittedAuthority(ctx, data, installedDeletionVault{v, creator}); e == nil {
		t.Fatal("manifestless staging accepted")
	}
	if _, e = readPending(data); e != nil {
		t.Fatal("refusal discarded bootstrap evidence", e)
	}
	if e = os.Remove(marker); e != nil {
		t.Fatal(e)
	}
	if e = deleteNeverAdmittedAuthority(ctx, data, installedDeletionVault{v, creator}); e != nil {
		t.Fatal(e)
	}
	if v.created != 1 {
		t.Fatal("manifestless cleanup bypassed exact creator")
	}
}

func TestNeverAdmittedLegacyAbsenceCannotEstablishDeletion(t *testing.T) {
	if !vault.UpgradeHandoffRequired() {
		t.Skip("legacy code-identity custody is macOS native only")
	}
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(root, "data")
	dir := filepath.Join(root, "install")
	digest := strings.Repeat("a", 64)
	creator := install.Record{Dir: dir, DataDir: data, SHA256: digest, Executable: filepath.Join(dir, "bin", digest, "telara-memory")}
	v := &deletionTestCustody{refuseLegacyRead: true, data: data}
	ctx := context.Background()
	if e = provisionAuthority(ctx, data, v, nil); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(filepath.Join(data, pendingAuthority))
	if e != nil {
		t.Fatal(e)
	}
	if e = deleteNeverAdmittedAuthority(ctx, data, installedDeletionVault{v, creator}); !errors.Is(e, install.ErrUnverified) {
		t.Fatal("legacy absence reported as deletion", e)
	}
	after, e := os.ReadFile(filepath.Join(data, pendingAuthority))
	if e != nil || !bytes.Equal(before, after) || v.installed != 0 || len(v.values) != 1 {
		t.Fatal("legacy refusal lost recovery evidence", e)
	}
	v.refuseLegacyRead = false
	if e = deleteNeverAdmittedAuthority(ctx, data, installedDeletionVault{v, creator}); e != nil {
		t.Fatal(e)
	}
	if !v.creatorAtDelete || v.installed != 1 || len(v.values) != 0 {
		t.Fatal("verified legacy custodian was not durable before deletion")
	}
}
