package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/mcp"
	"github.com/Telara-Labs/hilo/contract/internal/node/vault"
)

type refusingVault struct{}

func TestNativeCustodyFailureHasExplicitPublicDiagnostic(t *testing.T) {
	if publicCode(vault.ErrUnavailable) != "secret_vault_unavailable" {
		t.Fatal("native custody gap hidden")
	}
	if publicCode(errors.New("runtime_authority_unavailable")) != "runtime_authority_unavailable" {
		t.Fatal("authority gap hidden")
	}
}

func (refusingVault) Put(context.Context, string, []byte) error {
	return errors.New("native vault locked")
}
func (refusingVault) Get(context.Context, string) ([]byte, error) {
	return nil, errors.New("native vault locked")
}
func (refusingVault) Delete(context.Context, string) error { return errors.New("native vault locked") }

func TestBootstrapRequiresNativeCustodyBeforeCreatingDatabase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite privacy adapter lacks Windows runtime acceptance")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	if err := provisionAuthority(context.Background(), data, refusingVault{}, nil); err == nil {
		t.Fatal("locked vault accepted")
	}
	for _, name := range []string{"memory.sqlite", "installed-authority.json"} {
		if _, err := os.Stat(filepath.Join(data, name)); !os.IsNotExist(err) {
			t.Fatal("profile created without custody", name, err)
		}
	}
	v := &serviceVault{}
	if err := provisionAuthority(context.Background(), data, v, nil); err != nil {
		t.Fatal(err)
	}
	if len(v.values) != 1 {
		t.Fatal("probe entry retained", len(v.values))
	}
	if err := provisionAuthority(context.Background(), data, v, nil); err != nil {
		t.Fatal("never-admitted retry", err)
	}
	if len(v.values) != 1 {
		t.Fatal("existing authority changed")
	}
	if err := disclosure.DeleteInstalledSecret(context.Background(), data, v); err != nil {
		t.Fatal(err)
	}
	if len(v.values) != 0 {
		t.Fatal("uninstall retained credential")
	}
	if err := disclosure.DeleteInstalledSecret(context.Background(), data, v); err != nil {
		t.Fatal("idempotent uninstall", err)
	}
}

func TestInstallValidationFailureDoesNotStrandAuthority(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite privacy adapter lacks Windows runtime acceptance")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	v := &serviceVault{}
	refused := errors.New("bad authenticated release input")
	err = provisionAuthority(context.Background(), data, v, func() error {
		if lock, e := ipc.Lock(filepath.Join(data, "db.lock")); e == nil {
			lock.Close()
			t.Fatal("installer did not retain database admission")
		}
		return refused
	})
	if !errors.Is(err, refused) {
		t.Fatal(err)
	}
	if len(v.values) != 0 {
		t.Fatal("failed install retained secret")
	}
	for _, name := range []string{"memory.sqlite", "installed-authority.json"} {
		if _, err := os.Stat(filepath.Join(data, name)); !os.IsNotExist(err) {
			t.Fatal("failed install created authority", name, err)
		}
	}
	if err = provisionAuthority(context.Background(), data, v, func() error { return nil }); err != nil {
		t.Fatal("corrected retry refused", err)
	}
	lock, err := ipc.Lock(filepath.Join(data, "db.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err = deleteAuthority(context.Background(), data, v); err == nil {
		t.Fatal("deleted authority while writer active")
	}
	if len(v.values) != 1 {
		t.Fatal("active-writer refusal changed vault")
	}
	lock.Close()
	if err = deleteAuthority(context.Background(), data, v); err != nil {
		t.Fatal(err)
	}
	if len(v.values) != 0 {
		t.Fatal("secret retained")
	}
}

type interruptedVault struct {
	serviceVault
	puts int
}

func (v *interruptedVault) Put(ctx context.Context, h string, b []byte) error {
	v.puts++
	if v.puts == 2 {
		return errors.New("native write interrupted")
	}
	return v.serviceVault.Put(ctx, h, b)
}

func TestInterruptedBootstrapHasExplicitSafeRetry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite privacy adapter lacks Windows runtime acceptance")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	v := &interruptedVault{}
	if err = provisionAuthority(context.Background(), data, v, func() error { return nil }); err == nil {
		t.Fatal("interrupted native write succeeded")
	}
	p, err := readPending(data)
	if err != nil || p.Handle == "" {
		t.Fatal("no durable cleanup handle", err)
	}
	if _, err = os.Stat(filepath.Join(data, "memory.sqlite")); err != nil {
		t.Fatal("failure did not exercise actual SQLite bootstrap", err)
	}
	// The installed manifest writer can create a file before a partial write or
	// crash. Provisioning phase proves this profile never admitted a backend.
	if err = os.WriteFile(filepath.Join(data, "installed-authority.json"), []byte(`{"version":`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = provisionAuthority(context.Background(), data, v, func() error { return nil }); err != nil {
		t.Fatal("explicit retry failed", err)
	}
	if len(v.values) != 1 {
		t.Fatal("retry retained abandoned keys", len(v.values))
	}
	if p, err := readPending(data); err != nil || p.Phase != "complete" {
		t.Fatal("never-admitted evidence missing", err)
	}
}

func TestCompletePhaseNeverDiscardsCorruptedManifest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite privacy adapter lacks Windows runtime acceptance")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	v := &serviceVault{}
	ctx := context.Background()
	if err = provisionAuthority(ctx, data, v, nil); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(data, "memory.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	var handle string
	for h := range v.values {
		handle = h
	}
	if err = writePending(data, pendingProfile{Version: 1, Handle: handle, Phase: "complete"}); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(data, "installed-authority.json"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = provisionAuthority(ctx, data, v, nil); err == nil {
		t.Fatal("completed corrupt profile reset")
	}
	after, err := os.ReadFile(filepath.Join(data, "memory.sqlite"))
	if err != nil || !bytes.Equal(before, after) || v.values[handle] == nil {
		t.Fatal("completed state discarded", err)
	}
	p, err := readPending(data)
	if err != nil || p.Phase != "complete" {
		t.Fatal("complete recovery fence lost", err)
	}
}

func TestCompletedBootstrapRecoveryNeverErasesCommittedProfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite privacy adapter lacks Windows runtime acceptance")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	v := &serviceVault{}
	ctx := context.Background()
	if err = provisionAuthority(ctx, data, v, nil); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(data, "memory.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	var handle string
	for h := range v.values {
		handle = h
	}
	if err = writePending(data, pendingProfile{Version: 1, Handle: handle}); err != nil {
		t.Fatal(err)
	}
	provider := mcp.InstalledRuntimeProvider{Provider: disclosure.InstalledProvider{Dir: data, Vault: v, Peers: servicePeer{}}}
	b, err := installedOpener(data, "unused", provider)(ctx)
	if err == nil || b != nil {
		if b != nil {
			b.Close()
		}
		t.Fatal("pending setup opened backend")
	}
	registered := false
	if err = provisionAuthority(ctx, data, v, func() error { registered = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !registered || len(v.values) != 1 || v.values[handle] == nil {
		t.Fatal("recovery recreated authority")
	}
	after, err := os.ReadFile(filepath.Join(data, "memory.sqlite"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("completed profile was modified", err)
	}
	if err = writePending(data, pendingProfile{Version: 1, Handle: handle}); err != nil {
		t.Fatal(err)
	}
	if err = deleteAuthority(ctx, data, v); err != nil {
		t.Fatal("pending uninstall", err)
	}
	if len(v.values) != 0 {
		t.Fatal("pending uninstall retained secret")
	}
	after, err = os.ReadFile(filepath.Join(data, "memory.sqlite"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("uninstall erased retained data", err)
	}
}

func TestPendingDaemonReleasesWriterForExplicitRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite privacy adapter lacks Windows runtime acceptance")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p, err := ipc.Resolve(filepath.Join(root, "data"), filepath.Join(root, "run"))
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err = writePending(p.Data, pendingProfile{Version: 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = daemon.Run(ctx, daemon.Config{Paths: p, Open: installedOpener(p.Data, "unused", nil)}); err == nil {
		t.Fatal("pending daemon started")
	}
	lock, err := ipc.Lock(filepath.Join(p.Data, "db.lock"))
	if err != nil {
		t.Fatal("pending daemon retained writer admission", err)
	}
	lock.Close()
	if err = provisionAuthority(ctx, p.Data, &serviceVault{}, func() error { return nil }); err != nil {
		t.Fatal("pending manager attempt prevented owner retry", err)
	}
}

func TestPendingRecoveryRejectsMalformedAndUnsafeRecords(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission and symlink negative cases")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	if err = ipc.ValidateDir(data, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(data, pendingAuthority)
	for _, raw := range []string{`{"version":1,"phase":"complete","vault_handle":""}`, `{"version":1,"phase":"admitted","vault_handle":""}`, `{}`, `{"version":2,"vault_handle":""}`, `{"version":1,"vault_handle":"invalid"}`, `{"version":1,"vault_handle":"","extra":true}`, `{"version":1,"vault_handle":""} {}`} {
		if err = os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = readPending(data); err == nil {
			t.Fatal("malformed pending accepted", raw)
		}
	}
	if err = writePending(data, pendingProfile{Version: 1}); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = readPending(data); err == nil {
		t.Fatal("loose pending accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(root, "sentinel")
	if err = os.WriteFile(sentinel, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(sentinel, filepath.Join(data, "memory.sqlite")); err != nil {
		t.Fatal(err)
	}
	if err = recoverPending(context.Background(), data, &serviceVault{}); err == nil {
		t.Fatal("unsafe database recovered")
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "preserve" {
		t.Fatal("recovery changed outside target", err)
	}
	if _, err = readPending(data); err != nil {
		t.Fatal("failed recovery lost marker", err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(sentinel, path); err != nil {
		t.Fatal(err)
	}
	if _, err = readPending(data); err == nil {
		t.Fatal("symlink marker accepted")
	}
}

func TestNeverStartedUninstallRetainsAdmissionFence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite native privacy acceptance is separate")
	}
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(root, "data")
	v := &serviceVault{}
	ctx := context.Background()
	if e = provisionAuthority(ctx, data, v, nil); e != nil {
		t.Fatal(e)
	}
	p, e := readPending(data)
	if e != nil || p.Phase != "complete" || len(v.values) != 1 {
		t.Fatal("missing never-admitted state", e)
	}
	lock, e := ipc.Lock(filepath.Join(data, "db.lock"))
	if e != nil {
		t.Fatal(e)
	}
	if e = deleteNeverAdmittedAuthority(ctx, data, v); !errors.Is(e, ipc.ErrBusy) {
		t.Fatal("writer bypass", e)
	}
	lock.Close()
	if e = deleteNeverAdmittedAuthority(ctx, data, v); e != nil || len(v.values) != 0 {
		t.Fatal("never-started secret retained", e)
	}
	if _, e = os.Stat(filepath.Join(data, "memory.sqlite")); e != nil {
		t.Fatal("data removed", e)
	}
}
func TestFirstOpenDurablyConsumesNeverAdmittedState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite native privacy acceptance is separate")
	}
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(root, "data")
	v := &serviceVault{}
	ctx := context.Background()
	if e = provisionAuthority(ctx, data, v, nil); e != nil {
		t.Fatal(e)
	}
	lock, e := ipc.Lock(filepath.Join(data, "db.lock"))
	if e != nil {
		t.Fatal(e)
	}
	provider := mcp.InstalledRuntimeProvider{Provider: disclosure.InstalledProvider{Dir: data, Vault: v, Peers: servicePeer{}}}
	b, e := installedOpener(data, "unused", provider)(ctx)
	if e != nil {
		lock.Close()
		t.Fatal(e)
	}
	p, e := readPending(data)
	if e != nil || p.Phase != "admitted" {
		t.Fatal("first open did not consume never-admitted state", e)
	}
	b.Close()
	lock.Close()
	if e = provisionAuthority(ctx, data, v, nil); e == nil {
		t.Fatal("admitted bootstrap retried")
	}
}

func TestNeverAdmittedShortcutRechecksPhaseUnderLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SQLite native privacy acceptance is separate")
	}
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(root, "data")
	v := &serviceVault{}
	ctx := context.Background()
	if e = provisionAuthority(ctx, data, v, nil); e != nil {
		t.Fatal(e)
	}
	// Model a daemon admission after uninstall's preliminary complete read,
	// followed by a crash. No settlement receipt exists for this profile.
	p, e := readPending(data)
	if e != nil || p.Phase != "complete" {
		t.Fatal(e)
	}
	lock, e := ipc.Lock(filepath.Join(data, "db.lock"))
	if e != nil {
		t.Fatal(e)
	}
	p.Phase = "admitted"
	if e = writePending(data, p); e != nil {
		t.Fatal(e)
	}
	lock.Close()
	if e = deleteNeverAdmittedAuthority(ctx, data, v); !errors.Is(e, errAuthorityAdmitted) {
		t.Fatal("stale shortcut admitted", e)
	}
	if len(v.values) != 1 {
		t.Fatal("crashed admitted profile lost authority")
	}
}
