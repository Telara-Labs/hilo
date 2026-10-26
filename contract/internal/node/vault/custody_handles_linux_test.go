//go:build linux

package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/bundle"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/peer"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/syncnode"
	"github.com/godbus/dbus/v5"
)

// recordedHandles lists every handle with its own custody record.
func recordedHandles(t *testing.T, data string) map[string]string {
	t.Helper()
	names, e := filepath.Glob(filepath.Join(data, custodyItemPrefix+"*.json"))
	if e != nil {
		t.Fatal(e)
	}
	out := map[string]string{}
	for _, name := range names {
		h := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(name), custodyItemPrefix), ".json")
		m, e := readLinuxRecord(data, filepath.Base(name))
		if e != nil {
			t.Fatal("unreadable handle record", name, e)
		}
		out[h] = m.State
	}
	return out
}

func randomHandle(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(b[:])
}

// profileSecretLifecycle drives the real callers that share one profile's
// custody: installation, export-key creation, sync login, refresh credential
// replacement, logout and uninstall. Every step uses a fresh vault object, as
// a separate command process would, and checks that earlier secrets survive.
// remaining reports how many of this profile's items the service still holds.
func profileSecretLifecycle(t *testing.T, data string, r install.Record, remaining func() int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	v := New()
	if e := v.PrepareForInstall(ctx, r); e != nil {
		t.Fatal(e)
	}
	// Installation's disposable probe uses its own generation and record.
	probe := randomHandle(t)
	if e := v.PutForInstall(ctx, r, probe, []byte("disposable custody probe")); e != nil {
		t.Fatal(e)
	}
	if e := v.DeleteForInstall(ctx, r, probe); e != nil {
		t.Fatal(e)
	}
	if e := v.PrepareForInstall(ctx, r); e != nil {
		t.Fatal(e)
	}
	if e := disclosure.BootstrapInstalled(ctx, data, "Linux native custody fixture", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{}, Installed{Vault: v, Record: r}); e != nil {
		t.Fatal("install", e)
	}
	var runtimeHandle string
	for h, state := range recordedHandles(t, data) {
		if h != probe && state == "ready" {
			if runtimeHandle != "" {
				t.Fatal("ambiguous installed authority")
			}
			runtimeHandle = h
		}
	}
	if runtimeHandle == "" {
		t.Fatal("installed authority has no handle record")
	}
	authority := func(step string) {
		t.Helper()
		rt, e := (disclosure.InstalledProvider{Dir: data, Vault: ForProfile(data), Peers: peer.Authority{}}).Load(ctx)
		if e != nil {
			t.Fatal(step, "installed authority lost", e)
		}
		rt.Material.Clear()
	}
	authority("install")

	// Export-key creation adds a second, independent secret.
	sum := sha256.Sum256([]byte(data))
	id := bundle.Identity{Genesis: hex.EncodeToString(sum[:16]), Device: hex.EncodeToString(sum[16:]), Machine: "6f1c2d3e-4b5a-4c6d-8e7f-901a2b3c4d5e"}
	offer, e := bundle.EnsureExportKey(ctx, data, ForProfile(data), id)
	if e != nil {
		t.Fatal("export key", e)
	}
	exportKey := func(step string) {
		t.Helper()
		k, e := bundle.LoadExportIdentity(ctx, data, ForProfile(data), id)
		if e != nil || k.Recipient().String() != offer.Recipient {
			t.Fatal(step, "export key lost", e)
		}
	}
	exportKey("export")
	authority("export")

	// Login adds the DPoP key and a refresh credential.
	key, _, e := syncnode.NewCredential(ctx, ForProfile(data))
	if e != nil {
		t.Fatal("login key", e)
	}
	refresh, e := syncnode.StoreRefresh(ctx, ForProfile(data), "synthetic refresh one")
	if e != nil {
		t.Fatal("login refresh", e)
	}
	scope := nodesync.Scope{Tenant: "tenant"}
	login := func(step, refreshHandle, want string) {
		t.Helper()
		c, e := (syncnode.VaultKeystore{Vault: ForProfile(data), Key: key, Refresh: refreshHandle, Tenant: "tenant"}).Load(ctx, scope)
		if e != nil || c.Refresh != want {
			t.Fatal(step, "login credentials lost", e)
		}
		digest := sha256.Sum256([]byte(step))
		if _, e = c.DPoP.Sign(ctx, digest[:]); e != nil {
			t.Fatal(step, "login key unusable", e)
		}
	}
	login("login", refresh, "synthetic refresh one")
	exportKey("login")
	authority("login")

	// Credential replacement stores the new refresh slot, then retires the old.
	replacement, e := syncnode.StoreRefresh(ctx, ForProfile(data), "synthetic refresh two")
	if e != nil {
		t.Fatal("replacement", e)
	}
	if e = syncnode.DeleteCredentials(ctx, ForProfile(data), refresh); e != nil {
		t.Fatal("retire replaced refresh", e)
	}
	if b, e := ForProfile(data).Get(ctx, refresh); b != nil || !errors.Is(e, ErrNotFound) {
		clear(b)
		t.Fatal("replaced refresh credential still readable", e)
	}
	login("replace", replacement, "synthetic refresh two")
	exportKey("replace")
	authority("replace")

	// Logout deletes only the sync credentials.
	if e = syncnode.DeleteCredentials(ctx, ForProfile(data), key, replacement); e != nil {
		t.Fatal("logout", e)
	}
	for _, h := range []string{key, replacement} {
		if b, e := ForProfile(data).Get(ctx, h); b != nil || !errors.Is(e, ErrNotFound) {
			clear(b)
			t.Fatal("logout left a credential", e)
		}
	}
	exportKey("logout")
	authority("logout")
	if n := remaining(); n != 2 {
		t.Fatal("expected installed authority and export key only", n)
	}

	// Uninstall from a new process, then remove the export key.
	if e = New().DeleteForInstall(ctx, r, runtimeHandle); e != nil {
		t.Fatal("uninstall", e)
	}
	exportKey("uninstall")
	states := recordedHandles(t, data)
	var exportHandle string
	for h, state := range states {
		if state == "ready" {
			exportHandle = h
		}
	}
	if exportHandle == "" || ForProfile(data).Delete(ctx, exportHandle) != nil {
		t.Fatal("export key cleanup")
	}
	if n := remaining(); n != 0 {
		t.Fatal("custody retained items", n)
	}
	for h, state := range recordedHandles(t, data) {
		if state != "deleted" {
			t.Fatal("handle not proven deleted", h, state)
		}
	}
	if len(recordedHandles(t, data)) != 6 {
		t.Fatal("expected probe, authority, export, key and two refresh records", recordedHandles(t, data))
	}
	// Idempotent retries of every deletion.
	for h := range recordedHandles(t, data) {
		if e = ForProfile(data).Delete(ctx, h); e != nil {
			t.Fatal("idempotent delete", e)
		}
	}
}

// A profile holds every secret its commands need at the same time.
func TestSecretServiceProfileHoldsIndependentSecrets(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		s, _ := privateSecretService(t, mode)
		data := linuxProfile(t)
		r := linuxInstalledRecord(t, data)
		profileSecretLifecycle(t, data, r, func() int {
			s.mu.Lock()
			defer s.mu.Unlock()
			return len(s.collections[testC1]) + len(s.collections[testC2])
		})
	})
}

// A crash in one handle's creation neither disturbs another handle's record
// nor loses its own exact recovery.
func TestSecretServiceSecondHandleCrashRecoveryIsIndependent(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		s, address := privateSecretService(t, mode)
		data := linuxProfile(t)
		ctx := context.Background()
		first, second := linuxTestHandle, randomHandle(t)
		if e := ForProfile(data).Put(ctx, first, []byte("synthetic profile authority")); e != nil {
			t.Fatal(e)
		}
		before, e := os.ReadFile(filepath.Join(data, custodyItemFile(first)))
		if e != nil {
			t.Fatal(e)
		}
		s.mu.Lock()
		s.loseReply = true
		s.mu.Unlock()
		if e = ForProfile(data).Put(ctx, second, []byte("second secret")); e != ErrUnavailable {
			t.Fatal(e)
		}
		s.mu.Lock()
		s.loseReply = false
		s.mu.Unlock()
		m, e := readLinuxRecord(data, custodyItemFile(second))
		if e != nil || m.State != "creating" || m.Creation == "" {
			t.Fatal("second creation intent missing", m, e)
		}
		after, e := os.ReadFile(filepath.Join(data, custodyItemFile(first)))
		if e != nil || !bytes.Equal(before, after) {
			t.Fatal("second handle rewrote the first handle's record", e)
		}
		s.aliasTo(t, address, testC2)
		s.restart(t, address)
		linuxProcess(t, data, "get")
		if b, e := ForProfile(data).Get(ctx, second); e != ErrUnavailable || len(b) != 0 {
			clear(b)
			t.Fatal("empty placeholder became authority", e)
		}
		if e = ForProfile(data).Delete(ctx, second); e != nil {
			t.Fatal("interrupted second creation not recoverable", e)
		}
		linuxProcess(t, data, "get")
		if e = ForProfile(data).Put(ctx, second, []byte("second secret")); e != nil {
			t.Fatal("next generation refused", e)
		}
		b, e := ForProfile(data).Get(ctx, second)
		if e != nil || string(b) != "second secret" {
			t.Fatal(e)
		}
		clear(b)
		linuxProcess(t, data, "delete")
		if e = ForProfile(data).Delete(ctx, second); e != nil {
			t.Fatal(e)
		}
		s.mu.Lock()
		count := len(s.collections[testC1])
		s.mu.Unlock()
		if count != 0 {
			t.Fatal("retained items", count)
		}
	})
}

// Concurrent writers for different handles in one profile keep every record.
func TestSecretServiceConcurrentHandlesKeepEveryRecord(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		s, _ := privateSecretService(t, mode)
		data := linuxProfile(t)
		ctx := context.Background()
		if e := ForProfile(data).bindCustody(ctx, data, true); e != nil {
			t.Fatal(e)
		}
		handles := make([]string, 8)
		for i := range handles {
			handles[i] = randomHandle(t)
		}
		var wg sync.WaitGroup
		errs := make([]error, len(handles))
		for i, h := range handles {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = ForProfile(data).Put(ctx, h, []byte(fmt.Sprint("secret ", i)))
			}()
		}
		wg.Wait()
		for i, h := range handles {
			if errs[i] != nil {
				t.Fatal(errs[i])
			}
			b, e := ForProfile(data).Get(ctx, h)
			if e != nil || string(b) != fmt.Sprint("secret ", i) {
				t.Fatal("lost handle", i, e)
			}
			clear(b)
		}
		states := recordedHandles(t, data)
		got := make([]string, 0, len(states))
		for h, state := range states {
			if state != "ready" {
				t.Fatal(h, state)
			}
			got = append(got, h)
		}
		want := append([]string(nil), handles...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatal("records", got)
		}
		for _, h := range handles {
			if e := ForProfile(data).Delete(ctx, h); e != nil {
				t.Fatal(e)
			}
		}
		s.mu.Lock()
		count := len(s.collections[testC1])
		s.mu.Unlock()
		if count != 0 {
			t.Fatal("retained items", count)
		}
	})
}

// A record written before per-handle records keeps its handle in the
// selection record. It stays readable and deletable, and new handles get
// their own records beside it.
func TestSecretServiceLegacyRecordCoexistsWithNewHandles(t *testing.T) {
	secretModes(t, func(t *testing.T, mode string) {
		s, _ := privateSecretService(t, mode)
		data := linuxProfile(t)
		ctx := context.Background()
		if e := ForProfile(data).Put(ctx, linuxTestHandle, []byte("synthetic profile authority")); e != nil {
			t.Fatal(e)
		}
		// Rewrite into the earlier single-handle layout.
		m, e := linuxItemRecord(data)
		if e != nil {
			t.Fatal(e)
		}
		if e = writeLinuxLocation(data, *m); e != nil {
			t.Fatal(e)
		}
		if e = os.Remove(filepath.Join(data, custodyItemFile(linuxTestHandle))); e != nil {
			t.Fatal(e)
		}
		other := randomHandle(t)
		if e = ForProfile(data).Put(ctx, other, []byte("export key")); e != nil {
			t.Fatal("new handle refused beside legacy record", e)
		}
		linuxProcess(t, data, "get")
		if main, e := readLinuxLocation(data); e != nil || main.Handle != linuxTestHandle || main.State != "ready" {
			t.Fatal("legacy record changed", main, e)
		}
		// A handle recorded in both layouts is ambiguous and refuses.
		dup := *m
		if e = writeLinuxRecord(data, custodyItemFile(linuxTestHandle), dup); e != nil {
			t.Fatal(e)
		}
		if b, e := ForProfile(data).Get(ctx, linuxTestHandle); e != ErrUnavailable {
			clear(b)
			t.Fatal("ambiguous record accepted", e)
		}
		if e = os.Remove(filepath.Join(data, custodyItemFile(linuxTestHandle))); e != nil {
			t.Fatal(e)
		}
		linuxProcess(t, data, "delete")
		if main, e := readLinuxLocation(data); e != nil || main.State != "deleted" || main.Item != m.Item {
			t.Fatal("legacy deletion not recorded exactly", main, e)
		}
		b, e := ForProfile(data).Get(ctx, other)
		if e != nil || string(b) != "export key" {
			t.Fatal("new handle lost", e)
		}
		clear(b)
		if e = ForProfile(data).Delete(ctx, other); e != nil {
			t.Fatal(e)
		}
		s.mu.Lock()
		count := len(s.collections[testC1])
		s.mu.Unlock()
		if count != 0 {
			t.Fatal("retained items", count)
		}
	})
}

// The same lifecycle against the Secret Service on the session bus, such as
// GNOME Keyring. It removes only the items it created.
func TestSecretServiceNativeProfileHoldsIndependentSecrets(t *testing.T) {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Skip("no session bus; native multi-secret custody UNVERIFIED")
	}
	data := linuxProfile(t)
	r := linuxInstalledRecord(t, data)
	remaining := func() int {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		main, e := readLinuxLocation(data)
		if e != nil {
			t.Fatal(e)
		}
		s, e := openSession(ctx, false, dbus.ObjectPath(main.Collection))
		if e != nil {
			t.Fatal(e)
		}
		defer s.close()
		n := 0
		for h := range recordedHandles(t, data) {
			var items []dbus.ObjectPath
			if e = s.call(s.collection, "Collection.SearchItems", map[string]string{"service": service, "handle": h}).Store(&items); e != nil {
				t.Fatal(e)
			}
			n += len(items)
		}
		return n
	}
	t.Cleanup(func() {
		ctx := context.Background()
		for h, state := range recordedHandles(t, data) {
			if state != "deleted" {
				_ = ForProfile(data).Delete(ctx, h)
			}
		}
	})
	main := func() string {
		m, e := readLinuxLocation(data)
		if e != nil {
			return "unread"
		}
		return m.Alias + " " + m.Collection
	}
	profileSecretLifecycle(t, data, r, remaining)
	t.Logf("selected %s, %d handle records", main(), len(recordedHandles(t, data)))
}
