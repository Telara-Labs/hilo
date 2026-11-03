//go:build darwin && cgo

package vault

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/custodyguard"
	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

func profileTestDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	return d
}

func fixtureProfileHandoff(t *testing.T) profileHandoff {
	t.Helper()
	dir := profileTestDir(t)
	sourceDigest := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	targetDigest := hex.EncodeToString(bytes.Repeat([]byte{2}, 32))
	source := install.Record{Schema: 1, Dir: filepath.Join(dir, "install"), DataDir: dir, SHA256: sourceDigest}
	source.Executable = handoffTarget(source, sourceDigest)
	handle := "0123456789abcdef0123456789abcdef"
	old := creatorReceipt{1, handle, source.Executable, sourceDigest, service + ".source", filepath.Join(dir, "keychain"), sourceDigest, "bound"}
	next := old
	next.Image, next.Digest, next.Namespace = handoffTarget(source, targetDigest), targetDigest, service+".target"
	return profileHandoff{2, source, targetDigest, sourceDigest, "preparing", []profileTransfer{{Reference: custodyguard.Handle{Handle: handle, Purpose: "installed-authority"}, Source: old, Target: next, Stage: "planned"}}}
}

func TestProfileHandoffStrictJournalAndGeneration(t *testing.T) {
	m := fixtureProfileHandoff(t)
	if err := writeProfileHandoff(m); err != nil {
		t.Fatal(err)
	}
	got, err := readProfileHandoff(m.Source.DataDir)
	if err != nil || !reflect.DeepEqual(got, m) {
		t.Fatal(got, err)
	}
	mutations := []func(*profileHandoff){
		func(m *profileHandoff) { m.Version = 1 },
		func(m *profileHandoff) { m.Generation = "" },
		func(m *profileHandoff) { m.Target = "../foreign" },
		func(m *profileHandoff) {
			m.Entries[0].Target.Expected = hex.EncodeToString(bytes.Repeat([]byte{3}, 32))
		},
		func(m *profileHandoff) { m.Entries[0].Target.Image = "/foreign" },
		func(m *profileHandoff) { m.Entries[0].Reference.Purpose = "unknown" },
		func(m *profileHandoff) { m.Entries = append(m.Entries, m.Entries[0]) },
		func(m *profileHandoff) { m.Phase = "ready" },
		func(m *profileHandoff) { m.Entries[0].Retired = true },
	}
	for i, mutate := range mutations {
		b, _ := json.Marshal(m)
		var bad profileHandoff
		if err := json.Unmarshal(b, &bad); err != nil {
			t.Fatal(err)
		}
		mutate(&bad)
		if err := bad.validate(); err == nil {
			t.Fatalf("invalid journal mutation %d accepted", i)
		}
	}
	foreign := profileTestDir(t)
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(foreign, custodyguard.ProfileJournal), b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProfileHandoff(foreign); err == nil {
		t.Fatal("journal redirected profile")
	}
}

func TestProfileCreatorPlannedGetIsReadOnlyDuringFreeze(t *testing.T) {
	v, keychain := isolatedVault(t)
	dir := profileTestDir(t)
	v.profile = dir
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	handle := "1234567890abcdef1234567890abcdef"
	secret := []byte("synthetic high entropy commitment test material")
	if err := v.Put(ctx, handle, secret); err != nil {
		t.Fatal(err)
	}
	r, err := readCreator(dir, handle)
	if err != nil {
		t.Fatal(err)
	}
	planned := r
	planned.Phase = "planned"
	if err := writeCreator(dir, &r, planned); err != nil {
		t.Fatal(err)
	}
	before, err := privateRead(filepath.Join(dir, creatorName(handle)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, custodyguard.ProfileJournal), []byte("freeze"), 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reader, err := openIsolated(keychain)
			if err != nil {
				t.Error(err)
				return
			}
			defer reader.closeIsolated()
			reader.profile = dir
			var b []byte
			for {
				b, err = reader.Get(ctx, handle)
				if !errors.Is(err, ipc.ErrBusy) || ctx.Err() != nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if err != nil || !bytes.Equal(b, secret) {
				t.Errorf("planned read %v", err)
			}
			clear(b)
		}()
	}
	wg.Wait()
	after, err := privateRead(filepath.Join(dir, creatorName(handle)))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("Get changed frozen creator evidence", err)
	}
	if err := os.Remove(filepath.Join(dir, custodyguard.ProfileJournal)); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete(ctx, handle); err != nil {
		t.Fatal(err)
	}
}

func TestProfilePendingAbandonNeverTouchesUnrecordedCollision(t *testing.T) {
	v, _ := isolatedVault(t)
	dir := profileTestDir(t)
	ctx := context.Background()
	handle := "fedcba0987654321fedcba0987654321"
	// Create an unrelated same-name item before the profile has any creator
	// intent. Abandonment must not look it up, adopt it, or remove it.
	want := []byte("unrelated native item")
	if err := v.Put(ctx, handle, want); err != nil {
		t.Fatal(err)
	}
	v.profile = dir
	if err := v.bindCustody(ctx, dir, true); err != nil {
		t.Fatal(err)
	}
	if err := v.AbandonPlanned(ctx, handle); err != nil {
		t.Fatal(err)
	}
	got, err := v.get(ctx, handle)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("unrecorded item changed", err)
	}
	clear(got)
	if err := v.delete(ctx, handle); err != nil {
		t.Fatal(err)
	}
}

func TestProfileCreatorRetainsTransientInvokerBeforePut(t *testing.T) {
	_, keychain := isolatedVault(t)
	root := profileTestDir(t)
	data, dir, run := filepath.Join(root, "data"), filepath.Join(root, "install"), filepath.Join(root, "run")
	for _, d := range []string{data, dir, run} {
		if err := ipc.ValidateDir(d, true); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	digest := hex.EncodeToString(sum[:])
	installed := handoffTarget(install.Record{Dir: dir}, digest)
	if err := ipc.ValidateDir(filepath.Dir(installed), true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed, b, 0700); err != nil {
		t.Fatal(err)
	}
	transient := filepath.Join(root, "downloaded-test-cli")
	if err := os.WriteFile(transient, b, 0700); err != nil {
		t.Fatal(err)
	}
	r := install.Record{Schema: 1, Dir: dir, Home: root, Label: "dev.memory.transient.fixture", Platform: "darwin", UserID: strconv.Itoa(os.Geteuid()), Executable: installed, SHA256: digest, Version: "transient-test", DataDir: data, RunDir: run}
	for name, value := range map[string]any{"install.json": r, "intent.json": map[string]string{"mode": "stop", "sha256": digest, "version": r.Version, "session": ""}} {
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	handle := "6789abcdef0123456789abcdef012345"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	action := func(exe, action string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, exe, "custody-upgrade-fixture", action, keychain, data, dir, handle)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", action, err, out)
		}
	}
	action(transient, "profile-put")
	creator, err := readCreator(data, handle)
	if err != nil || creator.Image == transient || creator.Digest != digest {
		t.Fatal("creator not retained", err)
	}
	if err := os.Remove(transient); err != nil {
		t.Fatal(err)
	}
	action(installed, "profile-get")
	action(installed, "profile-delete")
}

func TestLegacyMaintenanceRejectsChangedRecordAndKey(t *testing.T) {
	m := fixtureProfileHandoff(t)
	source := m.Source
	source.Platform = "darwin"
	current := source
	current.SHA256, current.Executable, current.Version = m.Target, handoffTarget(source, m.Target), "next"
	if !maintenanceRecords(source, current) {
		t.Fatal("valid record relation rejected")
	}
	for _, mutate := range []func(*install.Record){
		func(r *install.Record) { r.DataDir += "/foreign" },
		func(r *install.Record) { r.Label = "foreign" },
		func(r *install.Record) { r.UserID = "foreign" },
		func(r *install.Record) { r.Executable = source.Executable },
	} {
		bad := current
		mutate(&bad)
		if maintenanceRecords(source, bad) {
			t.Fatal("foreign record accepted")
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := key.D.FillBytes(make([]byte, 32))
	defer clear(secret)
	got, err := rawDPoPThumbprint(secret)
	if err != nil || len(got) != 43 {
		t.Fatal(got, err)
	}
	if _, err := rawDPoPThumbprint(bytes.Repeat([]byte{0}, 32)); err == nil {
		t.Fatal("zero scalar accepted")
	}
	if err := New().RecoverLegacyDPoP(nil, source, current, got); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

var ownedLegacyMaintenance = flag.String("owned-legacy-maintenance", "", "Explicit reviewed private maintenance request for the single owned legacy DPoP fixture")

func TestOwnedLegacyDPoPMaintenance(t *testing.T) {
	if *ownedLegacyMaintenance == "" {
		t.Skip("explicit owned maintenance request required")
	}
	path := *ownedLegacyMaintenance
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || ipc.ValidateDir(filepath.Dir(path), false) != nil {
		t.Fatal("unsafe request")
	}
	b, err := privateReadLimit(path, 32768)
	if err != nil {
		t.Fatal(err)
	}
	var q struct {
		Source, Current install.Record
		JKT             string
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF {
		t.Fatal("invalid request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), profileLifecycleWait)
	defer cancel()
	if err := New().RecoverLegacyDPoP(ctx, q.Source, q.Current, q.JKT); err != nil {
		t.Fatal(err)
	}
	// A retry must prove the completed receipt and identical target key rather
	// than requiring the deliberately retired source slot to reappear.
	if err := New().RecoverLegacyDPoP(ctx, q.Source, q.Current, q.JKT); err != nil {
		t.Fatal("retry", err)
	}
	t.Log("same-handle DPoP recovery and completed-receipt retry verified")
}
