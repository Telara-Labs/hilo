//go:build darwin && cgo

package vault

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/bundle"
	"github.com/Telara-Labs/hilo/contract/internal/node/custodyguard"
	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/hilo/contract/internal/node/sync"
	"github.com/Telara-Labs/hilo/contract/internal/node/syncnode"
	"github.com/Telara-Labs/hilo/contract/sig"
)

type fullProfileExpectations struct {
	JKT       string            `json:"jkt"`
	Recipient string            `json:"recipient"`
	Active    map[string]string `json:"active_sha256"`
	Retired   []string          `json:"retired_handles"`
}

func fixtureOpaqueHandle() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// This is a custody state-machine fixture over real native slots and validated
// typed descriptors. The synthetic login/context/join descriptors do not claim
// authenticated hosted enrollment or governed repository-ingress acceptance.
func fullProfileFixture(ctx context.Context, v *Vault, data, action string) error {
	path := filepath.Join(data, "custody-test-expectations.json")
	if action == "seed-full-profile" {
		v.profile = data
		return custodyguard.With(ctx, data, func(ctx context.Context) error {
			jkt, err := syncnode.CreateKey(ctx, data, v)
			if err != nil {
				return err
			}
			p, err := syncnode.LoadProfile(data)
			if err != nil {
				return err
			}
			refresh, err := syncnode.StoreRefresh(ctx, v, "synthetic native refresh")
			if err != nil {
				return err
			}
			retired, err := syncnode.StoreRefresh(ctx, v, "synthetic retired refresh")
			if err != nil {
				return err
			}
			scalar, err := v.Get(ctx, p.Credential)
			if err != nil {
				return err
			}
			key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
			clear(scalar)
			if err != nil {
				return err
			}
			public, err := nodesync.PublicJWKOf(&key.PublicKey)
			key.D.SetInt64(0)
			if err != nil {
				return err
			}
			servicePub, servicePrivate, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			clear(servicePrivate)
			p.Refresh, p.Origin, p.Tenant, p.User, p.Config, p.AuthIssuer = refresh, "https://custody.invalid", "fixture", "fixture", "fixture", "fixture"
			p.AuthKey = &public
			p.ServiceKeys = []syncnode.ServiceKey{{KeyID: sig.KeyID(servicePub), Public: base64.RawURLEncoding.EncodeToString(servicePub)}}
			p.Grant = &nodesync.MemoryGrant{Origin: "local", GenesisID: p.Genesis, DeviceID: p.Device, Ops: []string{"push", "pull", "erase"}, Repos: []string{"r1:" + hex.EncodeToString(bytes.Repeat([]byte{1}, 32))}, ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}
			p.Retired = []string{retired}
			if err := syncnode.SaveProfile(data, p); err != nil {
				return err
			}
			id, err := bundle.ProfileIdentity(data)
			if err != nil {
				return err
			}
			offer, err := bundle.EnsureExportKey(ctx, data, v, id)
			if err != nil {
				return err
			}
			pending, err := fixtureOpaqueHandle()
			if err != nil {
				return err
			}
			_, signing, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			if err := v.Put(ctx, pending, signing); err != nil {
				clear(signing)
				return err
			}
			clear(signing)
			join, _ := json.Marshal(map[string]any{"version": 1, "genesis": id.Genesis, "device": id.Device, "machine": id.Machine, "vault_handle": pending, "device_add": hex.EncodeToString(bytes.Repeat([]byte{3}, 32))})
			if err := store.WriteProfileRecord(data, store.JoinPendingName, join); err != nil {
				return err
			}
			contextHandle, err := fixtureOpaqueHandle()
			if err != nil {
				return err
			}
			contextRetired, err := fixtureOpaqueHandle()
			if err != nil {
				return err
			}
			for _, handle := range []string{contextHandle, contextRetired} {
				secret := make([]byte, 32)
				if _, err := rand.Read(secret); err != nil {
					return err
				}
				err := v.Put(ctx, handle, secret)
				clear(secret)
				if err != nil {
					return err
				}
			}
			contexts, _ := json.Marshal(map[string]any{"version": 1, "owner": p.Genesis, "machine": p.Device, "contexts": []disclosure.RepositoryContext{
				{ID: "1234567890abcdef1234567890abcdef", Binding: hex.EncodeToString(bytes.Repeat([]byte{4}, 32)), Generation: 1, Credential: "0b7a2859-6756-4a14-98c8-dfce2214e653", Handle: contextHandle, State: "active", Native: "created"},
				{ID: "abcdef1234567890abcdef1234567890", Binding: hex.EncodeToString(bytes.Repeat([]byte{5}, 32)), Generation: 1, Credential: "a7d89320-fb60-46d5-b5fc-fd9697e22ca9", Handle: contextRetired, State: "retired", Native: "created"},
			}})
			if err := store.WriteProfileRecord(data, store.RepositoryContextsName, contexts); err != nil {
				return err
			}
			refs, _, err := inventory(data)
			if err != nil {
				return err
			}
			expect := fullProfileExpectations{JKT: jkt, Recipient: offer.Recipient, Active: map[string]string{}}
			for _, ref := range refs {
				if cleanupPurpose(ref.Purpose) {
					expect.Retired = append(expect.Retired, ref.Handle)
					continue
				}
				secret, err := v.Get(ctx, ref.Handle)
				if err != nil {
					return err
				}
				h := sha256.Sum256(secret)
				clear(secret)
				expect.Active[ref.Handle] = hex.EncodeToString(h[:])
			}
			b, _ := json.Marshal(expect)
			return writeExclusivePublicReceipt(path, b)
		})
	}
	b, err := privateRead(path)
	if err != nil {
		return err
	}
	var expect fullProfileExpectations
	if err := json.Unmarshal(b, &expect); err != nil {
		return err
	}
	if action == "absent-full-profile" {
		for handle := range expect.Active {
			secret, err := v.nativeGetOwn(handle)
			clear(secret)
			if !errors.Is(err, ErrNotFound) {
				return ErrUnavailable
			}
		}
		return nil
	}
	v.profile = data
	p, err := syncnode.LoadProfile(data)
	if err != nil {
		return err
	}
	jkt, err := syncnode.CredentialThumbprint(ctx, v, p.Credential)
	if err != nil || jkt != expect.JKT {
		return ErrUnavailable
	}
	id, err := bundle.ProfileIdentity(data)
	if err != nil {
		return err
	}
	key, err := bundle.LoadExportIdentity(ctx, data, v, id)
	if err != nil || key.Recipient().String() != expect.Recipient {
		return ErrUnavailable
	}
	for handle, expected := range expect.Active {
		secret, err := v.Get(ctx, handle)
		h := sha256.Sum256(secret)
		clear(secret)
		if err != nil || hex.EncodeToString(h[:]) != expected {
			return ErrUnavailable
		}
	}
	for _, handle := range expect.Retired {
		secret, err := v.nativeGetOwn(handle)
		clear(secret)
		if !errors.Is(err, ErrNotFound) {
			return ErrUnavailable
		}
	}
	return nil
}

func TestNativeWholeProfileCustodyTwoUpgrades(t *testing.T) {
	_, keychain := isolatedVault(t)
	root := profileTestDir(t)
	data, run, dir, home := filepath.Join(root, "data"), filepath.Join(root, "run"), filepath.Join(root, "install"), filepath.Join(root, "home")
	for _, path := range []string{data, run, dir, home} {
		if err := ipc.ValidateDir(path, true); err != nil {
			t.Fatal(err)
		}
	}
	type image struct{ path, digest string }
	var images []image
	for _, variant := range []string{"profile-first", "profile-second", "profile-third"} {
		exe := filepath.Join(root, variant)
		cmd := exec.Command("go", "test", "-p", "1", "-c", "-o", exe, "-ldflags=-X github.com/Telara-Labs/hilo/contract/internal/node/vault.custodyBuild="+variant, ".")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture build %v %s", err, b)
		}
		if b, err := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", exe).CombinedOutput(); err != nil {
			t.Fatalf("fixture sign %v %s", err, b)
		}
		b, err := os.ReadFile(exe)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		digest := hex.EncodeToString(h[:])
		retained := handoffTarget(install.Record{Dir: dir}, digest)
		if err := ipc.ValidateDir(filepath.Dir(retained), true); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(retained, b, 0700); err != nil {
			t.Fatal(err)
		}
		images = append(images, image{retained, digest})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	r := install.Record{Schema: 1, Dir: dir, Home: home, Label: "dev.memory.full-profile.fixture", Platform: "darwin", UserID: strconv.Itoa(os.Geteuid()), Executable: images[0].path, SHA256: images[0].digest, Version: "first", DataDir: data, RunDir: run}
	publish := func(r install.Record) {
		t.Helper()
		for name, value := range map[string]any{"install.json": r, "intent.json": map[string]string{"mode": "stop", "sha256": r.SHA256, "version": r.Version, "session": ""}} {
			b, _ := json.Marshal(value)
			if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	publish(r)
	action := func(i int, name, target string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, images[i].path, "custody-upgrade-fixture", name, keychain, data, dir, target)
		cmd.Env = replaceHome(os.Environ(), home)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s image%d: %v %s", name, i, err, b)
		}
	}
	action(0, "bootstrap-installed", images[1].digest)
	action(0, "seed-full-profile", images[1].digest)
	refs, _, err := inventory(data)
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]bool{}
	for _, r := range refs {
		roles[r.Purpose] = true
	}
	for _, role := range []string{"installed-authority", "sync-dpop", "sync-refresh", "sync-retired", "bundle-export", "bundle-pending-join", "repository-context", "repository-context-retired"} {
		if !roles[role] {
			t.Fatal("missing role", role)
		}
	}
	// Real native slots are copied twice. Explicit source-abort also checks
	// staging cleanup and retry before either receipt publication is modeled.
	action(0, "prepare", images[1].digest)
	action(0, "abort-full-profile", images[1].digest)
	action(1, "absent-full-profile", images[1].digest)
	for i := 0; i < 2; i++ {
		action(i, "prepare", images[i+1].digest)
		action(i, "verify-full-profile", images[i+1].digest)
		next := r
		next.Executable = images[i+1].path
		next.SHA256 = images[i+1].digest
		next.Version = []string{"second", "third"}[i]
		publish(next)
		action(i+1, "recover", images[i+1].digest)
		action(i+1, "check-full-profile", images[i+1].digest)
		action(i, "absent-full-profile", images[i+1].digest)
		if _, err := readProfileHandoff(data); !os.IsNotExist(err) {
			t.Fatal("freeze retained after recovery", err)
		}
		r = next
	}
}
