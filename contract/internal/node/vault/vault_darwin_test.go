//go:build darwin && cgo

package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/peer"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func isolatedVault(t *testing.T) (*Vault, string) {
	t.Helper()
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		t.Fatal(err)
	}
	defer clear(password)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "native-test.keychain")
	v, err := createIsolated(path, password)
	if err != nil {
		t.Fatalf("isolated native keychain unavailable (no login-keychain fallback): %v", err)
	}
	t.Cleanup(v.closeIsolated)
	return v, path
}

func TestNativeKeychainLifecycleAndDurability(t *testing.T) {
	v, path := isolatedVault(t)
	ctx := context.Background()
	h := "0123456789abcdef0123456789abcdef"
	want := []byte{0, 1, 0, 255, 42}
	if err := v.Put(ctx, h, want); err != nil {
		t.Fatal(err)
	}
	want[0] = 8
	if err := v.Put(ctx, h, []byte("replacement")); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	other, err := openIsolated(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.closeIsolated()
	b, err := other.Get(ctx, h)
	if err != nil || !bytes.Equal(b, []byte{0, 1, 0, 255, 42}) {
		t.Fatal(err)
	}
	clear(b)
	b, err = v.Get(ctx, h)
	if err != nil || b[1] != 1 {
		t.Fatal(err)
	}
	clear(b)
	if err := v.Delete(ctx, h); err != nil {
		t.Fatal(err)
	}
	if err := other.Delete(ctx, h); err != nil {
		t.Fatal(err)
	}
	if b, err := other.Get(ctx, h); b != nil || !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestNativeKeychainConcurrentPutRefusesReplacement(t *testing.T) {
	v, _ := isolatedVault(t)
	ctx := context.Background()
	h := "fedcba9876543210fedcba9876543210"
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- v.Put(ctx, h, []byte("one value")) }()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrExists) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatal("successful writers", wins)
	}
}

var signingIdentity = flag.String("custody-signing-identity", "", "Native test signing certificate with a stable designated requirement")
var custodyBuild = "first"

func TestCustodyBuildHelper(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "custody-build-helper" {
		return
	}
	// Path and handle are nonsecret fixture identifiers; secret bytes use pipes.
	v, e := openIsolated(os.Args[len(os.Args)-3])
	if e != nil {
		t.Fatal(e)
	}
	defer v.closeIsolated()
	ctx := context.Background()
	data := os.Args[len(os.Args)-2]
	if custodyBuild == "first" {
		e = disclosure.BootstrapInstalled(ctx, data, "Signed custody fixture", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{}, v)
	}
	if e != nil {
		t.Fatal(e)
	}
	loaded, e := (disclosure.InstalledProvider{Dir: data, Vault: v, Peers: peer.Authority{}}).Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer loaded.Material.Clear()
	fmt.Fprintln(os.Stdout, "custody-ok "+loaded.Config.OwnerGenesis)
	if custodyBuild != "first" {
		if e = disclosure.DeleteInstalledSecret(ctx, data, v); e != nil {
			t.Fatal(e)
		}
	}

}
func TestNativeCustodyAcrossDifferentSignedBuilds(t *testing.T) {
	if *signingIdentity == "" {
		t.Skip("requires -custody-signing-identity for two separately built signed executables; upgrade custody UNVERIFIED")
	}
	_, path := isolatedVault(t)
	data := filepath.Dir(path)
	var firstOwner string
	for _, variant := range []string{"first", "second"} {
		exe := filepath.Join(t.TempDir(), variant)
		cmd := exec.Command("go", "test", "-p", "1", "-c", "-o", exe, "-ldflags=-X github.com/Telara-Labs/telara-memory/contract/internal/node/vault.custodyBuild="+variant, ".")
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("build %v %s", e, b)
		}
		if b, e := exec.Command("/usr/bin/codesign", "--force", "--sign", *signingIdentity, "--identifier", "dev.telara.memory.custody-test", exe).CombinedOutput(); e != nil {
			t.Fatalf("sign %v %s", e, b)
		}
		certPrefix := filepath.Join(t.TempDir(), "signer-")
		if b, e := exec.Command("/usr/bin/codesign", "--display", "--extract-certificates", certPrefix, exe).CombinedOutput(); e != nil {
			t.Fatalf("extract signer %v %s", e, b)
		}
		cert, e := os.ReadFile(certPrefix + "0")
		if e != nil {
			t.Fatal(e)
		}
		fingerprint := sha1.Sum(cert)
		requirement := `=designated => identifier "dev.telara.memory.custody-test" and certificate leaf = H"` + hex.EncodeToString(fingerprint[:]) + `"`
		if b, e := exec.Command("/usr/bin/codesign", "--force", "--sign", *signingIdentity, "--identifier", "dev.telara.memory.custody-test", "--requirements", requirement, exe).CombinedOutput(); e != nil {
			t.Fatalf("stable requirement sign %v %s", e, b)
		}
		cmd = exec.Command(exe, "-test.run=^TestCustodyBuildHelper$", "--", path, data, "custody-build-helper")
		output, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v %s", variant, e, output)
		}
		owner := ""
		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(line, "custody-ok ") {
				owner = strings.TrimPrefix(line, "custody-ok ")
			}
		}
		if owner == "" {
			t.Fatalf("missing retained-profile proof %s", output)
		}
		if variant == "first" {
			firstOwner = owner
		} else if owner != firstOwner {
			t.Fatal("owner changed across builds")
		}

	}
}

func TestAdHocSigningPolicyUsesCreatorIdentityWithoutOpeningKeychain(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	output, _ := exec.Command("/usr/bin/codesign", "--display", "--verbose=4", exe).CombinedOutput()
	if !bytes.Contains(output, []byte("Signature=adhoc")) {
		t.Skip("test executable is not ad hoc signed")
	}
	if !signingPolicyAvailable() {
		t.Fatal("ad hoc creator custody refused")
	}
}
