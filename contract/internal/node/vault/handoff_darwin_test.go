//go:build darwin && cgo

package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/custodyguard"
	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/peer"
)

func TestHandoffMarkerValidationAndAtomicPublication(t *testing.T) {
	data, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(data, 0700); e != nil {
		t.Fatal(e)
	}
	digest := fmt.Sprintf("%064x", 1)
	r := install.Record{Dir: filepath.Join(data, "install"), DataDir: data, SHA256: digest}
	r.Executable = handoffTarget(r, digest)
	m := custodyHandoff{1, r, fmt.Sprintf("%064x", 2), "0123456789abcdef0123456789abcdef", "", "prepared", false}
	if e = writeHandoff(m); e != nil {
		t.Fatal(e)
	}
	got, e := readHandoff(data)
	if e != nil || got != m {
		t.Fatal(got, e)
	}
	for _, mutate := range []func(*custodyHandoff){
		func(m *custodyHandoff) { m.Phase = "complete" },
		func(m *custodyHandoff) { m.Target = "../other" },
		func(m *custodyHandoff) { m.Source.DataDir += "/other" },
		func(m *custodyHandoff) { m.Source.Executable = "/other" },
		func(m *custodyHandoff) { m.Handle = "bad" },
		func(m *custodyHandoff) { m.Keychain = "relative" },
	} {
		bad := m
		mutate(&bad)
		b, _ := json.Marshal(bad)
		if e = os.WriteFile(filepath.Join(data, handoffFile), b, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = readHandoff(data); e == nil {
			t.Fatal("invalid marker accepted", bad)
		}
	}
	if e = writeHandoff(m); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(filepath.Join(data, handoffFile), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = readHandoff(data); e == nil {
		t.Fatal("public marker accepted")
	}
	if e = os.Remove(filepath.Join(data, handoffFile)); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(filepath.Join(data, "missing"), filepath.Join(data, handoffFile)); e != nil {
		t.Fatal(e)
	}
	if _, e = readHandoff(data); e == nil {
		t.Fatal("symlink marker accepted")
	}
}

func TestHandoffImageAndHelperRefuseUntrustedInput(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "image")
	b := []byte("fixture, never executed")
	if e = os.WriteFile(path, b, 0700); e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(b)
	digest := hex.EncodeToString(hash[:])
	f, e := pinHandoffImage(path, digest)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	if _, e = pinHandoffImage(path, fmt.Sprintf("%064x", 7)); e == nil {
		t.Fatal("wrong digest accepted")
	}
	if e = os.Chmod(path, 0770); e != nil {
		t.Fatal(e)
	}
	if _, e = pinHandoffImage(path, digest); e == nil {
		t.Fatal("writable image accepted")
	}
	if e = os.Chmod(path, 0700); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "link")
	if e = os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e = pinHandoffImage(link, digest); e == nil {
		t.Fatal("symlink image accepted")
	}
	for _, input := range []string{"", `{}`, `{"source":{},"unknown":true}`, string(make([]byte, 17000))} {
		for _, arg := range []string{resumeArg, recoverArg} {
			var out bytes.Buffer
			if !runHandoffHelper([]string{arg}, bytes.NewBufferString(input), &out) || !bytes.Equal(out.Bytes(), []byte{1}) {
				t.Fatal("malformed recovery request accepted", arg)
			}
		}
	}
	out := &custodyOutput{}
	if _, e = out.Write(make([]byte, maxSecret+1)); e != nil {
		t.Fatal(e)
	}
	if _, e = out.Write([]byte{0}); e == nil {
		t.Fatal("unbounded helper output accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = New().imageOperation(ctx, path, digest, 4, "0123456789abcdef0123456789abcdef", []byte("secret")); e == nil {
		t.Fatal("canceled transfer accepted")
	}
}

// Fixture actions use actual OS custody and the retained SQLite profile. Receipt
// publication below models the installer's atomic receipt step, not a service-
// manager success claim. No Telara service is mocked.
func runCustodyUpgradeFixture(args []string) bool {
	if len(args) == 0 || args[0] != "custody-upgrade-fixture" {
		return false
	}
	if len(args) != 6 {
		os.Exit(2)
	}
	action, kc, data, dir, target := args[1], args[2], args[3], args[4], args[5]
	v, e := openIsolated(kc)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	defer v.closeIsolated()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	report, se := install.Status(ctx, dir)
	if se != nil && !errors.Is(se, install.ErrUnavailable) {
		fmt.Fprintln(os.Stderr, se)
		os.Exit(1)
	}
	var bootstrapVault disclosure.SecretVault = v
	switch action {
	case "seed-full-profile", "check-full-profile", "absent-full-profile":
		e = fullProfileFixture(ctx, v, data, action)
	case "verify-full-profile":
		e = VerifyPreparedProfile(ctx, report.Record, target)
	case "abort-full-profile":
		e = v.AbortProfileUpgrade(ctx, report.Record)
	case "profile-put":
		v.profile = data
		e = v.Put(ctx, target, []byte("owned transient caller credential"))
	case "profile-get":
		v.profile = data
		var b []byte
		b, e = v.Get(ctx, target)
		if e == nil && !bytes.Equal(b, []byte("owned transient caller credential")) {
			e = ErrUnavailable
		}
		clear(b)
	case "profile-delete":
		v.profile = data
		e = v.Delete(ctx, target)
	case "bootstrap-installed", "bootstrap":
		bootstrapVault = Installed{Vault: v, Record: report.Record}
		e = disclosure.BootstrapInstalled(ctx, data, "Installed target fixture", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{}, bootstrapVault)
	case "poison":
		h, he := installedHandle(data)
		e = he
		if e == nil {
			e = v.Put(ctx, h, bytes.Repeat([]byte{7}, 96))
		}
	case "clear":
		h, he := installedHandle(data)
		e = he
		if e == nil {
			e = v.Delete(ctx, h)
		}
	case "uninstall-secret":
		h, he := installedHandle(data)
		e = he
		if e == nil {
			e = v.PrepareProfileUninstall(ctx, report.Record)
		}
		if e == nil {
			e = v.DeleteForInstall(ctx, report.Record, h)
		}
	case "uninstall-direct":
		h, he := installedHandle(data)
		e = he
		if e == nil {
			e = v.DeleteForInstall(ctx, report.Record, h)
		}
	case "prepare":
		e = v.PrepareUpgrade(ctx, report.Record, target)
	case "recover":
		e = v.RecoverUpgrade(ctx, report.Record)
	case "resume":
		e = v.ResumeUpgrade(ctx, report.Record, target)
	case "absent":
		h, he := installedHandle(data)
		e = he
		if e == nil {
			var b []byte
			b, e = v.Get(ctx, h)
			clear(b)
			if errors.Is(e, ErrNotFound) {
				e = nil
			} else {
				e = errors.New("old item still readable")
			}
		}
	case "delete":
		e = disclosure.DeleteInstalledSecret(ctx, data, v)
	case "load":
	default:
		e = ErrInvalid
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if action == "bootstrap" || action == "bootstrap-installed" || action == "load" || action == "recover" {
		loaded, le := (disclosure.InstalledProvider{Dir: data, Vault: bootstrapVault, Peers: peer.Authority{}}).Load(ctx)
		if le != nil {
			fmt.Fprintln(os.Stderr, le)
			os.Exit(1)
		}
		loaded.Material.Clear()
		fmt.Fprintln(os.Stdout, loaded.Config.OwnerGenesis)
	}
	return true
}

func TestNativeCustodyCollisionRemainsFailClosed(t *testing.T) {
	v, keychain := isolatedVault(t)
	root := filepath.Dir(keychain)
	home := filepath.Join(root, "home")
	if e := os.Mkdir(home, 0700); e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(root, "data")
	run := filepath.Join(root, "run")
	dir := filepath.Join(root, "install")
	p, e := ipc.Resolve(data, run)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Prepare(); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(data, "authority-test.pending"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	type image struct{ path, digest string }
	builds := make([]image, 0, 2)
	for _, variant := range []string{"first", "second"} {
		exe := filepath.Join(root, variant)
		cmd := exec.Command("go", "test", "-p", "1", "-c", "-o", exe, "-ldflags=-X github.com/Telara-Labs/hilo/contract/internal/node/vault.custodyBuild="+variant, ".")
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("build %v %s", e, b)
		}
		if b, e := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", exe).CombinedOutput(); e != nil {
			t.Fatalf("ad hoc sign %v %s", e, b)
		}
		b, e := os.ReadFile(exe)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(b)
		digest := hex.EncodeToString(sum[:])
		path := filepath.Join(dir, "bin", digest, "telara-memory")
		if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0700); e != nil {
			t.Fatal(e)
		}
		builds = append(builds, image{path, digest})
	}
	if builds[0].digest == builds[1].digest {
		t.Fatal("two builds are identical")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	original := install.Record{Schema: 1, Dir: dir, Home: home, Label: "dev.memory.custody.fixture", Platform: runtime.GOOS, UserID: strconv.Itoa(os.Geteuid()), Executable: builds[0].path, SHA256: builds[0].digest, Version: "first", DataDir: data, RunDir: run}
	writeJSON := func(name string, value any) {
		t.Helper()
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeJSON("install.json", original)
	writeJSON("intent.json", map[string]string{"mode": "stop", "sha256": original.SHA256, "version": original.Version, "session": ""})
	targetDigest := builds[1].digest
	runAction := func(i int, name string) ([]byte, error) {
		t.Helper()
		cmd := exec.CommandContext(ctx, builds[i].path, "custody-upgrade-fixture", name, keychain, data, dir, targetDigest)
		cmd.Env = replaceHome(os.Environ(), home)
		return cmd.CombinedOutput()
	}
	action := func(i int, name string) string {
		t.Helper()
		b, e := runAction(i, name)
		if e != nil {
			t.Fatalf("%s build %d %v %s", name, i, e, b)
		}
		return string(bytes.TrimSpace(b))
	}
	owner := action(0, "bootstrap-installed")
	action(1, "poison")
	failed, e := runAction(0, "prepare")
	if e == nil || !bytes.Contains(failed, []byte(ErrUnavailable.Error())) {
		t.Fatalf("prepared over a known target collision or returned the wrong refusal: %s", failed)
	}
	m, e := readProfileHandoff(data)
	if e != nil {
		t.Fatal("collision journal unavailable", e)
	}
	h, e := installedHandle(data)
	if e != nil {
		t.Fatal(e)
	}
	var collisionFound bool
	knownSource := make(map[string][32]byte)
	originalSource := make(map[string]creatorReceipt)
	originalEntries := append([]profileTransfer(nil), m.Entries...)
	collisionEntries := 0
	for _, entry := range m.Entries {
		if entry.Stage == "collision" {
			collisionEntries++
			if entry.Reference.Handle != h {
				t.Fatal("unexpected handle collision in fixture", entry.Reference.Purpose)
			}
			collisionFound = collisionFound || entry.Reference.Handle == h
		} else if !cleanupPurpose(entry.Reference.Purpose) && entry.Stage != "planned" {
			t.Fatalf("target custody copied before the poisoned handle collision: purpose=%s stage=%s", entry.Reference.Purpose, entry.Stage)
		}
		if cleanupPurpose(entry.Reference.Purpose) {
			continue
		}
		secret, readErr := v.creatorOperation(ctx, entry.Source, 9, nil)
		if readErr != nil {
			t.Fatal("read exact source custody", entry.Reference.Purpose, readErr)
		}
		knownSource[entry.Reference.Handle] = sha256.Sum256(secret)
		originalSource[entry.Reference.Handle] = entry.Source
		clear(secret)
		if entry.Reference.Handle != h && entry.Source.Namespace != entry.Target.Namespace {
			secret, readErr = v.creatorOperation(ctx, entry.Target, 9, nil)
			clear(secret)
			if !errors.Is(readErr, ErrNotFound) {
				t.Fatalf("owned target existed before collision for %s: %v", entry.Reference.Purpose, readErr)
			}
		}
	}
	if !collisionFound || collisionEntries != 1 {
		t.Fatal("journal did not retain Stage=collision for the poisoned handle")
	}
	poison, e := v.imageOperation(ctx, builds[1].path, builds[1].digest, 9, h, nil)
	if e != nil {
		t.Fatal("read exact target poison", e)
	}
	poisonSHA := sha256.Sum256(poison)
	if !bytes.Equal(poison, bytes.Repeat([]byte{7}, 96)) {
		t.Fatal("target poison bytes changed before retries")
	}
	clear(poison)
	markerBefore, e := privateRead(filepath.Join(data, handoffFile))
	if e != nil {
		t.Fatal("runtime custody marker missing", e)
	}
	profileBefore, e := privateRead(filepath.Join(data, custodyguard.ProfileJournal))
	if e != nil {
		t.Fatal("full-profile custody journal missing", e)
	}
	checkRetained := func(operation string) {
		t.Helper()
		marker, err := privateRead(filepath.Join(data, handoffFile))
		if err != nil || !bytes.Equal(marker, markerBefore) {
			t.Fatal(operation, "changed runtime custody marker", err)
		}
		profile, err := privateRead(filepath.Join(data, custodyguard.ProfileJournal))
		if err != nil || !bytes.Equal(profile, profileBefore) {
			t.Fatal(operation, "changed full-profile custody journal", err)
		}
		got, err := readProfileHandoff(data)
		if err != nil {
			t.Fatal(operation, "removed collision journal", err)
		}
		if got.Version != m.Version || got.Source != m.Source || got.Target != m.Target || got.Generation != m.Generation || got.Phase != m.Phase || len(got.Entries) != len(originalEntries) {
			t.Fatal(operation, "changed full-profile journal identity or entry count")
		}
		found := false
		for i, entry := range got.Entries {
			original := originalEntries[i]
			if entry.Reference != original.Reference || entry.Source != original.Source || entry.Target != original.Target || entry.Stage != original.Stage || entry.RetirementPending != original.RetirementPending || entry.Retired != original.Retired {
				t.Fatal(operation, "changed original journal entry identity", original.Reference.Purpose)
			}
			if entry.Reference.Handle == h && entry.Stage == "collision" {
				found = true
			}
		}
		for handle, sourceReceipt := range originalSource {
			want, ok := knownSource[handle]
			if !ok {
				t.Fatal(operation, "missing source snapshot", handle)
			}
			secret, readErr := v.creatorOperation(ctx, sourceReceipt, 9, nil)
			actual := sha256.Sum256(secret)
			clear(secret)
			if readErr != nil || actual != want {
				t.Fatal(operation, "changed original source secret", handle, readErr)
			}
		}
		if !found {
			t.Fatal(operation, "did not retain Stage=collision")
		}
		secret, readErr := v.imageOperation(ctx, builds[1].path, builds[1].digest, 9, h, nil)
		actual := sha256.Sum256(secret)
		clear(secret)
		if readErr != nil || actual != poisonSHA {
			t.Fatal(operation, "changed known target poison", readErr)
		}
		if got := action(0, "load"); got != owner {
			t.Fatal(operation, "changed source authority")
		}
	}
	for i := 0; i < 2; i++ {
		for _, name := range []string{"prepare", "abort-full-profile"} {
			b, err := runAction(0, name)
			if err == nil || !bytes.Contains(b, []byte(ErrUnavailable.Error())) {
				t.Fatalf("collision %s unexpectedly succeeded or returned the wrong refusal: %s", name, b)
			}
			checkRetained(name)
		}
	}
	// Teardown removes only this test's known poison and journal-listed helper handles.
	action(1, "clear")
	for _, entry := range m.Entries {
		for _, creator := range []creatorReceipt{entry.Source, entry.Target} {
			if _, err := v.creatorOperation(ctx, creator, 6, nil); err != nil && !errors.Is(err, ErrNotFound) {
				t.Fatal("exact fixture handle teardown", entry.Reference.Purpose, err)
			}
		}
	}
}

func TestNativeCustodyAcrossDifferentAdHocBuilds(t *testing.T) {
	v, keychain := isolatedVault(t)
	root := filepath.Dir(keychain)
	home := filepath.Join(root, "home")
	if e := os.Mkdir(home, 0700); e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(root, "data")
	run := filepath.Join(root, "run")
	dir := filepath.Join(root, "install")
	p, e := ipc.Resolve(data, run)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Prepare(); e != nil {
		t.Fatal(e)
	}
	// Prevent automatic test-daemon startup from opening a not-yet-created DB.
	if e = os.WriteFile(filepath.Join(data, "authority-test.pending"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	type image struct{ path, digest string }
	builds := make([]image, 0, 3)
	for _, variant := range []string{"first", "second", "third", "older-helper"} {
		exe := filepath.Join(root, variant)
		cmd := exec.Command("go", "test", "-p", "1", "-c", "-o", exe, "-ldflags=-X github.com/Telara-Labs/hilo/contract/internal/node/vault.custodyBuild="+variant, ".")
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("build %v %s", e, b)
		}
		// Explicit ad hoc signing also covers Intel Go builds without auto-signing.
		if b, e := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", exe).CombinedOutput(); e != nil {
			t.Fatalf("ad hoc sign %v %s", e, b)
		}
		b, e := os.ReadFile(exe)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(b)
		digest := hex.EncodeToString(sum[:])
		path := filepath.Join(dir, "bin", digest, "telara-memory")
		if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0700); e != nil {
			t.Fatal(e)
		}
		builds = append(builds, image{path, digest})
	}
	if builds[0].digest == builds[1].digest {
		t.Fatal("two builds are identical")
	}
	// A real static target has native custody compiled out.
	static := filepath.Join(root, "static")
	buildStatic := exec.Command("go", "build", "-p", "2", "-o", static, "../cmd/hilo")
	buildStatic.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if b, e := buildStatic.CombinedOutput(); e != nil {
		t.Fatalf("static build %v %s", e, b)
	}
	if b, e := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", static).CombinedOutput(); e != nil {
		t.Fatalf("static sign %v %s", e, b)
	}
	rawStatic, e := os.ReadFile(static)
	if e != nil {
		t.Fatal(e)
	}
	staticSum := sha256.Sum256(rawStatic)
	staticDigest := hex.EncodeToString(staticSum[:])
	staticPath := filepath.Join(dir, "bin", staticDigest, "telara-memory")
	if e = os.MkdirAll(filepath.Dir(staticPath), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(staticPath, rawStatic, 0700); e != nil {
		t.Fatal(e)
	}
	builds = append(builds, image{staticPath, staticDigest})
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	// Native custody fixture uses real validated receipts without registering a
	// service. Stop intent selects the receipt without requiring an OS manager.
	original := install.Record{Schema: 1, Dir: dir, Home: home, Label: "dev.memory.custody.fixture", Platform: runtime.GOOS, UserID: strconv.Itoa(os.Geteuid()), Executable: builds[0].path, SHA256: builds[0].digest, Version: "first", DataDir: data, RunDir: run}
	fixtureRecord, _ := json.Marshal(original)
	if e = os.WriteFile(filepath.Join(dir, "install.json"), fixtureRecord, 0600); e != nil {
		t.Fatal(e)
	}
	fixtureIntent, _ := json.Marshal(map[string]string{"mode": "stop", "sha256": original.SHA256, "version": original.Version, "session": ""})
	if e = os.WriteFile(filepath.Join(dir, "intent.json"), fixtureIntent, 0600); e != nil {
		t.Fatal(e)
	}
	targetDigest := builds[1].digest
	action := func(i int, name string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, builds[i].path, "custody-upgrade-fixture", name, keychain, data, dir, targetDigest)
		cmd.Env = replaceHome(os.Environ(), home)
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("%s build %d %v %s", name, i, e, b)
		}
		return string(bytes.TrimSpace(b))
	}
	// The invoking build is neither the installed target nor its successor.
	// Bootstrap and authority readback must both use the installed target.
	owner := action(2, "bootstrap-installed")
	if got := action(0, "load"); got != owner {
		t.Fatal("target could not read initial custody")
	}
	action(2, "absent")
	// An interrupted prepared marker retains old custody and permits retry.
	action(0, "prepare")
	m, e := readHandoff(data)
	if e != nil {
		t.Fatal(e)
	}
	m.Phase = "prepared"
	if e = writeHandoff(m); e != nil {
		t.Fatal(e)
	}
	if got := action(0, "load"); got != owner {
		t.Fatal("old custody lost before receipt switch")
	}
	action(0, "resume")
	m, e = readHandoff(data)
	if e != nil || m.Phase != "ready" {
		t.Fatal(m, e)
	}
	next := original
	next.SHA256 = builds[1].digest
	next.Executable = builds[1].path
	next.Version = "second"
	// Publish the real receipt/intent types to exercise post-publication recovery.
	writeJSON := func(name string, value any) {
		t.Helper()
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeJSON("install.json", next)
	writeJSON("intent.json", map[string]string{"mode": "stop", "sha256": next.SHA256, "version": next.Version, "session": ""})
	// Losing the target item after readback must not authorize old deletion.
	action(1, "clear")
	missing := exec.CommandContext(ctx, builds[1].path, "custody-upgrade-fixture", "recover", keychain, data, dir, builds[1].digest)
	missing.Env = replaceHome(os.Environ(), home)
	if b, e := missing.CombinedOutput(); e == nil {
		t.Fatalf("missing target authorized retirement %s", b)
	}
	if got := action(0, "load"); got != owner {
		t.Fatal("missing target lost source custody")
	}
	writeJSON("install.json", original)
	writeJSON("intent.json", map[string]string{"mode": "stop", "sha256": original.SHA256, "version": original.Version, "session": ""})
	action(0, "prepare")
	writeJSON("install.json", next)
	writeJSON("intent.json", map[string]string{"mode": "stop", "sha256": next.SHA256, "version": next.Version, "session": ""})
	if got := action(1, "recover"); got != owner {
		t.Fatal("owner changed across upgrade")
	}
	action(0, "absent")
	if _, e = readHandoff(data); !os.IsNotExist(e) {
		t.Fatal("pending marker not cleared", e)
	}
	// Simulate a crash after old deletion but before pending-marker removal.
	if e = writeHandoff(m); e != nil {
		t.Fatal(e)
	}
	if got := action(1, "recover"); got != owner {
		t.Fatal("post-delete recovery lost custody")
	}
	action(1, "uninstall-secret")
	// Parent build must not be able to read either ad hoc build's private slot.
	h, e := installedHandle(data)
	if e != nil {
		t.Fatal(e)
	}
	b, e := v.Get(context.Background(), h)
	clear(b)
	if !errors.Is(e, ErrNotFound) {
		t.Fatal("unexpected fixture item", e)
	}
	// A separate real profile proves uninstall also removes pending staging
	// custody while the old receipt is still authoritative.
	data = filepath.Join(root, "abort-data")
	if e = ipc.ValidateDir(data, true); e != nil {
		t.Fatal(e)
	}
	original.DataDir = data
	writeJSON("install.json", original)
	writeJSON("intent.json", map[string]string{"mode": "stop", "sha256": original.SHA256, "version": original.Version, "session": ""})
	action(0, "bootstrap")
	action(0, "prepare")
	action(2, "uninstall-secret")
	action(0, "absent")
	action(1, "absent")
	if _, e = readHandoff(data); !os.IsNotExist(e) {
		t.Fatal("aborted transfer marker retained", e)
	}
	// A never-started profile without a transfer is deleted from another build.
	data = filepath.Join(root, "never-started-data")
	if e = ipc.ValidateDir(data, true); e != nil {
		t.Fatal(e)
	}
	original.DataDir = data
	writeJSON("install.json", original)
	writeJSON("intent.json", map[string]string{"mode": "stop", "sha256": original.SHA256, "version": original.Version, "session": ""})
	action(2, "bootstrap-installed")
	action(1, "uninstall-secret")
	action(0, "absent")

	// Publication happened but startup recovery has not. A third build dispatches
	// teardown into the current receipt image, then removes both native slots.
	data = filepath.Join(root, "post-publication-data")
	if e = ipc.ValidateDir(data, true); e != nil {
		t.Fatal(e)
	}
	original.DataDir = data
	writeJSON("install.json", original)
	writeJSON("intent.json", map[string]string{"mode": "stop", "sha256": original.SHA256, "version": original.Version, "session": ""})
	action(2, "bootstrap-installed")
	action(0, "prepare")
	next.DataDir = data
	writeJSON("install.json", next)
	writeJSON("intent.json", map[string]string{"mode": "stop", "sha256": next.SHA256, "version": next.Version, "session": ""})
	action(2, "uninstall-secret")
	action(0, "absent")
	action(1, "absent")
	if _, e = readHandoff(data); !os.IsNotExist(e) {
		t.Fatal("post-publication marker retained", e)
	}

	// Both new refusals leave no marker. Historical runtime-only markers retain
	// every slot and require explicit maintenance rather than automatic cleanup.
	for _, incompatible := range []int{3, 4} {
		for _, recovery := range []string{"uninstall", "replacement"} {
			data = filepath.Join(root, fmt.Sprintf("incompatible-%d-%s", incompatible, recovery))
			if e = ipc.ValidateDir(data, true); e != nil {
				t.Fatal(e)
			}
			original.DataDir = data
			writeJSON("install.json", original)
			writeJSON("intent.json", map[string]string{"mode": "stop", "sha256": original.SHA256, "version": original.Version, "session": ""})
			owner := action(2, "bootstrap-installed")
			targetDigest = builds[incompatible].digest
			bad := exec.CommandContext(ctx, builds[0].path, "custody-upgrade-fixture", "prepare", keychain, data, dir, targetDigest)
			bad.Env = replaceHome(os.Environ(), home)
			if b, e := bad.CombinedOutput(); e == nil {
				t.Fatalf("incompatible %d accepted %s", incompatible, b)
			}
			if _, e := readHandoff(data); !os.IsNotExist(e) {
				t.Fatal("incompatible refusal published marker", e)
			}
			if got := action(0, "load"); got != owner {
				t.Fatal("refusal changed source custody")
			}
			h, e := installedHandle(data)
			if e != nil {
				t.Fatal(e)
			}
			m := custodyHandoff{1, original, targetDigest, h, keychain, "prepared", false}
			// Historical older helpers may already have received authority. Refusal
			// must retain that exact known slot, not infer absence from a handshake.
			if incompatible == 3 {
				secret, e := v.imageOperation(ctx, original.Executable, original.SHA256, 9, h, nil)
				if e != nil {
					t.Fatal(e)
				}
				readback, e := v.imageOperation(ctx, builds[incompatible].path, targetDigest, 4, h, secret)
				clear(secret)
				clear(readback)
				if e != nil {
					t.Fatal(e)
				}
			}
			if e = writeHandoff(m); e != nil {
				t.Fatal(e)
			}
			markerBefore, e := privateRead(filepath.Join(data, handoffFile))
			if e != nil {
				t.Fatal(e)
			}
			sourceSecret, e := v.imageOperation(ctx, original.Executable, original.SHA256, 9, h, nil)
			if e != nil {
				t.Fatal(e)
			}
			expectedSecret := sha256.Sum256(sourceSecret)
			clear(sourceSecret)
			refused := func(name, digest string, typed bool) {
				t.Helper()
				cmd := exec.CommandContext(ctx, builds[2].path, "custody-upgrade-fixture", name, keychain, data, dir, digest)
				cmd.Env = replaceHome(os.Environ(), home)
				b, err := cmd.CombinedOutput()
				if err == nil {
					t.Fatalf("historical %s unexpectedly succeeded: %s", name, b)
				}
				if typed && !bytes.Contains(b, []byte(ErrLegacyCustody.Error())) {
					t.Fatalf("historical %s wrong refusal: %s", name, b)
				}
				after, err := privateRead(filepath.Join(data, handoffFile))
				if err != nil || !bytes.Equal(after, markerBefore) {
					t.Fatal("refusal changed historical marker", err)
				}
				if _, err := os.Lstat(filepath.Join(data, custodyguard.ProfileJournal)); !os.IsNotExist(err) {
					t.Fatal("historical refusal created a full-profile freeze", err)
				}
				if got := action(0, "load"); got != owner {
					t.Fatal("historical refusal lost source custody")
				}
				sourceSecret, err := v.imageOperation(ctx, original.Executable, original.SHA256, 9, h, nil)
				sourceSum := sha256.Sum256(sourceSecret)
				clear(sourceSecret)
				if err != nil || sourceSum != expectedSecret {
					t.Fatal("historical refusal changed exact source bytes", err)
				}
				if incompatible == 3 {
					secret, err := v.imageOperation(ctx, builds[3].path, builds[3].digest, 9, h, nil)
					targetSum := sha256.Sum256(secret)
					clear(secret)
					if err != nil || targetSum != expectedSecret {
						t.Fatal("historical refusal changed known target custody", err)
					}
				}
			}
			refused("uninstall-secret", targetDigest, true)
			refused("uninstall-direct", targetDigest, true)
			if recovery == "replacement" {
				targetDigest = builds[1].digest
				refused("resume", targetDigest, false)
				action(1, "absent")
			}
			// A published historical target must also refuse before dispatching
			// recovery into an incompatible retained image. In particular an old
			// native helper must not retire the still-readable source slot.
			published := original
			published.Executable = builds[incompatible].path
			published.SHA256 = builds[incompatible].digest
			published.Version = "historical-target"
			writeJSON("install.json", published)
			writeJSON("intent.json", map[string]string{"mode": "stop", "sha256": published.SHA256, "version": published.Version, "session": ""})
			m.Phase = "ready"
			if e = writeHandoff(m); e != nil {
				t.Fatal(e)
			}
			markerBefore, e = privateRead(filepath.Join(data, handoffFile))
			if e != nil {
				t.Fatal(e)
			}
			refused("uninstall-direct", published.SHA256, true)
			// Restore only this test's modeled receipt before exact teardown.
			writeJSON("install.json", original)
			writeJSON("intent.json", map[string]string{"mode": "stop", "sha256": original.SHA256, "version": original.Version, "session": ""})
			// This is teardown of this test's exact known historical helper and
			// handle. It is not a product maintenance or enumeration fallback.
			if incompatible == 3 {
				if _, e := v.imageOperation(ctx, builds[3].path, builds[3].digest, 6, h, nil); e != nil {
					t.Fatal("exact isolated target teardown", e)
				}
			}
			again, e := readHandoff(data)
			if e != nil || again != m {
				t.Fatal("isolated teardown marker identity changed", e)
			}
			if e := os.Remove(filepath.Join(data, handoffFile)); e != nil {
				t.Fatal(e)
			}
			if e := syncHandoffDir(data); e != nil {
				t.Fatal(e)
			}
			action(2, "uninstall-secret")
			action(0, "absent")
			if incompatible == 3 {
				action(3, "absent")
			}
			if recovery == "replacement" {
				action(1, "absent")
			}
			if _, e := readHandoff(data); !os.IsNotExist(e) {
				t.Fatal("incompatible marker retained", e)
			}
		}
	}
}

var _ io.Writer = (*custodyOutput)(nil)

func TestHandoffRecoveryAdmissionRefusalsPreserveMarker(t *testing.T) {
	data, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(data, 0700); e != nil {
		t.Fatal(e)
	}
	digest := fmt.Sprintf("%064x", 1)
	source := install.Record{Dir: filepath.Join(data, "install"), DataDir: data, SHA256: digest}
	source.Executable = handoffTarget(source, digest)
	m := custodyHandoff{1, source, fmt.Sprintf("%064x", 2), "0123456789abcdef0123456789abcdef", "", "prepared", false}
	if e = New().RecoverUpgrade(context.Background(), source); e != nil {
		t.Fatal("no marker", e)
	}
	if e = writeHandoff(m); e != nil {
		t.Fatal(e)
	}
	if e = New().RecoverUpgrade(context.Background(), source); e != nil {
		t.Fatal("source receipt must retain custody", e)
	}
	wrong := source
	wrong.SHA256 = m.Target
	wrong.Executable = handoffTarget(source, m.Target)
	if e = New().RecoverUpgrade(context.Background(), wrong); !errors.Is(e, install.ErrUnverified) {
		t.Fatal("unverified receipt/process admitted", e)
	}
	got, e := readHandoff(data)
	if e != nil || got != m {
		t.Fatal("refusal changed pending marker", got, e)
	}
	if e = New().PrepareUpgrade(context.Background(), source, m.Target); !errors.Is(e, install.ErrUnverified) {
		t.Fatal("non-owning source accepted", e)
	}
	if e = New().PrepareUpgrade(context.Background(), source, "bad"); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if e = New().ResumeUpgrade(context.Background(), source, "bad"); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if e = CheckUpgradeTarget(nil, source, m.Target); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if e = CheckUpgradeTarget(context.Background(), source, "bad"); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if e = CheckUpgradeTarget(context.Background(), source, m.Target); !errors.Is(e, install.ErrUnverified) {
		t.Fatal(e)
	}
	if e = New().ResumeUpgrade(nil, source, m.Target); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if e = New().DeleteForInstall(context.Background(), source, "bad"); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
}

// These helper exchanges execute real images but do not open any Keychain.
func TestHandoffCapabilitiesNativeStaticAndOlderProtocol(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	for _, variant := range []string{"native", "static", "older-helper"} {
		path := filepath.Join(root, variant)
		var cmd *exec.Cmd
		if variant == "static" {
			cmd = exec.Command("go", "build", "-p", "2", "-o", path, "../cmd/hilo")
		} else {
			cmd = exec.Command("go", "test", "-p", "1", "-c", "-o", path, "-ldflags=-X github.com/Telara-Labs/hilo/contract/internal/node/vault.custodyBuild="+variant, ".")
		}
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if variant == "static" {
			cmd.Env = append(cmd.Env, "CGO_ENABLED=0")
		}
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("%s build %v %s", variant, e, b)
		}
		if e = os.Chmod(path, 0700); e != nil {
			t.Fatal(e)
		}
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(b)
		digest := hex.EncodeToString(sum[:])
		before, e := os.ReadDir(root)
		if e != nil {
			t.Fatal(e)
		}
		e = checkTargetCapabilities(context.Background(), path, digest)
		if (e == nil) != (variant == "native") {
			t.Fatalf("%s compatibility %v", variant, e)
		}
		after, e := os.ReadDir(root)
		if e != nil || len(before) != len(after) {
			t.Fatal("handshake mutated directory", e)
		}
		if e = checkTargetCapabilities(context.Background(), path, fmt.Sprintf("%064x", 1)); e == nil {
			t.Fatal("unauthenticated image accepted")
		}
	}
}
