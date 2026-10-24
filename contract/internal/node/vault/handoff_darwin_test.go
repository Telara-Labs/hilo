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

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/peer"
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
		var out bytes.Buffer
		if !runHandoffHelper([]string{resumeArg}, bytes.NewBufferString(input), &out) || !bytes.Equal(out.Bytes(), []byte{1}) {
			t.Fatal("malformed recovery request accepted")
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
	switch action {
	case "bootstrap":
		e = disclosure.BootstrapInstalled(ctx, data, "Upgrade fixture", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{}, v)
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
	if action == "bootstrap" || action == "load" || action == "recover" {
		loaded, le := (disclosure.InstalledProvider{Dir: data, Vault: v, Peers: peer.Authority{}}).Load(ctx)
		if le != nil {
			fmt.Fprintln(os.Stderr, le)
			os.Exit(1)
		}
		loaded.Material.Clear()
		fmt.Fprintln(os.Stdout, loaded.Config.OwnerGenesis)
	}
	return true
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
	builds := make([]image, 0, 2)
	for _, variant := range []string{"first", "second"} {
		exe := filepath.Join(root, variant)
		cmd := exec.Command("go", "test", "-p", "1", "-c", "-o", exe, "-ldflags=-X github.com/Telara-Labs/telara-memory/contract/internal/node/vault.custodyBuild="+variant, ".")
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
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
	action := func(i int, name string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, builds[i].path, "custody-upgrade-fixture", name, keychain, data, dir, builds[1].digest)
		cmd.Env = replaceHome(os.Environ(), home)
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("%s build %d %v %s", name, i, e, b)
		}
		return string(bytes.TrimSpace(b))
	}
	owner := action(0, "bootstrap")
	action(1, "poison")
	failed := exec.CommandContext(ctx, builds[0].path, "custody-upgrade-fixture", "prepare", keychain, data, dir, builds[1].digest)
	failed.Env = replaceHome(os.Environ(), home)
	if b, e := failed.CombinedOutput(); e == nil {
		t.Fatalf("mismatched existing target accepted %s", b)
	}
	if got := action(0, "load"); got != owner {
		t.Fatal("failed transfer lost source custody")
	}
	action(1, "clear")

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
	action(0, "uninstall-secret")
	action(0, "absent")
	action(1, "absent")
	if _, e = readHandoff(data); !os.IsNotExist(e) {
		t.Fatal("aborted transfer marker retained", e)
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
	if e = New().DeleteForInstall(context.Background(), source, "bad"); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
}
