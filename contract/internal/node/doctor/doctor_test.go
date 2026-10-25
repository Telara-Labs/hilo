//go:build darwin || linux

package doctor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/syncnode"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/vault"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	_ "modernc.org/sqlite"
)

// Disposable custody and peer doubles stand in for the OS vault and the
// verified peer image only. Store, daemon, disclosure and capture are real.
type memVault struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (v *memVault) Put(_ context.Context, k string, b []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.values == nil {
		v.values = map[string][]byte{}
	}
	if v.values[k] != nil {
		return errors.New("exists")
	}
	v.values[k] = append([]byte(nil), b...)
	return nil
}
func (v *memVault) Get(_ context.Context, k string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.values[k] == nil {
		return nil, errors.New("missing")
	}
	return append([]byte(nil), v.values[k]...), nil
}
func (v *memVault) Delete(_ context.Context, k string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	clear(v.values[k])
	delete(v.values, k)
	return nil
}

type samePID struct{}

func (samePID) VerifyAndDrain(ctx context.Context, h ipc.Hello, _ string) error {
	if h.PID != os.Getpid() || daemon.AuthenticatedPeerPID(ctx) != h.PID {
		return errors.New("peer denied")
	}
	return nil
}

type node struct {
	t     *testing.T
	base  string
	home  string
	paths ipc.Paths
	vault *memVault
}

func newNode(t *testing.T) *node {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	p, err := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if err != nil {
		t.Fatal(err)
	}
	n := &node{t: t, base: base, home: filepath.Join(base, "home"), paths: p, vault: &memVault{}}
	if err = os.MkdirAll(n.home, 0700); err != nil {
		t.Fatal(err)
	}
	if err = disclosure.BootstrapInstalled(context.Background(), p.Data, "Doctor test", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{Repos: disclosure.AllLocalRepos(), AllowUnscoped: true, Actions: []disclosure.TaskMutation{disclosure.Create}}, n.vault); err != nil {
		t.Fatal(err)
	}
	return n
}

func (n *node) start() {
	n.t.Helper()
	provider := mcp.InstalledRuntimeProvider{Provider: disclosure.InstalledProvider{Dir: n.paths.Data, Vault: n.vault, Peers: samePID{}}, CaptureHome: n.home}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Config{Paths: n.paths, Ready: func() { close(ready) }, Open: func(ctx context.Context) (daemon.Backend, error) {
			return mcp.Open(ctx, n.paths.Data, provider)
		}})
	}()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		n.t.Fatal(err)
	case <-time.After(10 * time.Second):
		cancel()
		n.t.Fatal("daemon not ready")
	}
	n.t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			n.t.Error("daemon did not stop")
		}
	})
}

func (n *node) doctor() Report {
	n.t.Helper()
	r, err := Run(context.Background(), Config{DataDir: n.paths.Data, RunDir: n.paths.Run, Home: n.home, Executable: "/usr/local/bin/telara-memory", ProbeTimeout: 500 * time.Millisecond})
	if err != nil {
		n.t.Fatal(err)
	}
	return r
}

func has(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestDoctorDaemonReachabilityAndKeyStore(t *testing.T) {
	n := newNode(t)
	r := n.doctor()
	if r.Daemon.Reachable || !has(r.Problems, "daemon_unreachable") || r.KeyStore.RuntimeAuthority != "unknown" {
		t.Fatalf("stopped daemon %+v %v", r.Daemon, r.Problems)
	}
	if r.KeyStore.Backend != vault.Backend() || r.KeyStore.Location != vault.Location() || r.KeyStore.InstalledProfile != "present" {
		t.Fatalf("key store %+v", r.KeyStore)
	}
	n.start()
	r = n.doctor()
	if !r.Daemon.Reachable || r.Daemon.PID != os.Getpid() || !r.Daemon.StoreWired || r.KeyStore.RuntimeAuthority != "loaded" || has(r.Problems, "daemon_unreachable") {
		t.Fatalf("running daemon %+v %+v %v", r.Daemon, r.KeyStore, r.Problems)
	}
	if r.Store.State != "ok" || r.Store.Records < 1 {
		t.Fatalf("store %+v", r.Store)
	}
}

func TestDoctorSigningBacklog(t *testing.T) {
	n := newNode(t)
	if r := n.doctor(); r.Signing.Backlog != 0 || has(r.Problems, "signing_backlog") {
		t.Fatalf("clean %+v", r.Signing)
	}
	// Plant one unsigned-local record directly in the real database file.
	db, err := sql.Open("sqlite", filepath.Join(n.paths.Data, "memory.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE record SET sig_status='unsigned-local' WHERE rowid=(SELECT max(rowid) FROM record)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	r := n.doctor()
	if r.Signing.Backlog != 1 || r.Signing.SignatureStates["unsigned-local"] != 1 || !has(r.Problems, "signing_backlog") {
		t.Fatalf("backlog %+v %v", r.Signing, r.Problems)
	}
}

func TestDoctorHookTrustCaptureGapsAndSpool(t *testing.T) {
	n := newNode(t)
	spool := filepath.Join(n.paths.Data, "spool", "claude", "new")
	if err := os.MkdirAll(spool, 0700); err != nil {
		t.Fatal(err)
	}
	secret := "spoolcontentmustnotappear"
	if err := os.WriteFile(filepath.Join(spool, "01J00000000000000000000000.json"), []byte(`{"hint":"`+secret+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	r := n.doctor()
	if len(r.Hooks) != 4 {
		t.Fatal(r.Hooks)
	}
	byClient := map[string]Hook{}
	for _, h := range r.Hooks {
		byClient[h.Client] = h
		if h.Error != "" || h.MCP == "" || h.Hooks == "" || len(h.CaptureGaps) == 0 {
			t.Fatalf("hook row %+v", h)
		}
	}
	if byClient["codex"].Trust != "review_required" || byClient["claude"].Trust != "not_required" || !has(r.Problems, "hook_trust_review_codex") {
		t.Fatalf("trust %+v %v", byClient, r.Problems)
	}
	if r.Capture.PendingSpool != 1 || r.Capture.Spool["claude"].New != 1 || !r.Capture.Incomplete {
		t.Fatalf("spool %+v", r.Capture)
	}
	for _, want := range []string{"daemon_stopped", "spool_pending_without_daemon", "capture_gap:cursor:assistant_decoder_missing"} {
		if !has(r.Capture.Reasons, want) {
			t.Fatalf("missing reason %s in %v", want, r.Capture.Reasons)
		}
	}
	b, _ := json.Marshal(r)
	var text bytes.Buffer
	if err := WriteText(&text, r); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(secret)) || strings.Contains(text.String(), secret) {
		t.Fatal("doctor printed spool content")
	}
}

// standalone opens a real store with its own device key, outside any daemon.
func standalone(t *testing.T) (*store.Store, string, ed25519.PrivateKey) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "data")
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	pub := key.Public().(ed25519.PublicKey)
	genesis, machine := sig.KeyID(pub), "22222222-2222-4222-8222-222222222222"
	st, err := store.Open(context.Background(), store.Options{Dir: dir, PinnedGenesisID: genesis, LocalMachineID: machine})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(pub, record.RoleDevice, machine), Genesis: genesis}, pub, machine, 1761150000000, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.Append(context.Background(), store.SignedRecord{HeaderJCS: op.Rec.HeaderJCS, BodyJCS: op.Rec.BodyJCS, Sigs: op.Sigs, AdvisoryID: op.Rec.ID}); err != nil {
		t.Fatal(err)
	}
	return st, dir, key
}

type keySigner struct{ key ed25519.PrivateKey }

func (s keySigner) KeyID() string { return sig.KeyID(s.key.Public().(ed25519.PublicKey)) }
func (s keySigner) SignRecordID(id string) (record.Signature, error) {
	return sig.SignRecord(s.key, id)
}

func TestDoctorScrubState(t *testing.T) {
	st, dir, key := standalone(t)
	ctx := context.Background()
	receipt, err := st.EraseExact(ctx, store.EraseRequest{IDs: []string{strings.Repeat("ab", 32)}}, keySigner{key})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Run(ctx, Config{DataDir: dir, ProbeTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if r.Scrub.Pending != 1 || len(r.Scrub.Jobs) != 1 || r.Scrub.Jobs[0].Control != receipt.Control || !has(r.Problems, "scrub_pending") {
		t.Fatalf("pending %+v %v", r.Scrub, r.Problems)
	}
	if done, err := st.Scrub(ctx, receipt.Control); err != nil || done.State != "complete" {
		t.Fatal(done, err)
	}
	r, _ = Run(ctx, Config{DataDir: dir, ProbeTimeout: 200 * time.Millisecond})
	if r.Scrub.Pending != 0 || r.Scrub.Complete != 1 || has(r.Problems, "scrub_pending") {
		t.Fatalf("complete %+v %v", r.Scrub, r.Problems)
	}
}

func TestDoctorPolicyStaleKillAndSyncBlockers(t *testing.T) {
	st, dir, _ := standalone(t)
	ctx := context.Background()
	policyKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{63}, 32))
	pub := policyKey.Public().(ed25519.PublicKey)
	root, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(pub, record.RolePolicy, ""), Genesis: "tenant-doctor"}, pub, "", time.Now().UnixMilli(), policyKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.InstallTenantPolicyContext(ctx, store.TenantPolicyContext{Tenant: "tenant-doctor", UserID: "doctor-user", Origin: "https://tenant.example", Root: store.SignedRecord{HeaderJCS: root.Rec.HeaderJCS, BodyJCS: root.Rec.BodyJCS, Sigs: root.Sigs, AdvisoryID: root.Rec.ID}}); err != nil {
		t.Fatal(err)
	}
	b := &record.PolicyBody{Tenant: "tenant-doctor", Seq: 1, IssuedAt: time.Now().UnixMilli() - 1000, NotAfter: time.Now().UnixMilli() + 3600000, RefreshAfter: time.Now().UnixMilli() - 1, Kill: record.PolicyKill{Sync: true}}
	b.Applies.Users = []string{"doctor-user"}
	pr, err := record.Build(record.Header{Type: record.KindPolicy, LID: record.PolicyLID(b.Tenant), At: time.Now().UnixMilli(), Author: record.Author{KeyID: sig.KeyID(pub)}, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, b)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := sig.SignRecord(policyKey, pr.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.Append(ctx, store.SignedRecord{HeaderJCS: pr.HeaderJCS, BodyJCS: pr.BodyJCS, Sigs: []record.Signature{sg}, AdvisoryID: pr.ID}); err != nil {
		t.Fatal(err)
	}
	r, err := Run(ctx, Config{DataDir: dir, ProbeTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	p := r.Policy
	if !p.Installed || p.Seq != 1 || p.Freshness != "refresh-due" || !p.Stale || p.FailClosed || !p.KillSync || p.DataPush {
		t.Fatalf("policy %+v", p)
	}
	if !has(r.Problems, "policy_refresh-due") || !has(r.Problems, "policy_kill_switch") {
		t.Fatal(r.Problems)
	}
	// No sync profile: sync is off and reports no blockers.
	if r.Sync.Configured || len(r.Sync.Blockers) != 0 {
		t.Fatalf("unconfigured sync %+v", r.Sync)
	}
	// A real unenrolled profile reports its blockers plus the policy kill.
	if err = writeInstalledIdentity(dir, st); err != nil {
		t.Fatal(err)
	}
	if _, err = syncnode.CreateKey(ctx, dir, &memVault{}); err != nil {
		t.Fatal(err)
	}
	r, _ = Run(ctx, Config{DataDir: dir, ProbeTimeout: 200 * time.Millisecond})
	for _, want := range []string{"not_enrolled", "disabled", "policy_kill_sync"} {
		if !has(r.Sync.Blockers, want) || !has(r.Problems, "sync_blocked:"+want) {
			t.Fatalf("missing %s in %+v %v", want, r.Sync, r.Problems)
		}
	}
}

// writeInstalledIdentity records the standalone store's identity the way
// installation does, so the sync key can bind to it.
func writeInstalledIdentity(dir string, _ *store.Store) error {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "memory.sqlite")+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var genesis, machine string
	if err = db.QueryRow("SELECT genesis,machine FROM meta").Scan(&genesis, &machine); err != nil {
		return err
	}
	b, _ := json.Marshal(map[string]string{"owner": genesis, "machine": machine})
	return store.WriteInstalledRecord(dir, b)
}

func TestDoctorInstallReceipt(t *testing.T) {
	n := newNode(t)
	dir := filepath.Join(n.base, "install")
	image := []byte("synthetic executable image\n")
	sum := sha256.Sum256(image)
	digest := hex.EncodeToString(sum[:])
	exe := filepath.Join(dir, "bin", digest, "telara-memory")
	if err := os.MkdirAll(filepath.Dir(exe), 0700); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{dir, filepath.Join(dir, "bin"), filepath.Dir(exe)} {
		if err := os.Chmod(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(exe, image, 0700); err != nil {
		t.Fatal(err)
	}
	rec := install.Record{Schema: 1, Dir: dir, Home: n.home, Label: "dev.memory.doctor", Platform: runtime.GOOS, UserID: strconv.Itoa(os.Geteuid()), Executable: exe, SHA256: digest, Version: "9.9.9", DataDir: n.paths.Data, RunDir: n.paths.Run}
	write := func(name string, v any) {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("install.json", rec)
	write("intent.json", map[string]string{"mode": "start", "sha256": digest, "version": "9.9.9", "session": ""})
	r, err := Run(context.Background(), Config{InstallDir: dir, Home: n.home, ProbeTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if r.Install == nil || r.Install.State != "verified" || !r.Install.Verified || r.Install.Version != "9.9.9" || r.DataDir != n.paths.Data {
		t.Fatalf("receipt %+v %s", r.Install, r.DataDir)
	}
	if err = os.WriteFile(exe, []byte("substituted\n"), 0700); err != nil {
		t.Fatal(err)
	}
	r, _ = Run(context.Background(), Config{InstallDir: dir, Home: n.home, ProbeTimeout: 200 * time.Millisecond})
	if r.Install.State != "unverified" || r.Install.Verified || !has(r.Problems, "install_unverified") {
		t.Fatalf("substituted %+v %v", r.Install, r.Problems)
	}
}

func TestDoctorTextHasEverySection(t *testing.T) {
	n := newNode(t)
	var b bytes.Buffer
	if err := WriteText(&b, n.doctor()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Install receipt", "Daemon", "Key store", "Signing", "Hooks", "Capture", "Store", "Policy", "Scrub", "Sync"} {
		if !strings.Contains(b.String(), "\n"+want+"\n") {
			t.Fatalf("missing section %s\n%s", want, b.String())
		}
	}
}
