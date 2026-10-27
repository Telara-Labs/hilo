//go:build darwin || linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/shim"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/syncnode"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// loginTenant is one hosted tenant: its policy key, pinned login root and the
// hosted session keys a login returns. Its origin is a private TLS server that
// answers only the session mint and the authenticated login response; the
// daemon's sync worker validates against the system pool and never reaches it,
// so the test proves local state only.
type loginTenant struct {
	t                    *testing.T
	tenant, user, origin string
	key                  ed25519.PrivateKey
	root                 *sig.KeyOp
	auth                 *ecdsa.PrivateKey
	service              ed25519.PublicKey
	// serviceOp is the signed tenant_key of service the authenticated login
	// response returns; serviceReply, when set, replaces it.
	serviceOp    record.Envelope
	serviceReply []record.Envelope
}

func newLoginTenant(t *testing.T, seed byte, tenant, user string) *loginTenant {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	pub := key.Public().(ed25519.PublicKey)
	root, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(pub, record.RolePolicy, ""), Genesis: tenant}, pub, "", time.Now().UnixMilli(), key)
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	service, servicePriv, _ := ed25519.GenerateKey(rand.Reader)
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(service, record.RoleService, ""), Genesis: tenant}, service, "", time.Now().UnixMilli(), servicePriv)
	if err != nil {
		t.Fatal(err)
	}
	l := &loginTenant{t: t, tenant: tenant, user: user, key: key, root: root, auth: auth, service: service, serviceOp: nodesync.Envelope(op.Rec.HeaderJCS, op.Rec.BodyJCS, op.Sigs, op.Rec.ID)}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(l.serve))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	l.origin = srv.URL
	old := loginTLSRoots
	loginTLSRoots = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	t.Cleanup(func() { loginTLSRoots = old })
	return l
}

// serve mints a memory session bound to the presented DPoP key and answers the
// authenticated login response with this tenant's policy root.
func (l *loginTenant) serve(w http.ResponseWriter, r *http.Request) {
	fail := func() { w.WriteHeader(http.StatusUnauthorized) }
	switch {
	case r.Method == "POST" && r.URL.Path == "/v1/mcp/session":
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer telara_mcp_") {
			fail()
			return
		}
		jkt, ok := proofThumbprint(r.Header.Get("DPoP"))
		var body struct {
			Grant struct {
				Ops     []string `json:"ops"`
				Repos   []string `json:"repos"`
				Origin  string   `json:"origin"`
				Genesis string   `json:"genesis_id"`
				Device  string   `json:"device_id"`
				Expiry  string   `json:"expires_at_unix"`
			} `json:"memory_grant"`
		}
		if !ok || json.NewDecoder(r.Body).Decode(&body) != nil {
			fail()
			return
		}
		expiry, err := strconv.ParseInt(body.Grant.Expiry, 10, 64)
		if err != nil {
			fail()
			return
		}
		now := time.Now().UTC().Truncate(time.Second)
		claims := map[string]any{"exp": now.Add(10 * time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix(), "iss": "https://auth.example", "sub": l.user, "aud": []string{"telara-mcp-session"}, "tenant_id": l.tenant, "mcp_config_id": "config-" + l.tenant, "cnf": map[string]string{"jkt": jkt},
			"memory_grant": nodesync.MemoryGrant{Ops: body.Grant.Ops, Repos: body.Grant.Repos, Origin: body.Grant.Origin, GenesisID: body.Grant.Genesis, DeviceID: body.Grant.Device, ExpiresAtUnix: expiry}}
		token, err := signLoginJWT(l.auth, claims)
		if err != nil {
			fail()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"session_token": token, "expires_at": claims["exp"]})
	case r.Method == "GET" && r.URL.Path == "/sync/v1/login":
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "DPoP ")
		parts := strings.Split(token, ".")
		if !ok || len(parts) != 3 {
			fail()
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		var c struct {
			Grant nodesync.MemoryGrant `json:"memory_grant"`
		}
		if err != nil || json.Unmarshal(raw, &c) != nil {
			fail()
			return
		}
		keys := l.serviceReply
		if keys == nil {
			keys = []record.Envelope{l.serviceOp}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nodesync.LoginReply{Origin: l.origin, Tenant: l.tenant, User: l.user, Config: "config-" + l.tenant, DeviceID: c.Grant.DeviceID, PolicyRoot: nodesync.Envelope(l.root.Rec.HeaderJCS, l.root.Rec.BodyJCS, l.root.Sigs, l.root.Rec.ID), ServiceKeys: keys})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// proofThumbprint returns the jkt of the public key a DPoP proof carries.
func proofThumbprint(proof string) (string, bool) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	var head struct {
		JWK map[string]string `json:"jwk"`
	}
	if err != nil || json.Unmarshal(raw, &head) != nil {
		return "", false
	}
	x, e1 := base64.RawURLEncoding.DecodeString(head.JWK["x"])
	y, e2 := base64.RawURLEncoding.DecodeString(head.JWK["y"])
	if e1 != nil || e2 != nil {
		return "", false
	}
	jkt, err := nodesync.Thumbprint(&ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)})
	return jkt, err == nil
}

func signLoginJWT(key *ecdsa.PrivateKey, claims any) (string, error) {
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	msg := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	d := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		return "", err
	}
	return msg + "." + base64.RawURLEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)), nil
}

// policy signs a fresh policy carrying a private rule string that logout
// must purge from every database file.
func (l *loginTenant) policy(seq int64, secret string) (*record.Record, record.Envelope) {
	l.t.Helper()
	now := time.Now().UnixMilli()
	pb := &record.PolicyBody{Tenant: l.tenant, Seq: seq, IssuedAt: now - 1000, RefreshAfter: now + 1800000, NotAfter: now + 3600000}
	pb.Applies.Users = []string{l.user}
	pb.Push = record.PolicyPush{MaxProfile: record.ProfilePushMetadata, AllowRepos: []string{"*"}}
	pb.BlockedRepos = []record.BlockedRepo{{RemoteGlob: "blocked.example/" + secret, Effect: "no-push"}}
	pub := l.key.Public().(ed25519.PublicKey)
	r, err := record.Build(record.Header{Type: record.KindPolicy, LID: record.PolicyLID(l.tenant), At: now, Author: record.Author{KeyID: sig.KeyID(pub)}, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, pb)
	if err != nil {
		l.t.Fatal(err)
	}
	s, err := sig.SignRecord(l.key, r.ID)
	if err != nil {
		l.t.Fatal(err)
	}
	return r, nodesync.Envelope(r.HeaderJCS, r.BodyJCS, []record.Signature{s}, r.ID)
}

// document is the login document one authenticated login returns for d.
func (l *loginTenant) document(d *bundleDevice, policy record.Envelope, refresh string) string {
	l.t.Helper()
	ident := d.identity()
	jwk, err := nodesync.PublicJWKOf(&l.auth.PublicKey)
	if err != nil {
		l.t.Fatal(err)
	}
	doc := syncnode.LoginDocument{
		Enrollment: syncnode.Enrollment{Origin: l.origin, Tenant: l.tenant, User: l.user, Config: "config-" + l.tenant, AuthIssuer: "https://auth.example", AuthKey: jwk,
			ServiceKeys:  []syncnode.ServiceKey{{KeyID: sig.KeyID(l.service), Public: base64.RawURLEncoding.EncodeToString(l.service)}},
			Grant:        nodesync.MemoryGrant{Ops: []string{"push", "pull"}, Repos: []string{"r1:" + strings.Repeat("a", 64)}, Origin: "local", GenesisID: ident.Genesis, DeviceID: ident.Machine, ExpiresAtUnix: time.Now().Add(time.Hour).Unix()},
			RefreshToken: refresh},
		PolicyRoot: nodesync.Envelope(l.root.Rec.HeaderJCS, l.root.Rec.BodyJCS, l.root.Sigs, l.root.Rec.ID),
		Policy:     policy,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		l.t.Fatal(err)
	}
	return string(raw)
}

// callToolIn sends one tools/call through a real shim session in the named
// conversation, so separate phases are separate operations, never retries of
// an operation recorded under an earlier policy.
func callToolIn(n *installedNode, conversation, tool string, args map[string]any) mcp.Result {
	n.t.Helper()
	input, write := io.Pipe()
	read, output := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- shim.Run(ctx, input, output, shim.Config{Paths: n.paths, Hello: ipc.Hello{Shim: "login-test-shim"}})
		output.Close()
	}()
	defer func() {
		cancel()
		write.Close()
		read.Close()
		input.Close()
		<-done
	}()
	req := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args, "_meta": map[string]any{"com.telara/conversation": conversation}}}
	if err := json.NewEncoder(write).Encode(req); err != nil {
		n.t.Fatal(err)
	}
	line, err := bufio.NewReader(read).ReadBytes('\n')
	if err != nil {
		n.t.Fatal(err)
	}
	var response struct {
		Error  *daemon.RPCError `json:"error"`
		Result mcp.Result       `json:"result"`
	}
	if err = json.Unmarshal(line, &response); err != nil || response.Error != nil {
		n.t.Fatalf("%s %v", line, err)
	}
	return response.Result
}

// createTaskIn creates one task with goal in its own conversation. The task
// is always recorded; the reply may be withheld when earlier exposures on this
// machine hold later output (07 section 10.3), so callers check the record.
func createTaskIn(n *installedNode, conversation, goal string) {
	n.t.Helper()
	r := callToolIn(n, conversation, "telara_task_create", map[string]any{"goal": goal})
	if r.IsError || len(r.Content) == 0 {
		n.t.Fatalf("task create in %s: %+v", conversation, r)
	}
}

// taskWith returns the id and policy of the one task record whose stored body
// holds needle.
func taskWith(t *testing.T, dir, needle string) (string, string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "memory.sqlite")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var id, pol string
	if err = db.QueryRow("SELECT r.id,coalesce(json_extract(CAST(r.header AS TEXT),'$.pol'),'') FROM record r JOIN record_body b ON b.id=r.id WHERE json_extract(CAST(r.header AS TEXT),'$.type')='task' AND instr(b.body,?)>0", needle).Scan(&id, &pol); err != nil {
		t.Fatal("no task record holds", needle, err)
	}
	return id, pol
}

// governedRecords returns the data record ids sealed under policy id pol.
func governedRecords(t *testing.T, dir, pol string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "memory.sqlite")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT id FROM record WHERE json_extract(CAST(header AS TEXT),'$.pol')=? ORDER BY seq", pol)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			t.Fatal("scan")
		}
		out = append(out, id)
	}
	return out
}

func countIn(t *testing.T, path, q string, args ...any) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err = db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(q, err)
	}
	return n
}

func exclusionOf(sel store.BundleSelection, id string) string {
	for _, e := range sel.Excluded {
		if e.ID == id {
			return e.Reason
		}
	}
	return ""
}

// TestInstalledLogoutThenLoginToDifferentTenant drives the real login,
// logout, erase and sync commands against an installed profile with its
// daemon running. It logs in to tenant A, captures governed tasks through
// MCP, erases a record, logs out and logs in to tenant B. Pins, rollback
// facts, tombs and per-record logout fences survive; credentials and policy
// secrets do not; nothing of A is readable, bundleable or queued under B.
func TestInstalledLogoutThenLoginToDifferentTenant(t *testing.T) {
	useBundleVaults(t)
	old := syncVault
	syncVault = func(dir string) syncnode.SecretVault {
		bundleVaults.Lock()
		defer bundleVaults.Unlock()
		return bundleVaults.m[dir]
	}
	t.Cleanup(func() { syncVault = old })
	d := newGenesisDevice(t)
	n := d.start()
	// cli runs one real command line in process with this profile's data dir.
	cli := func(stdin string, args ...string) (string, error) {
		var out bytes.Buffer
		err := run(context.Background(), append(args, "--data-dir", d.paths.Data), strings.NewReader(stdin), &out)
		return out.String(), err
	}
	mustCLI := func(stdin string, args ...string) string {
		t.Helper()
		out, err := cli(stdin, args...)
		if err != nil {
			t.Fatalf("%v: %s\n%s", args, publicCode(err), out)
		}
		return out
	}
	memory := filepath.Join(d.paths.Data, "memory.sqlite")
	syncDB := filepath.Join(d.paths.Data, store.SyncDatabaseName)

	plantTask(t, n, "preloginotterlanterncanary")
	var preCheckpoint string
	for _, r := range dataRecords(t, d.paths.Data) {
		if r.kind == "checkpoint" {
			preCheckpoint = r.id
		}
	}
	if preCheckpoint == "" || len(governedRecords(t, d.paths.Data, "")) != 0 {
		t.Fatal("pre-login capture")
	}

	// Login to tenant A.
	tenantA := newLoginTenant(t, 71, "tenant-alpha", "alpha-user")
	tenantB := newLoginTenant(t, 72, "tenant-bravo", "bravo-user")
	if _, err := cli("", "login", "x"); publicCode(err) != "invalid_arguments" {
		t.Fatal("login accepted a positional argument", err)
	}
	if _, err := cli("", "logout", "--yes"); publicCode(err) != "invalid_arguments" {
		t.Fatal("logout accepted an unknown flag", err)
	}
	p1, p1Env := tenantA.policy(1, "alphasecretrulecanary")
	if _, err := cli(tenantA.document(d, p1Env, "telara_mcp_alpha"), "login"); publicCode(err) != "sync_not_enrolled" {
		t.Fatal("login without a device key", publicCode(err))
	}
	jktA := mustCLI("", "login", "--key")
	if _, err := cli(`{"origin":"https://x.example","unexpected":true}`, "login"); publicCode(err) != "login_invalid" {
		t.Fatal("malformed login document", publicCode(err))
	}
	out := mustCLI(tenantA.document(d, p1Env, "telara_mcp_alpha"), "login")
	var loggedIn syncnode.LoginReport
	if err := json.Unmarshal([]byte(out), &loggedIn); err != nil || loggedIn.State != "logged_in" || loggedIn.Tenant != tenantA.tenant || loggedIn.Policy != p1.ID {
		t.Fatal("login A", out, err)
	}
	if strings.Contains(out, "telara_mcp_alpha") {
		t.Fatal("login printed the refresh credential")
	}
	profileA, err := syncnode.LoadProfile(d.paths.Data)
	if err != nil || profileA.Tenant != tenantA.tenant || !profileA.Enabled {
		t.Fatal("profile A", err)
	}

	// A second tenant is refused until logout, by login and by sync enroll.
	_, p1B := tenantB.policy(1, "bravosecretrulecanary")
	if _, err = cli(tenantB.document(d, p1B, "telara_mcp_bravo"), "login"); publicCode(err) != "tenant_conflict" {
		t.Fatal("second tenant login", publicCode(err))
	}
	var enrollOnly map[string]any
	_ = json.Unmarshal([]byte(tenantB.document(d, p1B, "telara_mcp_bravo")), &enrollOnly)
	delete(enrollOnly, "policy_root")
	delete(enrollOnly, "policy")
	raw, _ := json.Marshal(enrollOnly)
	if _, err = cli(string(raw), "sync", "enroll"); publicCode(err) != "tenant_conflict" {
		t.Fatal("sync enroll switched tenants", publicCode(err))
	}

	// Governed capture under A.
	plantTask(t, n, "alphagovernedheroncanary")
	governedA := governedRecords(t, d.paths.Data, p1.ID)
	if len(governedA) < 2 {
		t.Fatalf("expected tasks sealed under A's policy, have %d", len(governedA))
	}

	// Logout of A.
	out = mustCLI("", "logout")
	var loggedOut syncnode.LogoutReport
	if err = json.Unmarshal([]byte(out), &loggedOut); err != nil || loggedOut.State != "logged_out" || loggedOut.HostedHistory != "not_deleted" || loggedOut.Physical != "complete" {
		t.Fatal("logout A", out, err)
	}
	if status := mustCLI("", "sync", "status"); !strings.Contains(status, `"configured":false`) {
		t.Fatal("sync still configured after logout", status)
	}
	d.vault.mu.Lock()
	for _, h := range []string{profileA.Credential, profileA.Refresh} {
		if d.vault.values[h] != nil {
			d.vault.mu.Unlock()
			t.Fatal("logout left a credential slot")
		}
	}
	d.vault.mu.Unlock()
	if again := mustCLI("", "logout"); !strings.Contains(again, `"logged_out"`) {
		t.Fatal("repeated logout", again)
	}
	for q, want := range map[string]int{
		"SELECT count(*) FROM operation WHERE state='pending'":                     0,
		"SELECT count(*) FROM outbox WHERE header IS NOT NULL OR body IS NOT NULL": 0,
		"SELECT count(*) FROM ctl_pending":                                         0,
		"SELECT count(*) FROM data_quarantine":                                     0,
		"SELECT count(*) FROM sync_state":                                          0,
	} {
		if got := countIn(t, syncDB, q); got != want {
			t.Fatalf("after logout %q = %d", q, got)
		}
	}

	// fenced checks that records sealed under logged-out policies stay local:
	// unreadable, not bundleable and their policy rule text physically gone.
	fenced := func(stage, secret string, ids []string) {
		t.Helper()
		if hits := n.filesContaining(secret); len(hits) != 0 {
			t.Fatal(stage, "logged-out policy rule text remains in", hits)
		}
		sel := selectionOf(t, d, ids)
		if len(sel.Data) != 0 {
			t.Fatal(stage, "logged-out governed records bundleable")
		}
		for _, id := range ids {
			// Governed bodies are withheld before the policy predicate runs for
			// some kinds, so either fixed refusal proves the record stays local.
			if r := exclusionOf(sel, id); r != store.ExcludedPolicy && r != store.ExcludedUnavailable {
				t.Fatal(stage, "logged-out governed record not excluded", r)
			}
			if e := snapshotOf(t, d, id); e.BodyJCS != nil {
				t.Fatal(stage, "logged-out governed body readable")
			}
		}
	}
	// retainedA checks A's pin, rollback watermark and per-record fence.
	retainedA := func(stage string, active, seq int, highest string) {
		t.Helper()
		for q, want := range map[string]int{
			"SELECT count(*) FROM tenant_context WHERE tenant='tenant-alpha' AND active=" + strconv.Itoa(active) + " AND highest_seq=" + strconv.Itoa(seq) + " AND highest_id='" + highest + "'": 1,
			"SELECT count(*) FROM tenant_key WHERE tenant='tenant-alpha' AND login=1 AND id='" + tenantA.root.Rec.ID + "'":                                                                       1,
			"SELECT count(*) FROM tenant_policy WHERE id='" + p1.ID + "' AND body IS NULL":                                                                                                       1,
			"SELECT count(*) FROM policy_logout WHERE id='" + p1.ID + "'":                                                                                                                        1,
		} {
			if got := countIn(t, memory, q); got != want {
				t.Fatalf("%s: %q = %d, want %d", stage, q, got, want)
			}
		}
		fenced(stage, "alphasecretrulecanary", governedA)
	}
	retainedA("after logout A", 0, 1, p1.ID)

	// New capture after logout is unrestricted: no policy, readable, bundleable.
	createTaskIn(n, "login-after-logout", "Investigate the afterlogoutbadgercanary fixture")
	afterLogout, afterPol := taskWith(t, d.paths.Data, "afterlogoutbadgercanary")
	if afterPol != "" || len(governedRecords(t, d.paths.Data, p1.ID)) != len(governedA) {
		t.Fatal("post-logout capture sealed under a policy", afterPol)
	}
	if r := exclusionOf(selectionOf(t, d, []string{afterLogout}), afterLogout); r == store.ExcludedPolicy {
		t.Fatal("post-logout task refused by policy")
	}

	// Login to tenant B with a fresh key.
	jktB := mustCLI("", "login", "--key")
	if jktB == jktA {
		t.Fatal("logout did not delete the DPoP key")
	}
	q1, q1Env := tenantB.policy(1, "bravosecretrulecanary")
	out = mustCLI(tenantB.document(d, q1Env, "telara_mcp_bravo"), "login")
	if err = json.Unmarshal([]byte(out), &loggedIn); err != nil || loggedIn.Tenant != tenantB.tenant || loggedIn.Policy != q1.ID {
		t.Fatal("login B", out, err)
	}
	status := mustCLI("", "sync", "status")
	var st syncnode.StatusReport
	if err = json.Unmarshal([]byte(status), &st); err != nil || st.Tenant != tenantB.tenant || st.Receipts != 0 || st.CtlCursor != 0 || st.DataCursor != 0 || st.Outbox["pending"] != 0 {
		t.Fatal("B did not start from empty state", status, err)
	}
	for q, want := range map[string]int{
		"SELECT count(*) FROM tenant_context WHERE active=1 AND tenant='tenant-bravo'":                     1,
		"SELECT count(*) FROM tenant_context WHERE active=1":                                               1,
		"SELECT count(*) FROM tenant_policy WHERE tenant='tenant-bravo' AND body IS NOT NULL":              1,
		"SELECT count(*) FROM tenant_policy WHERE tenant='tenant-alpha' AND body IS NOT NULL":              0,
		"SELECT count(*) FROM tenant_key WHERE tenant='tenant-bravo' AND id='" + tenantA.root.Rec.ID + "'": 0,
	} {
		if got := countIn(t, memory, q); got != want {
			t.Fatalf("after login B %q = %d", q, got)
		}
	}
	for q, want := range map[string]int{
		"SELECT count(*) FROM outbox":           0,
		"SELECT count(*) FROM operation":        0,
		"SELECT count(*) FROM delivery_receipt": 0,
	} {
		if got := countIn(t, syncDB, q); got != want {
			t.Fatalf("after login B %q = %d", q, got)
		}
	}
	retainedA("after login B", 0, 1, p1.ID)

	// B-governed capture works and never reuses A's policy.
	createTaskIn(n, "login-tenant-b", "Investigate the bravogovernedcranecanary fixture")
	createTaskIn(n, "login-tenant-b-second", "Investigate the second bravo fixture")
	governedB := governedRecords(t, d.paths.Data, q1.ID)
	if _, pol := taskWith(t, d.paths.Data, "bravogovernedcranecanary"); pol != q1.ID {
		t.Fatal("B capture not sealed under B's policy", pol)
	}
	if len(governedB) < 2 || len(governedRecords(t, d.paths.Data, p1.ID)) != len(governedA) {
		t.Fatal("B capture provenance")
	}

	// Erase the pre-login checkpoint under B. It is an executed root, so every
	// later output of this machine is held and a new operation is reported
	// as unavailable, never as a storage failure.
	var receipt bytes.Buffer
	if err = run(context.Background(), []string{"erase", "--data-dir", d.paths.Data, "--run-dir", d.paths.Run, "--yes", "--json", "--id", preCheckpoint}, strings.NewReader(""), &receipt); err != nil {
		t.Fatal(publicCode(err), receipt.String())
	}
	tombs := countIn(t, memory, "SELECT count(*) FROM tomb WHERE target='"+preCheckpoint+"'")
	if tombs == 0 || snapshotOf(t, d, preCheckpoint).BodyJCS != nil {
		t.Fatal("erase left no tomb")
	}
	if r := callToolIn(n, "login-after-erase", "telara_task_create", map[string]any{"goal": "after the erased root"}); !r.IsError || r.Content[0].Text != "unavailable" {
		t.Fatal("held operation not reported unavailable", r)
	}
	tombSurvives := func(stage string) {
		t.Helper()
		if got := countIn(t, memory, "SELECT count(*) FROM tomb WHERE target='"+preCheckpoint+"'"); got != tombs || snapshotOf(t, d, preCheckpoint).BodyJCS != nil {
			t.Fatal(stage, "tomb lost or erased checkpoint resurrected", got)
		}
	}

	// Logout of B, then login to A again: a different tenant from the active
	// one. Tombs, both pins and every per-record logout fence survive, and
	// re-login to A with a newer policy cannot reopen A's earlier records.
	if out = mustCLI("", "logout"); !strings.Contains(out, `"physical":"complete"`) {
		t.Fatal("logout B", out)
	}
	tombSurvives("after logout B")
	retainedA("after logout B", 0, 1, p1.ID)
	fenced("after logout B", "bravosecretrulecanary", governedB)
	if countIn(t, memory, "SELECT count(*) FROM policy_logout WHERE id='"+q1.ID+"'") != 1 || countIn(t, memory, "SELECT count(*) FROM tenant_key WHERE tenant='tenant-bravo' AND login=1") != 1 {
		t.Fatal("B logout fence or pin missing")
	}
	mustCLI("", "login", "--key")
	p2, p2Env := tenantA.policy(2, "alphasecondrulecanary")
	if _, err = cli(tenantA.document(d, p1Env, "telara_mcp_alpha_again"), "login"); publicCode(err) != "login_policy_not_current" {
		t.Fatal("re-login accepted a policy at the logged-out sequence")
	}
	out = mustCLI(tenantA.document(d, p2Env, "telara_mcp_alpha_again"), "login")
	if err = json.Unmarshal([]byte(out), &loggedIn); err != nil || loggedIn.Tenant != tenantA.tenant || loggedIn.Policy != p2.ID || loggedIn.Seq != 2 {
		t.Fatal("re-login A", out, err)
	}
	tombSurvives("after re-login A")
	retainedA("after re-login A", 1, 2, p2.ID)
	fenced("after re-login A", "bravosecretrulecanary", governedB)
	mustCLI("", "logout")
	tombSurvives("after final logout")
	retainedA("after final logout", 0, 2, p2.ID)
}

// TestReceiptIssuerRequiresServiceKeysPinnedByTLSLogin: receipt authority is a
// service key the origin's authenticated TLS login response returned. An
// enrollment document is terminal input, so `sync enroll` records its service
// keys without pin provenance and gives no receipt authority. A login document
// that names an attacker's service key is refused even though its policy root
// is the legitimate one, and nothing is pinned. Only the legitimate login pins
// the key the response returned.
func TestReceiptIssuerRequiresServiceKeysPinnedByTLSLogin(t *testing.T) {
	useBundleVaults(t)
	old := syncVault
	syncVault = func(dir string) syncnode.SecretVault {
		bundleVaults.Lock()
		defer bundleVaults.Unlock()
		return bundleVaults.m[dir]
	}
	t.Cleanup(func() { syncVault = old })
	d := newGenesisDevice(t)
	d.start()
	cli := func(stdin string, args ...string) error {
		var out bytes.Buffer
		return run(context.Background(), append(args, "--data-dir", d.paths.Data), strings.NewReader(stdin), &out)
	}
	tenant := newLoginTenant(t, 84, "tenant-service-pin", "service-user")
	_, policyEnv := tenant.policy(1, "servicepinrulecanary")
	if err := cli("", "login", "--key"); err != nil {
		t.Fatal(publicCode(err))
	}

	// An attacker-chosen service key in otherwise valid terminal input.
	attacker, _, _ := ed25519.GenerateKey(rand.Reader)
	var doc syncnode.LoginDocument
	if err := json.Unmarshal([]byte(tenant.document(d, policyEnv, "telara_mcp_service_pin")), &doc); err != nil {
		t.Fatal(err)
	}
	doc.ServiceKeys = []syncnode.ServiceKey{{KeyID: sig.KeyID(attacker), Public: base64.RawURLEncoding.EncodeToString(attacker)}}
	enrollOnly, _ := json.Marshal(doc.Enrollment)
	if err := cli(string(enrollOnly), "sync", "enroll"); err != nil {
		t.Fatal("sync enroll", publicCode(err))
	}
	if p, err := syncnode.LoadProfile(d.paths.Data); err != nil || !p.Enrolled() || p.ServiceKeysPinned() {
		t.Fatalf("enroll-only profile: pinned=%v err=%v", p.ServiceKeysPinned(), err)
	}
	if issuer := receiptIssuer(d.paths.Data); issuer != nil {
		t.Fatal("an enrollment document established receipt authority")
	}
	forged, _ := json.Marshal(doc)
	if err := cli(string(forged), "login"); publicCode(err) != "login_root_unverified" {
		t.Fatal("login naming an attacker service key", publicCode(err))
	}
	if issuer := receiptIssuer(d.paths.Data); issuer != nil {
		t.Fatal("a refused login left receipt authority")
	}
	// A response returning a key the tenant did not sign is refused too.
	stranger, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(stranger, record.RoleService, ""), Genesis: "another-tenant"}, stranger, "", time.Now().UnixMilli(), strangerPriv)
	if err != nil {
		t.Fatal(err)
	}
	tenant.serviceReply = []record.Envelope{nodesync.Envelope(op.Rec.HeaderJCS, op.Rec.BodyJCS, op.Sigs, op.Rec.ID)}
	if err := cli(tenant.document(d, policyEnv, "telara_mcp_service_pin"), "login"); publicCode(err) != "login_root_unverified" {
		t.Fatal("login response with another tenant's service key", publicCode(err))
	}
	if issuer := receiptIssuer(d.paths.Data); issuer != nil {
		t.Fatal("a refused login response left receipt authority")
	}
	tenant.serviceReply = nil
	if err := cli(tenant.document(d, policyEnv, "telara_mcp_service_pin"), "login"); err != nil {
		t.Fatal("legitimate login", publicCode(err))
	}
	issuer := receiptIssuer(d.paths.Data)
	if issuer == nil || issuer.Tenant != tenant.tenant || len(issuer.Keys) != 1 || !bytes.Equal(issuer.Keys[sig.KeyID(tenant.service)], tenant.service) || issuer.Keys[sig.KeyID(attacker)] != nil {
		t.Fatal("receipt authority is not the TLS-pinned service key")
	}
}
