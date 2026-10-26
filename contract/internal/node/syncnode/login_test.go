package syncnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// tenantAuthority is one hosted tenant's policy key and pinned login root.
type tenantAuthority struct {
	t      *testing.T
	key    ed25519.PrivateKey
	tenant string
	user   string
	root   *sig.KeyOp
}

func newTenantAuthority(t *testing.T, seed byte, tenant, user string) *tenantAuthority {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	pub := key.Public().(ed25519.PublicKey)
	root, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKey, Subject: sig.KeyRefOf(pub, record.RolePolicy, ""), Genesis: tenant}, pub, "", time.Now().UnixMilli(), key)
	if err != nil {
		t.Fatal(err)
	}
	return &tenantAuthority{t: t, key: key, tenant: tenant, user: user, root: root}
}

// policy returns a signed fresh policy that permits push-metadata for every
// remote and carries a private rule string that logout must purge.
func (a *tenantAuthority) policy(seq int64, secret string) (*record.Record, record.Envelope) {
	a.t.Helper()
	now := time.Now().UnixMilli()
	pb := &record.PolicyBody{Tenant: a.tenant, Seq: seq, IssuedAt: now - 1000, RefreshAfter: now + 1800000, NotAfter: now + 3600000}
	pb.Applies.Users = []string{a.user}
	pb.Push = record.PolicyPush{MaxProfile: record.ProfilePushMetadata, AllowRepos: []string{"*"}}
	pb.BlockedRepos = []record.BlockedRepo{{RemoteGlob: "blocked.example/" + secret, Effect: "no-push"}}
	pub := a.key.Public().(ed25519.PublicKey)
	r, err := record.Build(record.Header{Type: record.KindPolicy, LID: record.PolicyLID(a.tenant), At: now, Author: record.Author{KeyID: sig.KeyID(pub)}, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, pb)
	if err != nil {
		a.t.Fatal(err)
	}
	s, err := sig.SignRecord(a.key, r.ID)
	if err != nil {
		a.t.Fatal(err)
	}
	return r, envelopeOf(r, []record.Signature{s})
}

// loginDocument is what one authenticated hosted login returns for h.
func (w *world) loginDocument(h *hosted, a *tenantAuthority, policy record.Envelope) LoginDocument {
	w.t.Helper()
	jwk, err := nodesync.PublicJWKOf(&h.authKey.PublicKey)
	if err != nil {
		w.t.Fatal(err)
	}
	root := envelopeOf(a.root.Rec, a.root.Sigs)
	h.mu.Lock()
	h.policyRoot = &root
	h.mu.Unlock()
	d := LoginDocument{Enrollment: Enrollment{Origin: h.srv.URL, Tenant: h.tenant, User: h.user, Config: h.config, AuthIssuer: "https://auth.example", AuthKey: jwk, ServiceKeys: []ServiceKey{h.serviceKey()}, Grant: h.grant, RefreshToken: h.bootstrap}, PolicyRoot: envelopeOf(a.root.Rec, a.root.Sigs), Policy: policy}
	// Round-trip through the strict terminal decoder the command uses.
	raw, err := json.Marshal(d)
	if err != nil {
		w.t.Fatal(err)
	}
	parsed, err := ParseLogin(bytes.NewReader(raw))
	if err != nil {
		w.t.Fatal(err)
	}
	return parsed
}

// installKey records the installed identity and provisions the DPoP key, as
// installation and the key step do.
func (w *world) installKey() {
	w.t.Helper()
	manifest, _ := json.Marshal(map[string]any{"version": 1, "owner": w.genesis, "machine": testMachine, "credential": "22222222-2222-4222-8222-222222222222", "vault_handle": strings.Repeat("ab", 16)})
	if err := store.WriteInstalledRecord(w.dir, manifest); err != nil {
		w.t.Fatal(err)
	}
	if _, err := CreateKey(context.Background(), w.dir, w.vault); err != nil {
		w.t.Fatal(err)
	}
}

// session appends a device session page with a repository remote, sealed
// under pol, the only kind a governed policy can push.
func (w *world) session(n int, remote, pol string) *record.Record {
	w.t.Helper()
	native := fmt.Sprintf("login-session-%d", n)
	repo, err := record.RepoID(remote)
	if err != nil {
		w.t.Fatal(err)
	}
	sk, err := record.SessionKey("codex", "local", record.NativeGlobal, native, testMachine)
	if err != nil {
		w.t.Fatal(err)
	}
	r, s := w.signed(record.Header{Type: record.KindSession, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk, RepoID: repo}, LID: record.SessionLID(sk, testMachine, 0), Pol: pol}, &record.SessionBody{NativeID: native, NativeIDKind: record.NativeGlobal, Repo: &record.RepoRef{ID: repo, Remote: remote}})
	w.append(r, s)
	return r
}

// storeDB opens the node database read-only for physical inspection.
func storeDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: filepath.Join(dir, "memory.sqlite"), RawQuery: "mode=ro"}).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func scalar(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(q, err)
	}
	return n
}

func entryOf(t *testing.T, st *store.Store, id string) store.Entry {
	t.Helper()
	snap, err := st.Snapshot(context.Background(), storeRead(id))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range snap.Entries {
		if e.ID == id {
			return e
		}
	}
	t.Fatal("not present", id)
	return store.Entry{}
}

func bundleExclusion(t *testing.T, st *store.Store, id string) string {
	t.Helper()
	sel, err := st.SelectBundle(context.Background(), []string{id})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range sel.Excluded {
		if e.ID == id {
			return e.Reason
		}
	}
	for _, r := range sel.Data {
		if r.AdvisoryID == id {
			return ""
		}
	}
	t.Fatal("selection neither carried nor excluded", id)
	return ""
}

func importsContain(h *hosted, needles ...string) bool {
	for _, body := range h.imports() {
		for _, n := range needles {
			if bytes.Contains(body, []byte(n)) {
				return true
			}
		}
	}
	return false
}

// TestLogoutThenLoginToDifferentTenantKeepsFencesAndCopiesNothing logs in to
// tenant A over the hosted fixture, pushes a governed session and enforces a
// policy replacement and an erasure from A's control log, logs out, then logs
// in to tenant B. Pins, rollback facts, tombs and per-record logout fences
// survive; A's credentials, queue, cursors, controls and policy secrets do
// not; nothing sealed under A reaches B, and B starts from empty state.
func TestLogoutThenLoginToDifferentTenantKeepsFencesAndCopiesNothing(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.installKey()
	remoteA, remoteB := "github.com/acme/tenant-a-repo", "github.com/acme/tenant-b-repo"
	repoRemoteA, _ := record.RepoID(remoteA)
	repoRemoteB, _ := record.RepoID(remoteB)
	repos := []string{repoA, repoRemoteA, repoRemoteB}
	w.hosted.grant.Repos = repos
	before := w.task(1, repoA, "active")

	// Tenant A login pins A's policy root and admits its first policy.
	authA := newTenantAuthority(t, 61, w.hosted.tenant, w.hosted.user)
	p1, p1Env := authA.policy(1, "tenantasecretrulecanary")
	report, err := LoginTLS(ctx, w.dir, w.vault, w.hosted.roots(), w.loginDocument(w.hosted, authA, p1Env))
	if err != nil || report.Tenant != w.hosted.tenant || report.Policy != p1.ID || report.Seq != 1 {
		t.Fatal("login A", report, err)
	}
	profileA, err := LoadProfile(w.dir)
	if err != nil || !profileA.Enrolled() || !profileA.Enabled {
		t.Fatal("login A profile", err)
	}

	// A second login is refused until explicit logout, both to another tenant
	// and to another destination of the same tenant.
	hostedB := newHosted(t, w.key.Public().(ed25519.PublicKey), testMachine, repos)
	hostedB.tenant, hostedB.user, hostedB.config, hostedB.bootstrap = "tenant-two", "user-two", "config-two", "telara_mcp_bootstrap_two"
	authB := newTenantAuthority(t, 62, hostedB.tenant, hostedB.user)
	q1, q1Env := authB.policy(1, "tenantbsecretrulecanary")
	if _, err = Login(ctx, w.dir, w.vault, w.loginDocument(hostedB, authB, q1Env)); !errors.Is(err, ErrTenantConflict) {
		t.Fatal("second tenant login while logged in", err)
	}
	sameTenantOtherUser := w.loginDocument(w.hosted, authA, p1Env)
	sameTenantOtherUser.User = "someone-else"
	if _, err = Login(ctx, w.dir, w.vault, sameTenantOtherUser); !errors.Is(err, ErrTenantConflict) {
		t.Fatal("second destination login while logged in", err)
	}
	if err = Enroll(ctx, w.dir, w.vault, w.loginDocument(hostedB, authB, q1Env).Enrollment); !errors.Is(err, ErrTenantConflict) {
		t.Fatal("enroll switched tenants without logout", err)
	}
	if p, _ := LoadProfile(w.dir); p.Tenant != w.hosted.tenant {
		t.Fatal("refused login changed the profile")
	}

	// Under A: a governed session pushes; A's control log replaces the policy
	// and erases the pre-login task, leaving a tomb.
	sessionA := w.session(1, remoteA, p1.ID)
	p2, p2Env := authA.policy(2, "tenantasecondrulecanary")
	w.hosted.addControl(p2Env)
	w.hosted.addControl(w.control(1, record.KindErasure, before.ID))
	wk := w.worker()
	if _, err = wk.state.PutRule(ctx, "default", repos, []string{"session", "task"}, true); err != nil {
		t.Fatal(err)
	}
	if err = wk.Round(ctx); err != nil {
		t.Fatal("round A", err)
	}
	if rows(t, wk, profileA)[sessionA.ID] != stateComplete {
		t.Fatal("governed session was not pushed to A", rows(t, wk, profileA))
	}
	// A late row still queued for A when logout happens.
	w.hosted.mu.Lock()
	w.hosted.importStatuses = []int{503, 503, 503, 503}
	w.hosted.mu.Unlock()
	sessionA2 := w.session(2, remoteA, p2.ID)
	_ = wk.Round(ctx)
	if rows(t, wk, profileA)[sessionA2.ID] != statePending {
		t.Fatal("second A row not pending", rows(t, wk, profileA))
	}
	db := storeDB(t, w.dir)
	tombs := scalar(t, db, "SELECT count(*) FROM tomb")
	if tombs == 0 || len(entryOf(t, w.st, before.ID).BodyJCS) != 0 {
		t.Fatal("A's erasure was not enforced", tombs)
	}
	importsA := len(w.hosted.imports())
	destA := destination(profileA.Scope())
	receiptsA := count(t, wk, "SELECT count(*) FROM delivery_receipt WHERE destination=?", destA)

	// Logout from A.
	out, err := LogoutDetailed(ctx, w.dir, w.vault)
	if err != nil || out.State != "logged_out" || out.HostedHistory != "not_deleted" {
		t.Fatal("logout", out, err)
	}
	if out.Physical != "complete" {
		t.Fatal("policy secrets not physically scrubbed", out)
	}
	if _, err = LoadProfile(w.dir); !Disabled(err) {
		t.Fatal("profile survived logout", err)
	}
	if w.vault.count() != 0 {
		t.Fatal("logout left credential slots", w.vault.count())
	}
	for q, want := range map[string]int{
		"SELECT count(*) FROM operation WHERE destination=? AND state='pending'":                                          0,
		"SELECT count(*) FROM outbox WHERE destination=? AND (header IS NOT NULL OR body IS NOT NULL OR state='pending')": 0,
		"SELECT count(*) FROM ctl_pending WHERE destination=?":                                                            0,
		"SELECT count(*) FROM data_quarantine WHERE destination=?":                                                        0,
		"SELECT count(*) FROM sync_state WHERE destination=?":                                                             0,
	} {
		if n := count(t, wk, q, destA); n != want {
			t.Fatalf("after logout %q = %d", q, n)
		}
	}
	if count(t, wk, "SELECT count(*) FROM delivery_receipt WHERE destination=?", destA) != receiptsA {
		t.Fatal("verified receipts were not retained")
	}
	if err = wk.Round(ctx); !errors.Is(err, ErrNotEnrolled) {
		t.Fatal("round after logout", err)
	}
	if len(w.hosted.imports()) != importsA {
		t.Fatal("A received data after logout")
	}
	// Retained fences: A's login pin, rollback watermark, per-record logout
	// facts and tombs; every A policy body and salt is gone.
	checkRetainedA := func(stage string) {
		t.Helper()
		var seq int
		var id string
		var active bool
		if err := db.QueryRow("SELECT highest_seq,highest_id,active FROM tenant_context WHERE tenant=?", w.hosted.tenant).Scan(&seq, &id, &active); err != nil || seq != 2 || id != p2.ID || active {
			t.Fatal(stage, "A rollback fence", seq, id, active, err)
		}
		if scalar(t, db, "SELECT count(*) FROM tenant_key WHERE tenant=? AND login=1 AND id=?", w.hosted.tenant, authA.root.Rec.ID) != 1 {
			t.Fatal(stage, "A login pin lost")
		}
		if scalar(t, db, "SELECT count(*) FROM tenant_policy WHERE tenant=? AND body IS NOT NULL", w.hosted.tenant) != 0 {
			t.Fatal(stage, "A policy body retained")
		}
		if scalar(t, db, "SELECT count(*) FROM policy_logout WHERE id IN(?,?)", p1.ID, p2.ID) != 2 {
			t.Fatal(stage, "per-record logout fence missing")
		}
		if scalar(t, db, "SELECT count(*) FROM tomb") != tombs || len(entryOf(t, w.st, before.ID).BodyJCS) != 0 {
			t.Fatal(stage, "tomb lost")
		}
		for _, id := range []string{sessionA.ID, sessionA2.ID} {
			if len(entryOf(t, w.st, id).BodyJCS) != 0 {
				t.Fatal(stage, "A-governed body readable after logout")
			}
			if reason := bundleExclusion(t, w.st, id); reason != store.ExcludedPolicy {
				t.Fatal(stage, "A-governed record bundleable", reason)
			}
		}
	}
	checkRetainedA("after logout")
	for _, secret := range []string{"tenantasecretrulecanary", "tenantasecondrulecanary"} {
		for _, suffix := range []string{"", "-wal"} {
			if raw, _ := readIfExists(filepath.Join(w.dir, "memory.sqlite") + suffix); bytes.Contains(raw, []byte(secret)) {
				t.Fatal("policy rule text survived logout in", suffix)
			}
		}
	}
	// New capture after logout is unrestricted and carries no policy.
	after := w.task(3, repoA, "active")
	if after.Header.Pol != "" || len(entryOf(t, w.st, after.ID).BodyJCS) == 0 || bundleExclusion(t, w.st, after.ID) != "" {
		t.Fatal("post-logout capture restricted")
	}

	// Login to tenant B needs a fresh key: logout deleted the old DPoP key.
	if _, err = Login(ctx, w.dir, w.vault, w.loginDocument(hostedB, authB, q1Env)); !errors.Is(err, ErrNotEnrolled) {
		t.Fatal("login reused a deleted key", err)
	}
	if _, err = CreateKey(ctx, w.dir, w.vault); err != nil {
		t.Fatal(err)
	}
	report, err = LoginTLS(ctx, w.dir, w.vault, hostedB.roots(), w.loginDocument(hostedB, authB, q1Env))
	if err != nil || report.Tenant != hostedB.tenant || report.Policy != q1.ID {
		t.Fatal("login B", report, err)
	}
	profileB, err := LoadProfile(w.dir)
	if err != nil || profileB.Credential == profileA.Credential || profileB.Refresh == profileA.Refresh {
		t.Fatal("B reused A credential slots", err)
	}
	destB := destination(profileB.Scope())
	if destB == destA {
		t.Fatal("tenants share a destination")
	}
	status, err := Status(ctx, w.dir)
	if err != nil || status.Tenant != hostedB.tenant || status.Receipts != 0 || status.CtlCursor != 0 || status.DataCursor != 0 || len(status.Outbox) != 0 {
		t.Fatal("B did not start from empty state", status, err)
	}
	// A's later controls are never fetched by B.
	w.hosted.addControl(w.control(2, record.KindErasure, after.ID))
	sessionB := w.session(3, remoteB, q1.ID)
	if err = wk.Round(ctx); err != nil {
		t.Fatal("round B", err)
	}
	got := rows(t, wk, profileB)
	if got[sessionB.ID] != stateComplete {
		t.Fatal("B's own session was not pushed", got)
	}
	for _, id := range []string{sessionA.ID, sessionA2.ID, before.ID, after.ID} {
		if _, ok := got[id]; ok {
			t.Fatal("record queued for B that B must not receive", id[:8])
		}
	}
	for _, r := range []*record.Record{sessionA, sessionA2} {
		if importsContain(hostedB, r.Header.Subj.SessionKey, r.Header.LID, r.ID) {
			t.Fatal("A-governed record reached tenant B")
		}
	}
	if importsContain(hostedB, w.hosted.tenant, p1.ID, p2.ID) || len(w.hosted.imports()) != importsA {
		t.Fatal("tenant A provenance crossed to B, or A received data")
	}
	if len(entryOf(t, w.st, after.ID).BodyJCS) == 0 {
		t.Fatal("A's post-logout control reached the node through B")
	}
	status, _ = Status(ctx, w.dir)
	if status.Receipts != 1 {
		t.Fatal("B receipts include another destination's", status.Receipts)
	}
	if scalar(t, db, "SELECT count(*) FROM tenant_context WHERE active=1 AND tenant=?", hostedB.tenant) != 1 || scalar(t, db, "SELECT count(*) FROM tenant_policy WHERE tenant=?", hostedB.tenant) != 1 {
		t.Fatal("B authority not installed alone")
	}
	checkRetainedA("after login B")

	// Logging out of B leaves A's facts as they were and fences B's records.
	if _, err = LogoutDetailed(ctx, w.dir, w.vault); err != nil {
		t.Fatal(err)
	}
	checkRetainedA("after logout B")
	if scalar(t, db, "SELECT count(*) FROM policy_logout WHERE id=?", q1.ID) != 1 || bundleExclusion(t, w.st, sessionB.ID) != store.ExcludedPolicy {
		t.Fatal("B logout fence missing")
	}
}

func readIfExists(path string) ([]byte, error) { return os.ReadFile(path) }
