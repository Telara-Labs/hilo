package syncnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/custodyguard"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

func attackerServiceKey(t *testing.T) (ServiceKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ServiceKey{KeyID: sig.KeyID(pub), Public: base64.RawURLEncoding.EncodeToString(pub)}, priv
}

// Receipt keys are pinned only from the origin's authenticated TLS login
// response. A login document naming an attacker's service key next to the
// legitimate policy root is refused and pins nothing; so is a response whose
// service key is not a possession-signed service tenant_key of the
// authenticated tenant. A document that names no service keys pins exactly
// the ones the response returned, with pinned-TLS-login provenance.
func TestLoginPinsServiceKeysOnlyFromTheAuthenticatedResponse(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.installKey()
	h := w.hosted
	auth := newTenantAuthority(t, 61, h.tenant, h.user)
	_, policy := auth.policy(1, "servicepinrulecanary")
	doc := w.loginDocument(h, auth, policy)
	unchanged := func(stage string) {
		t.Helper()
		if p, err := LoadProfile(w.dir); err != nil || p.Enrolled() || p.ServiceKeysPinned() || len(p.ServiceKeys) != 0 {
			t.Fatalf("%s: profile changed: %+v %v", stage, p, err)
		}
	}

	attacker, attackerKey := attackerServiceKey(t)
	forged := doc
	forged.ServiceKeys = []ServiceKey{attacker}
	if _, err := LoginTLS(ctx, w.dir, w.vault, h.roots(), forged); !errors.Is(err, ErrLoginUnverified) {
		t.Fatalf("document naming an attacker service key: %v", err)
	}
	unchanged("forged document")

	tampered := serviceKeyOp(t, h.tsk, h.tenant)
	tampered.Sigs = append([]record.Signature(nil), tampered.Sigs...)
	other := serviceKeyOp(t, attackerKey, h.tenant)
	tampered.Sigs[0].Value = other.Sigs[0].Value
	for name, reply := range map[string][]record.Envelope{
		"none":          {},
		"other tenant":  {serviceKeyOp(t, h.tsk, "tenant-other")},
		"policy role":   {envelopeOf(auth.root.Rec, auth.root.Sigs)},
		"bad signature": {tampered},
	} {
		h.mu.Lock()
		h.serviceKeys = reply
		h.mu.Unlock()
		if _, err := LoginTLS(ctx, w.dir, w.vault, h.roots(), doc); !errors.Is(err, ErrLoginUnverified) {
			t.Fatalf("response with %s service keys: %v", name, err)
		}
		unchanged(name)
	}
	h.mu.Lock()
	h.serviceKeys = nil
	h.mu.Unlock()

	bare := doc
	bare.ServiceKeys = nil
	if _, err := LoginTLS(ctx, w.dir, w.vault, h.roots(), bare); err != nil {
		t.Fatal("legitimate login", err)
	}
	p, err := LoadProfile(w.dir)
	if err != nil || !p.ServiceKeysPinned() || p.ServiceKeyPins != string(sig.PinnedTLSLogin) || len(p.ServiceKeys) != 1 || p.ServiceKeys[0] != h.serviceKey() {
		t.Fatalf("pinned service keys %+v %v", p, err)
	}
}

// `sync enroll` is offline terminal input. Its service keys are recorded but
// are no receipt authority: no round runs and no network is contacted until a
// login pins them. A later enrollment to the same destination cannot replace
// keys a login pinned.
func TestEnrollmentServiceKeysAreNeverReceiptAuthority(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.installKey()
	h := w.hosted
	auth := newTenantAuthority(t, 61, h.tenant, h.user)
	_, policy := auth.policy(1, "enrollpinrulecanary")
	doc := w.loginDocument(h, auth, policy)
	attacker, _ := attackerServiceKey(t)
	e := doc.Enrollment
	e.ServiceKeys = []ServiceKey{attacker}
	if err := Enroll(ctx, w.dir, w.vault, e); err != nil {
		t.Fatal(err)
	}
	p, err := LoadProfile(w.dir)
	if err != nil || !p.Enrolled() || p.ServiceKeysPinned() || p.ServiceKeyPins != "" {
		t.Fatalf("enrolled profile claims pins: %+v %v", p, err)
	}
	wk := w.worker()
	if err := wk.Round(ctx); !errors.Is(err, ErrServiceKeysUnpinned) {
		t.Fatalf("round with unpinned receipt keys: %v", err)
	}
	h.mu.Lock()
	mints := h.mints
	h.mu.Unlock()
	if mints != 0 {
		t.Fatalf("round contacted hosted %d times with unpinned receipt keys", mints)
	}
	if r, err := Status(ctx, w.dir); err != nil || r.LastError != ErrServiceKeysUnpinned.Error() {
		t.Fatalf("status %+v %v", r, err)
	}

	bare := doc
	bare.ServiceKeys = nil
	if _, err := LoginTLS(ctx, w.dir, w.vault, h.roots(), bare); err != nil {
		t.Fatal("login", err)
	}
	if err := Enroll(ctx, w.dir, w.vault, e); err != nil {
		t.Fatal("re-enrollment", err)
	}
	p, err = LoadProfile(w.dir)
	if err != nil || !p.ServiceKeysPinned() || len(p.ServiceKeys) != 1 || p.ServiceKeys[0] != h.serviceKey() {
		t.Fatalf("re-enrollment replaced pinned keys: %+v %v", p, err)
	}
}

// interleave runs first; when it reaches stage it starts second and lets first
// continue as soon as second either finishes or is waiting on the profile
// lock. It returns both results.
func interleave(t *testing.T, stage string, first func() error, second func(context.Context) error) (error, error) {
	t.Helper()
	waiting := make(chan struct{}, 1)
	done := make(chan error, 1)
	var fired atomic.Bool
	secondCtx := custodyguard.ObserveContention(context.Background(), waiting)
	crashPoint = func(at string) {
		if at != stage || !fired.CompareAndSwap(false, true) {
			return
		}
		go func() { done <- second(secondCtx) }()
		select {
		case <-waiting:
		case err := <-done:
			done <- err
		}
	}
	defer func() {
		crashPoint = func(string) {}
	}()
	errFirst := first()
	if !fired.Load() {
		t.Fatalf("first operation never reached %s", stage)
	}
	return errFirst, <-done
}

// custodyMatches fails unless custody holds exactly the slots the profile
// names, so no credential is orphaned and none the profile uses is missing.
func custodyMatches(t *testing.T, w *world, stage string) {
	t.Helper()
	p, err := LoadProfile(w.dir)
	if err != nil {
		t.Fatal(stage, err)
	}
	want := map[string]bool{p.Credential: true}
	if p.Refresh != "" {
		want[p.Refresh] = true
	}
	for _, h := range p.Retired {
		want[h] = true
	}
	got := w.vault.handles()
	if len(got) != len(want) {
		t.Fatalf("%s: custody %v, profile names %v", stage, got, want)
	}
	for _, h := range got {
		if !want[h] {
			t.Fatalf("%s: custody %v holds a slot the profile does not name; profile %v", stage, got, want)
		}
	}
}

// Two enrollments replace the refresh credential concurrently, as two
// processes would. Each reads the profile, records its intent and stores a
// new secret; without serialization the later replacement commits from a
// stale snapshot and the other's new secret is left in custody with no
// durable reference, beyond the reach of logout. Every interleaving point
// leaves custody exactly what the profile names, and logout empties it.
func TestConcurrentEnrollmentsLeaveNoOrphanedCredential(t *testing.T) {
	ctx := context.Background()
	for _, stage := range []string{"intent_saved", "refresh_stored", "profile_replaced"} {
		t.Run(stage, func(t *testing.T) {
			w := newWorld(t)
			w.installKey()
			auth := newTenantAuthority(t, 61, w.hosted.tenant, w.hosted.user)
			_, policy := auth.policy(1, "concurrentrulecanary")
			e := w.loginDocument(w.hosted, auth, policy).Enrollment
			if err := Enroll(ctx, w.dir, w.vault, e); err != nil {
				t.Fatal(err)
			}
			e1, e2 := e, e
			e1.RefreshToken, e2.RefreshToken = e.RefreshToken+"_one", e.RefreshToken+"_two"
			err1, err2 := interleave(t, stage, func() error { return Enroll(ctx, w.dir, w.vault, e1) }, func(ctx context.Context) error { return Enroll(ctx, w.dir, w.vault, e2) })
			if err1 != nil || err2 != nil {
				t.Fatalf("enrollments: %v, %v", err1, err2)
			}
			custodyMatches(t, w, "after both")
			p, _ := LoadProfile(w.dir)
			secret, err := w.vault.Get(ctx, p.Refresh)
			if err != nil || !bytes.Equal(secret, []byte(e2.RefreshToken)) {
				t.Fatalf("profile refresh slot holds %q %v, want the later enrollment's", secret, err)
			}
			if _, err := LogoutDetailed(ctx, w.dir, w.vault); err != nil {
				t.Fatal(err)
			}
			if n := w.vault.count(); n != 0 {
				t.Fatalf("logout left %d credential slots", n)
			}
		})
	}
}

// A logout interleaved with a refresh replacement either runs after it or not
// at all: it never runs between the replacement's read and its commit, which
// would let the replacement resurrect a logged-out profile naming deleted
// slots, or leave its new secret unreferenced.
func TestLogoutInterleavedWithReplacementCompletes(t *testing.T) {
	ctx := context.Background()
	for _, stage := range []string{"intent_saved", "refresh_stored"} {
		t.Run(stage, func(t *testing.T) {
			w := newWorld(t)
			w.installKey()
			auth := newTenantAuthority(t, 61, w.hosted.tenant, w.hosted.user)
			_, policy := auth.policy(1, "logoutrulecanary")
			e := w.loginDocument(w.hosted, auth, policy).Enrollment
			if err := Enroll(ctx, w.dir, w.vault, e); err != nil {
				t.Fatal(err)
			}
			e.RefreshToken += "_replacement"
			errEnroll, errLogout := interleave(t, stage, func() error { return Enroll(ctx, w.dir, w.vault, e) }, func(ctx context.Context) error {
				_, err := LogoutDetailed(ctx, w.dir, w.vault)
				return err
			})
			if errEnroll != nil || errLogout != nil {
				t.Fatalf("enroll %v, logout %v", errEnroll, errLogout)
			}
			if _, err := LoadProfile(w.dir); !Disabled(err) {
				t.Fatalf("profile survives the logout: %v", err)
			}
			if n := w.vault.count(); n != 0 {
				t.Fatalf("custody holds %d slots after logout: %v", n, w.vault.handles())
			}
		})
	}
}

// A login does not hold the profile lock across its network exchange, so it
// revalidates the profile before committing. A logout that completes while
// the login waits on the origin wins: the login commits nothing, installs no
// tenant authority and resurrects no profile.
func TestLoginRevalidatesProfileAfterNetworkWait(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.installKey()
	h := w.hosted
	auth := newTenantAuthority(t, 61, h.tenant, h.user)
	_, policy := auth.policy(1, "revalidaterulecanary")
	doc := w.loginDocument(h, auth, policy)
	var logoutErr error
	var once atomic.Bool
	h.mu.Lock()
	h.onLogin = func() {
		if once.CompareAndSwap(false, true) {
			_, logoutErr = LogoutDetailed(ctx, w.dir, w.vault)
		}
	}
	h.mu.Unlock()
	if _, err := LoginTLS(ctx, w.dir, w.vault, h.roots(), doc); !errors.Is(err, ErrProfileChanged) {
		t.Fatalf("login across a concurrent logout: %v", err)
	}
	if logoutErr != nil {
		t.Fatal("logout", logoutErr)
	}
	if _, err := LoadProfile(w.dir); !Disabled(err) {
		t.Fatalf("login resurrected the logged-out profile: %v", err)
	}
	if n := w.vault.count(); n != 0 {
		t.Fatalf("custody holds %d slots", n)
	}
	db := storeDB(t, w.dir)
	if n := scalar(t, db, "SELECT count(*) FROM tenant_context WHERE active=1"); n != 0 {
		t.Fatal(fmt.Sprintf("tenant authority active after a refused login: %d", n))
	}
}
