package syncnode

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"
)

// failingDeletes is native custody whose deletions fail while failing is set.
type failingDeletes struct {
	*memVault
	mu      sync.Mutex
	failing bool
}

func (v *failingDeletes) Delete(ctx context.Context, h string) error {
	v.mu.Lock()
	failing := v.failing
	v.mu.Unlock()
	if failing {
		return errors.New("native deletion failed")
	}
	return v.memVault.Delete(ctx, h)
}

func (v *failingDeletes) set(failing bool) {
	v.mu.Lock()
	v.failing = failing
	v.mu.Unlock()
}

func (v *memVault) handles() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []string
	for h := range v.items {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// referenced returns the slots the current profile uses, sorted.
func referenced(t *testing.T, dir string) []string {
	t.Helper()
	p, err := LoadProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := []string{p.Credential}
	if p.Refresh != "" {
		out = append(out, p.Refresh)
	}
	sort.Strings(out)
	return out
}

// A replacement login cannot forget the refresh credential it replaces. When
// native deletion of the old slot fails, the replacement still succeeds but
// reports cleanup pending, status and blockers say so, and the slot stays
// recorded: a later logout or login deletes it. On no path does custody keep
// a slot the profile no longer names.
func TestRefreshReplacementKeepsUndeletedCredentialsUntilDeleted(t *testing.T) {
	ctx := context.Background()
	for _, recovery := range []string{"logout", "login"} {
		t.Run(recovery, func(t *testing.T) {
			w := newWorld(t)
			v := &failingDeletes{memVault: w.vault}
			w.installKey()
			auth := newTenantAuthority(t, 61, w.hosted.tenant, w.hosted.user)
			_, policy := auth.policy(1, "retirerulecanary")
			doc := w.loginDocument(w.hosted, auth, policy)
			if err := Enroll(ctx, w.dir, v, doc.Enrollment); err != nil {
				t.Fatal("first enrollment", err)
			}
			first, err := LoadProfile(w.dir)
			if err != nil {
				t.Fatal(err)
			}
			v.set(true)
			report, err := LoginTLS(ctx, w.dir, v, w.hosted.roots(), doc)
			if err != nil || report.CredentialCleanup != "pending" {
				t.Fatal("replacement login", report, err)
			}
			second, err := LoadProfile(w.dir)
			if err != nil || second.Refresh == first.Refresh || len(second.Retired) != 1 || second.Retired[0] != first.Refresh {
				t.Fatalf("replaced refresh slot not recorded: %+v %v", second.Retired, err)
			}
			status, err := Status(ctx, w.dir)
			if err != nil || status.CredentialCleanup != "pending" || !contains(Blockers(status, time.Now()), "credential_cleanup_pending") {
				t.Fatal("status does not report pending cleanup", status, err)
			}
			// A logout whose deletions fail keeps the profile and every slot.
			if _, err = LogoutDetailed(ctx, w.dir, v); err == nil {
				t.Fatal("logout reported success with credentials undeleted")
			}
			if p, err := LoadProfile(w.dir); err != nil || !contains(p.Retired, first.Refresh) {
				t.Fatal("failed logout forgot a retired slot", err)
			}
			v.set(false)
			switch recovery {
			case "logout":
				if _, err = LogoutDetailed(ctx, w.dir, v); err != nil {
					t.Fatal("logout", err)
				}
				if n := w.vault.count(); n != 0 {
					t.Fatalf("logout left %d credential slots", n)
				}
			case "login":
				if _, err = CreateKey(ctx, w.dir, v); err != nil {
					t.Fatal(err)
				}
				// Logout purged the first policy; the tenant issues a newer one.
				_, newer := auth.policy(2, "retirerulecanarytwo")
				report, err = LoginTLS(ctx, w.dir, v, w.hosted.roots(), w.loginDocument(w.hosted, auth, newer))
				if err != nil || report.CredentialCleanup != "complete" {
					t.Fatal("login after recovery", report, err)
				}
				if got, want := w.vault.handles(), referenced(t, w.dir); fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("custody %v, profile names %v", got, want)
				}
				if status, _ := Status(ctx, w.dir); status.CredentialCleanup != "" {
					t.Fatal("cleanup still reported pending")
				}
			}
		})
	}
}

// A crash at any durable step of a refresh replacement leaves custody
// reconcilable: after restart the next enrollment deletes every slot the
// profile does not use, and logout leaves no slot at all.
func TestRefreshReplacementCrashPointsLeaveNoUnrecordedCredential(t *testing.T) {
	ctx := context.Background()
	for _, stage := range []string{"intent_saved", "refresh_stored", "profile_replaced", "retired_deleted"} {
		t.Run(stage, func(t *testing.T) {
			w := newWorld(t)
			w.installKey()
			auth := newTenantAuthority(t, 61, w.hosted.tenant, w.hosted.user)
			_, policy := auth.policy(1, "crashrulecanary")
			e := w.loginDocument(w.hosted, auth, policy).Enrollment
			if err := Enroll(ctx, w.dir, w.vault, e); err != nil {
				t.Fatal(err)
			}
			crashed := func() (stopped bool) {
				defer func() {
					if r := recover(); r != nil {
						if r != stage {
							panic(r)
						}
						stopped = true
					}
				}()
				crashPoint = func(at string) {
					if at == stage {
						panic(stage)
					}
				}
				defer func() { crashPoint = func(string) {} }()
				_ = Enroll(ctx, w.dir, w.vault, e)
				return false
			}()
			if !crashed {
				t.Fatalf("replacement never reached %s", stage)
			}
			// Restart: nothing in memory survives; only the profile and custody.
			if err := Enroll(ctx, w.dir, w.vault, e); err != nil {
				t.Fatal("enrollment after crash", err)
			}
			if got, want := w.vault.handles(), referenced(t, w.dir); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("custody %v, profile names %v", got, want)
			}
			if p, _ := LoadProfile(w.dir); len(p.Retired) != 0 {
				t.Fatalf("retirement not completed: %v", p.Retired)
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
