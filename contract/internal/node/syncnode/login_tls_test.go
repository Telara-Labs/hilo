package syncnode

import (
	"context"
	"errors"
	"testing"
)

// A login document is terminal input, not an authority for a tenant root. An
// attacker who knows the legitimate origin, tenant, user and config can sign a
// perfectly valid tenant_key root of their own for that tenant and a policy
// under it. Login must refuse it because the origin's authenticated login
// response over validated TLS returns a different root, and nothing of the
// attacker's may be pinned. The same document over an untrusted certificate,
// and a response naming another device, are refused too; only the root the
// authenticated response returns for this device is installed.
func TestLoginPinsOnlyTheRootTheAuthenticatedTLSResponseReturns(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.installKey()
	h := w.hosted
	legit := newTenantAuthority(t, 61, h.tenant, h.user)
	attacker := newTenantAuthority(t, 66, h.tenant, h.user)
	_, policy := legit.policy(1, "legitrulecanary")
	_, forgedPolicy := attacker.policy(1, "attackerrulecanary")
	doc := w.loginDocument(h, legit, policy)
	forged := doc
	forged.PolicyRoot = envelopeOf(attacker.root.Rec, attacker.root.Sigs)
	forged.Policy = forgedPolicy
	db := storeDB(t, w.dir)
	slots := w.vault.count()

	nothingInstalled := func(stage string) {
		t.Helper()
		for _, id := range []string{attacker.root.Rec.ID, legit.root.Rec.ID} {
			if n := scalar(t, db, "SELECT count(*) FROM tenant_key WHERE id=?", id); n != 0 {
				t.Fatalf("%s: root %s pinned", stage, id[:8])
			}
		}
		if n := scalar(t, db, "SELECT count(*) FROM tenant_context WHERE active=1"); n != 0 {
			t.Fatalf("%s: tenant authority active", stage)
		}
		if p, err := LoadProfile(w.dir); err != nil || p.Enabled || p.Enrolled() {
			t.Fatalf("%s: profile changed: %v", stage, err)
		}
		if w.vault.count() != slots {
			t.Fatalf("%s: credential slots %d, want %d", stage, w.vault.count(), slots)
		}
	}

	// The forged root names the real origin; without a validated TLS
	// response from it, the system pool refuses the fixture's certificate.
	if _, err := Login(ctx, w.dir, w.vault, forged); !errors.Is(err, ErrLoginUnverified) {
		t.Fatalf("forged root without a validated TLS response: %v", err)
	}
	nothingInstalled("system pool")
	// Over validated TLS the origin returns the legitimate root.
	if _, err := LoginTLS(ctx, w.dir, w.vault, h.roots(), forged); !errors.Is(err, ErrLoginUnverified) {
		t.Fatalf("attacker root naming the origin: %v", err)
	}
	nothingInstalled("attacker root")
	// A response issued for another device is not this device's login.
	h.mu.Lock()
	h.loginDevice = machineB
	h.mu.Unlock()
	if _, err := LoginTLS(ctx, w.dir, w.vault, h.roots(), doc); !errors.Is(err, ErrLoginUnverified) {
		t.Fatalf("response bound to another device: %v", err)
	}
	h.mu.Lock()
	h.loginDevice = ""
	h.mu.Unlock()

	report, err := LoginTLS(ctx, w.dir, w.vault, h.roots(), doc)
	if err != nil || report.State != "logged_in" || report.CredentialCleanup != "complete" {
		t.Fatal("legitimate login", report, err)
	}
	if n := scalar(t, db, "SELECT count(*) FROM tenant_key WHERE id=? AND login=1", legit.root.Rec.ID); n != 1 {
		t.Fatal("verified root not pinned with login provenance")
	}
	if n := scalar(t, db, "SELECT count(*) FROM tenant_key WHERE id=?", attacker.root.Rec.ID); n != 0 {
		t.Fatal("attacker root pinned")
	}
}
