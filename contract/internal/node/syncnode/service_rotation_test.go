package syncnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// A TLS-pinned initial service root authorizes its causal rotation from the
// real control stream. The same round verifies pushed records' receipts under
// the new signer, and a restarted worker reuses that persisted authority.
func TestHostedServiceKeyRotationVerifiesNewReceipts(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.installKey()
	h := w.hosted
	auth := newTenantAuthority(t, 61, h.tenant, h.user)
	policy, pol := auth.policy(1, "rotation-rule")
	const remote = "github.com/acme/rotation"
	repo, _ := record.RepoID(remote)
	h.mu.Lock()
	h.grant.Repos = []string{repo}
	h.mu.Unlock()
	if _, err := LoginTLS(ctx, w.dir, w.vault, h.roots(), w.loginDocument(h, auth, pol)); err != nil {
		t.Fatal(err)
	}
	w.session(1, remote, policy.ID)
	p, err := LoadProfile(w.dir)
	if err != nil {
		t.Fatal(err)
	}
	old := h.tsk
	root := serviceKeyOp(t, old, h.tenant)
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{92}, 32))
	rot, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKeyRotate, Subject: sig.KeyRefOf(next.Public().(ed25519.PublicKey), record.RoleService, ""), Previous: sig.KeyID(old.Public().(ed25519.PublicKey)), Genesis: h.tenant, Parents: []string{root.ID}}, old.Public().(ed25519.PublicKey), "", w.at+1, next, old)
	if err != nil {
		t.Fatal(err)
	}
	rotation := store.SignedRecord{HeaderJCS: rot.Rec.HeaderJCS, BodyJCS: rot.Rec.BodyJCS, Sigs: rot.Sigs, AdvisoryID: rot.Rec.ID}
	if err := w.st.VerifyStaged(ctx, []store.SignedRecord{rotation}); err != nil {
		t.Fatal("service rotation staged verification", err)
	}
	before, err := w.st.ServiceKeyState(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if before.KeyFor(sig.KeyID(next.Public().(ed25519.PublicKey)), record.RoleService, h.tenant) != nil {
		t.Fatal("staged service key became live")
	}
	hc := h.addControl(envelopeOf(rot.Rec, rot.Sigs))
	h.mu.Lock()
	h.tsk = next
	h.mu.Unlock()
	wk := w.worker()
	w.selectRepo(wk, repo)
	if err := wk.Round(ctx); err != nil {
		t.Fatal("rotation and new-signer receipt", err)
	}
	if c := cursorsOf(t, wk, p); c.Ctl != hc {
		t.Fatal("rotation not enforced", c)
	}
	if n := len(h.imports()); n != 1 {
		t.Fatal("new-key receipt not exercised", n)
	}
	state, err := w.st.ServiceKeyState(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if k := state.KeyFor(sig.KeyID(next.Public().(ed25519.PublicKey)), record.RoleService, h.tenant); k == nil || k.Status != sig.KeyActive {
		t.Fatal("successor missing", k)
	}
	if k := state.KeyFor(sig.KeyID(old.Public().(ed25519.PublicKey)), record.RoleService, h.tenant); k == nil || k.Status != sig.KeyRetired {
		t.Fatal("prior key not retired", k)
	}
	// A key from another issuer role must not extend the service chain.
	wrong, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpTenantKeyRotate, Subject: sig.KeyRefOf(old.Public().(ed25519.PublicKey), record.RoleService, ""), Previous: sig.KeyID(next.Public().(ed25519.PublicKey)), Genesis: h.tenant, Parents: []string{rot.Rec.ID}}, auth.key.Public().(ed25519.PublicKey), "", w.at+2, old, auth.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.st.OfferTenantKeyOperation(ctx, store.SignedRecord{HeaderJCS: wrong.Rec.HeaderJCS, BodyJCS: wrong.Rec.BodyJCS, Sigs: wrong.Sigs, AdvisoryID: wrong.Rec.ID}); err == nil {
		t.Fatal("policy key rotated service authority")
	}
	_ = wk.state.Close()
	wk = w.worker()
	if err := wk.Round(ctx); err != nil {
		t.Fatal("restart with rotated authority", err)
	}
}
