package store

import (
	"context"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

func TestTransferredMetadataKeepsPolicyProvenance(t *testing.T) {
	for _, mode := range []string{"current", "unknown", "other-tenant", "logout", "current-denial"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			w := newWorld(t)
			recv := joinDevice(t, w)
			sign := installTenant(t, w, "tenant-provenance")
			old := sign(1, pushPolicy(nil))
			w.append(old)
			chunk, source := governedSession(w, old.AdvisoryID, "provenance fixture")
			w.append(chunk)
			w.append(source)
			current := sign(2, pushPolicy(nil))
			w.append(current)
			ids := []string{source.AdvisoryID, chunk.AdvisoryID}
			e, sel := registerExport(t, w.s, w.o, 55, ids, worldSigner{w.key}, []byte("sealed"))
			defer e.lock.Close()
			if len(sel.Data) != 1 {
				t.Fatal("old-source metadata export", sel.Excluded)
			}
			if err := e.publish(w.s, ids); err != nil {
				t.Fatal(err)
			}
			variant, err := record.Parse(sel.Data[0].HeaderJCS, sel.Data[0].BodyJCS, sel.Data[0].AdvisoryID)
			if err != nil || variant.Header.Pol != old.AdvisoryID {
				t.Fatal("source provenance rewritten", err)
			}
			rw := &world{t: t, s: recv.s, o: recv.o}
			installTenant(t, rw, "tenant-provenance")
			for _, p := range []SignedRecord{old, current} {
				if _, err := recv.s.Append(ctx, p); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "unknown":
				h := variant.Header
				h.Pol = strings.Repeat("e", 64)
				body := *variant.Body.(*record.SessionMetaBody)
				body.Salt = ""
				changed, err := record.Build(h, &body)
				if err != nil {
					t.Fatal(err)
				}
				signature, err := sig.SignRecord(w.key, changed.ID)
				if err != nil {
					t.Fatal(err)
				}
				sel.Data[0] = wire(changed, []record.Signature{signature})
			case "other-tenant", "logout":
				if err := recv.s.LogoutTenant(ctx); err != nil && Code(err) != "physical_pending" {
					t.Fatal(err)
				}
				if mode == "other-tenant" {
					otherSign := installTenant(t, rw, "other-tenant")
					if _, err := recv.s.Append(ctx, otherSign(1, pushPolicy(nil))); err != nil {
						t.Fatal(err)
					}
				} else {
					relogin(t, rw, "tenant-provenance")
					if _, err := recv.s.Append(ctx, sign(3, pushPolicy(nil))); err != nil {
						t.Fatal(err)
					}
				}
			case "current-denial":
				denied := sign(3, pushPolicy(func(b *record.PolicyBody) { b.Push.MaxProfile = record.ProfileLocal }))
				if _, err := recv.s.Append(ctx, denied); err != nil {
					t.Fatal(err)
				}
			}
			got, err := recv.s.ImportBundle(ctx, BundleImport{LocalKeyID: recv.KeyID(), Keyring: sel.Keyring, Data: sel.Data})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "current" {
				if got.Data != 1 || len(got.Excluded) != 0 {
					t.Fatal("known same-tenant provenance denied by head advance", got)
				}
				// Ordinary new local capture still has to name the current head.
				stale := repoProofFixture(t, w, old.AdvisoryID, "github.com/acme/widgets")
				if _, err := w.s.Append(ctx, stale); Code(err) != "policy_violation" {
					t.Fatal("stale ordinary capture accepted", err)
				}
			} else if got.Data != 0 || len(got.Excluded) != 1 || got.Excluded[0].Reason != ExcludedPolicy {
				t.Fatal("ineligible provenance/current authority accepted", mode, got)
			}
		})
	}
}
