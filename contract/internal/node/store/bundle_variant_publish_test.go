package store

import (
	"bytes"
	"os"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
)

// TestBundleVariantPublicationRevalidatesFrozenBytes pauses a governed
// session-metadata export after its signed variant is sealed under policy P1,
// then installs P2, which keeps the repository allowance but adds a
// redaction shape matching the variant's MachineOS. A variant built now
// satisfies P2 after redaction, but the sealed one does not: publication is
// invalidated, staging destroyed and nothing published. An export rebuilt
// under P2 carries the redacted variant and publishes. A policy change that
// leaves the variant's bytes and authorization unchanged still publishes.
func TestBundleVariantPublicationRevalidatesFrozenBytes(t *testing.T) {
	w := newWorld(t)
	sign := installTenant(t, w, "tenant-variant-publish")
	p1 := sign(1, pushPolicy(nil))
	w.append(p1)
	chunk, session := governedSession(w, p1.AdvisoryID, "variant_publish_canary_3e9b")
	w.append(chunk)
	w.append(session)
	ids := []string{session.AdvisoryID}
	signer := worldSigner{w.key}
	machineOS := []byte(`"machine_os":"darwin"`)

	// Negative control: an unrelated policy change leaves the sealed
	// variant byte-identical and permitted, so it still publishes.
	same, sel := registerExport(t, w.s, w.o, 9, ids, signer, []byte("sealed"))
	if len(sel.Data) != 1 || !bytes.Contains(sel.Data[0].BodyJCS, machineOS) {
		t.Fatal("variant under P1", len(sel.Data), sel.Excluded)
	}
	if countRows(t, w.s, "SELECT count(*) FROM bundle_export_variant WHERE export=? AND id=?", same.token, sel.Data[0].AdvisoryID) != 1 {
		t.Fatal("sealed variant bytes not registered")
	}
	w.append(sign(2, pushPolicy(func(b *record.PolicyBody) { b.NotAfter += 60000 })))
	if err := same.publish(w.s, ids); err != nil || !exists(t, same.final) {
		t.Fatal("unchanged variant did not publish after an unrelated policy change", err)
	}
	same.lock.Close()

	// The race: sealed under the current redaction, tightened, published.
	paused, sel := registerExport(t, w.s, w.o, 10, ids, signer, []byte("sealed"))
	if len(sel.Data) != 1 || !bytes.Contains(sel.Data[0].BodyJCS, machineOS) {
		t.Fatal("variant before tightening", len(sel.Data), sel.Excluded)
	}
	w.append(sign(3, pushPolicy(func(b *record.PolicyBody) {
		b.NotAfter += 60000
		b.Redaction.Shapes = []record.Shape{{Name: "machine-os", RE2: "darwin"}}
	})))
	if err := paused.publish(w.s, ids); Code(err) != "bundle_invalidated" {
		t.Fatal("sealed variant published after its redaction tightened", err)
	}
	if exists(t, paused.final) || exists(t, paused.staging) {
		t.Fatal("invalidated variant export left a copy")
	}
	if countRows(t, w.s, "SELECT count(*) FROM bundle_export_variant") != 0 || countRows(t, w.s, "SELECT count(*) FROM bundle_export") != 0 {
		t.Fatal("invalidated export left its registration")
	}
	paused.lock.Close()

	// Rebuilt under the tightened policy: the redacted variant publishes.
	rebuilt, sel := registerExport(t, w.s, w.o, 11, ids, signer, []byte("sealed"))
	if len(sel.Data) != 1 || bytes.Contains(sel.Data[0].BodyJCS, []byte("darwin")) {
		t.Fatal("variant rebuilt under the tightened policy", len(sel.Data), sel.Excluded)
	}
	if err := rebuilt.publish(w.s, ids); err != nil || !exists(t, rebuilt.final) {
		t.Fatal("rebuilt variant did not publish", err)
	}
	rebuilt.lock.Close()
	if _, err := os.Stat(rebuilt.staging); !os.IsNotExist(err) {
		t.Fatal("published export left staging", err)
	}
}
