package syncnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// stagingWithoutKeyRestriction is the node store with key staging reduced to
// verification alone, as before the key-restriction overlay. It is the
// negative control.
type stagingWithoutKeyRestriction struct{ *store.Store }

func (s stagingWithoutKeyRestriction) StageKeyOperation(ctx context.Context, in store.SignedRecord, staged []store.SignedRecord) error {
	return s.VerifyStaged(ctx, append(append([]store.SignedRecord(nil), staged...), in))
}

func deviceKeyStatus(t *testing.T, st *store.Store, key ed25519.PrivateKey) string {
	t.Helper()
	s, err := st.DeviceKeyStatus(context.Background(), sig.KeyID(key.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A device_rotate between a coverage-pending erasure and its supplement is
// split: retirement of the previous key is a restriction and applies durably
// at once, across restart, while the successor's activation is staged in the
// verification view. The successor's supplement completes c1 through the
// view; only then is the rotation committed and the successor active.
func TestX2RotationRetiresAtOnceAndStagesActivation(t *testing.T) {
	x := newX2Pair(t)
	a, b, h := x.a, x.b, x.h
	wa := a.worker()
	sk := x2SessionKey(t)
	k, _, e := a.chunk(sk, "x2_rotation_staged_canary_3be9", "x2-rot1")
	b.at = a.at + 10
	c1 := erasureBy(t, b.key, b.machine, "x2rot-c1", b.at, record.Selectors{IDs: []string{k.ID}})
	hc1 := h.addControl(c1)

	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, 32))
	b.at++
	rot, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceRotate, Subject: sig.KeyRefOf(next.Public().(ed25519.PublicKey), record.RoleDevice, b.machine), Previous: sig.KeyID(b.key.Public().(ed25519.PublicKey)), Genesis: a.genesis, Parents: []string{a.keyring[len(a.keyring)-1].AdvisoryID}}, b.key.Public().(ed25519.PublicKey), b.machine, b.at, next, b.key)
	if err != nil {
		t.Fatal(err)
	}
	hr := h.addControl(envelopeOf(rot.Rec, rot.Sigs))
	for i := 0; i < 2; i++ {
		x2Round(t, wa, ErrControlBlocked)
		x.heldBelow(t, wa, "rotation page", 0, hc1)
		if n := count(t, wa, "SELECT count(*) FROM ctl_pending WHERE hseq=? AND reason='staged'", hr); n != 1 {
			t.Fatal("rotation not staged")
		}
		if inKeyring(t, a.st, rot.Rec.ID) {
			t.Fatal("rotation committed while c1 pending")
		}
		if s := deviceKeyStatus(t, a.st, b.key); s != string(sig.KeyRetired) {
			t.Fatalf("previous key not retired at once: %q", s)
		}
		if s := deviceKeyStatus(t, a.st, next); s != "" {
			t.Fatalf("successor durable while staged: %q", s)
		}
		wa = a.restart(wa)
	}

	c2 := erasureBy(t, next, b.machine, "x2rot-c2", b.at+1, record.Selectors{Events: []record.EventSelector{{Owner: a.genesis, SessionKey: sk, EventID: e}}})
	hc2 := h.addControl(c2)
	x2Round(t, wa, nil)
	if c := cursorsOf(t, wa, x.pa); c.Ctl != hc2 || c.BarrierHSeq != 0 {
		t.Fatalf("successor's supplement did not recover: %+v", c)
	}
	if ack := x.lastAck(t); ack.CtlEnforcedThrough != hc2 {
		t.Fatalf("A final ack %+v", ack)
	}
	if !inKeyring(t, a.st, rot.Rec.ID) {
		t.Fatal("staged rotation not committed after c1 completed")
	}
	if s := deviceKeyStatus(t, a.st, next); s != string(sig.KeyActive) {
		t.Fatalf("successor not active after commit: %q", s)
	}
	if s := deviceKeyStatus(t, a.st, b.key); s != string(sig.KeyRetired) {
		t.Fatalf("previous key not retired after commit: %q", s)
	}
	if state, body := entryState(t, a.st, k.ID); state != "invalidated" || body {
		t.Fatalf("chunk not purged: %s", state)
	}
}

// Negative control: with key staging reduced to verification, the rotation is
// staged whole and the previous key stays active while c1 is pending. The
// retirement assertion above therefore detects the loss of the overlay.
func TestX2RotationWithoutKeyRestrictionLeavesPreviousActive(t *testing.T) {
	x := newX2Pair(t)
	a, b, h := x.a, x.b, x.h
	sk := x2SessionKey(t)
	k, _, _ := a.chunk(sk, "x2_rotation_negative_canary_90a4", "x2-rotn")
	b.at = a.at + 10
	hc1 := h.addControl(erasureBy(t, b.key, b.machine, "x2rotn-c1", b.at, record.Selectors{IDs: []string{k.ID}}))
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{14}, 32))
	b.at++
	rot, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceRotate, Subject: sig.KeyRefOf(next.Public().(ed25519.PublicKey), record.RoleDevice, b.machine), Previous: sig.KeyID(b.key.Public().(ed25519.PublicKey)), Genesis: a.genesis, Parents: []string{a.keyring[len(a.keyring)-1].AdvisoryID}}, b.key.Public().(ed25519.PublicKey), b.machine, b.at, next, b.key)
	if err != nil {
		t.Fatal(err)
	}
	hr := h.addControl(envelopeOf(rot.Rec, rot.Sigs))
	wk, err := NewWorker(context.Background(), Config{Dir: a.dir, Store: stagingWithoutKeyRestriction{a.st}, Signer: a.keys, Vault: a.vault, TLSRoots: h.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MaxRetry: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wk.state.Close() })
	x2Round(t, wk, ErrControlBlocked)
	x.heldBelow(t, wk, "rotation page", 0, hc1)
	if n := count(t, wk, "SELECT count(*) FROM ctl_pending WHERE hseq=? AND reason='staged'", hr); n != 1 {
		t.Fatal("rotation not staged")
	}
	if s := deviceKeyStatus(t, a.st, b.key); s != string(sig.KeyActive) {
		t.Fatalf("negative control retired the previous key without the overlay (%q); the positive test proves nothing", s)
	}
}
