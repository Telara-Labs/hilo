package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

// authorityError evaluates durable key authority exactly as the disclosure
// kernel and guarded admission do.
func authorityError(t *testing.T, s *Store) error {
	t.Helper()
	return s.write(context.Background(), func() error {
		_, err := s.loadAuthority(context.Background())
		return err
	})
}

// While the owner is blocked only by evaluation (a coverage-pending erasure,
// no privacy barrier row), ordinary admission must not durably admit a key
// operation whose parents are absent. Admitted, it would hold durable
// authority unevaluable: every later authority load refuses and nothing can
// complete it under a barrier. It is refused without a write; an authorized
// key operation is still admitted, and restart changes nothing.
func TestHeldParentsKeyOpCannotPoisonAuthorityUnderEvaluationBlock(t *testing.T) {
	ctx := context.Background()
	a := newWorld(t)
	b := joinDevice(t, a)
	aKey := a.o.PinnedGenesisID
	e := a.unsealed("held_parent_owner_canary_5a1c", "held-one", 1)
	k := a.chunk(e)
	a.append(k)
	x1 := deviceControl(t, b.key, joinedMachine, "held-x1", a.at+10, record.Selectors{IDs: []string{k.AdvisoryID}})
	if _, err := b.s.ApplyControl(ctx, x1); err != nil {
		t.Fatal(err)
	}
	carryControls(t, b.s, a.s, aKey)
	if countRows(t, a.s, "SELECT count(*) FROM erasure_pending WHERE control=?", x1.AdvisoryID) != 1 || countRows(t, a.s, "SELECT count(*) FROM privacy_barrier") != 0 {
		t.Fatal("fixture is not an evaluation-only owner block")
	}
	if held, err := a.s.guarded(ctx); err != nil || held {
		t.Fatal("fixture is guarded", held, err)
	}
	if err := authorityError(t, a.s); err != nil {
		t.Fatal("authority unevaluable before the candidate", err)
	}

	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, 32))
	orphan := a.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(other.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: aKey, Parents: []string{record.H("absent-parent")}}, a.key, a.key, other)
	epoch := countRows(t, a.s, "SELECT authority_epoch FROM meta")
	for stage := range 2 {
		_, err := a.s.Append(ctx, orphan)
		if err == nil {
			t.Fatalf("stage %d: held-parents key_op admitted under the owner block; durable authority now: %v", stage, authorityError(t, a.s))
		}
		if Code(err) != "authority_evaluation_required" {
			t.Fatalf("stage %d: refusal code %q", stage, Code(err))
		}
		if countRows(t, a.s, "SELECT count(*) FROM record WHERE id=?", orphan.AdvisoryID) != 0 || countRows(t, a.s, "SELECT authority_epoch FROM meta") != epoch {
			t.Fatalf("stage %d: refused key_op left durable authority state", stage)
		}
		if err = authorityError(t, a.s); err != nil {
			t.Fatalf("stage %d: authority poisoned: %v", stage, err)
		}
		reopenStore(t, &a.s, a.o)
	}

	// An operation authorized at its position is a valid control and is
	// admitted under the same block.
	added := a.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(other.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: aKey, Parents: []string{b.add.AdvisoryID}}, a.key, a.key, other)
	if _, err := a.s.Append(ctx, added); err != nil {
		t.Fatal("authorized key_op refused under the owner block", err)
	}
	if err := authorityError(t, a.s); err != nil {
		t.Fatal("authority unevaluable after an authorized key_op", err)
	}
	if countRows(t, a.s, "SELECT count(*) FROM erasure_pending WHERE control=?", x1.AdvisoryID) != 1 {
		t.Fatal("owner block released by a key operation")
	}
}

// A key operation admitted while its parents were absent (no owner block at
// the time) must not poison authority when a privacy barrier or projection
// hold commits before the parent arrives. Authority stays evaluable while the
// child is held, the parent that completes it is admitted under the guard,
// the completed child then takes effect, and restart preserves all of it.
func TestHeldChildParentAdmissibleUnderGuard(t *testing.T) {
	for _, guard := range []string{"privacy_barrier", "projection_hold"} {
		t.Run(guard, func(t *testing.T) {
			ctx := context.Background()
			w := newWorld(t)
			b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{43}, 32))
			c := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{44}, 32))
			genesis := w.o.PinnedGenesisID
			parent := w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(b.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{w.genesis.AdvisoryID}}, w.key, w.key, b)
			child := w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(c.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{parent.AdvisoryID}}, b, b, c)
			if _, err := w.s.Append(ctx, child); err != nil {
				t.Fatal("held child refused while the owner is not blocked", err)
			}
			if err := authorityError(t, w.s); err != nil {
				t.Fatal("held child made authority unevaluable", err)
			}
			err := w.s.write(ctx, func() error {
				if guard == "privacy_barrier" {
					return w.s.commitPrivacyBarrier(ctx, record.H("barrier-cause"), "bulk_confirmation_required", "bulk_confirmation_required")
				}
				return w.s.commitProjectionHold(ctx)
			})
			var blocked *Error
			if !isOwnerBlocked(err, &blocked) {
				t.Fatal("guard not committed", err)
			}
			if held, err := w.s.guarded(ctx); err != nil || !held {
				t.Fatal("fixture is not guarded", held, err)
			}
			if err := authorityError(t, w.s); err != nil {
				t.Fatal("authority unevaluable under the guard", err)
			}
			for stage := range 2 {
				if _, err := w.s.Append(ctx, parent); err != nil {
					t.Fatalf("stage %d: parent completing a held child refused under the guard: %v", stage, err)
				}
				if err := authorityError(t, w.s); err != nil {
					t.Fatalf("stage %d: authority poisoned: %v", stage, err)
				}
				var st *sig.State
				if err := w.s.write(ctx, func() error {
					d, err := w.s.loadAuthority(ctx)
					if err == nil {
						st = d.kr.State()
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if st.Status[child.AdvisoryID] != sig.OpAuthorized || st.Status[parent.AdvisoryID] != sig.OpAuthorized {
					t.Fatalf("stage %d: completed child not authorized: %v %v", stage, st.Status[child.AdvisoryID], st.Status[parent.AdvisoryID])
				}
				if k := st.KeyFor(sig.KeyID(c.Public().(ed25519.PublicKey)), record.RoleDevice, ""); k == nil || k.Status != sig.KeyActive {
					t.Fatalf("stage %d: completed child key not active", stage)
				}
				if countRows(t, w.s, "SELECT count(*) FROM record WHERE id=? AND sig_status='verified'", child.AdvisoryID) != 1 {
					t.Fatalf("stage %d: completed child keeps a held signature status", stage)
				}
				if held, err := w.s.guarded(ctx); err != nil || !held {
					t.Fatalf("stage %d: guard released by a key operation", stage)
				}
				reopenStore(t, &w.s, w.o)
			}
		})
	}
}

// A held revocation completed by its parent under a privacy barrier takes
// effect at once: the restriction is never lost behind the guard.
func TestHeldRevocationCompletesUnderGuard(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{45}, 32))
	c := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{46}, 32))
	genesis := w.o.PinnedGenesisID
	enroll := w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(b.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{w.genesis.AdvisoryID}}, w.key, w.key, b)
	w.append(enroll)
	parent := w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(c.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{enroll.AdvisoryID}}, w.key, w.key, c)
	revoke := w.op(record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: sig.KeyRefOf(b.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{parent.AdvisoryID}, Reason: "compromised"}, w.key, w.key)
	w.append(revoke)
	if err := w.s.write(ctx, func() error {
		return w.s.commitPrivacyBarrier(ctx, record.H("barrier-cause"), "bulk_confirmation_required", "bulk_confirmation_required")
	}); err == nil {
		t.Fatal("barrier not committed")
	}
	if _, err := w.s.Append(ctx, parent); err != nil {
		t.Fatal("parent of a held revocation refused under the guard", err)
	}
	reopenStore(t, &w.s, w.o)
	var st *sig.State
	if err := w.s.write(ctx, func() error {
		d, err := w.s.loadAuthority(ctx)
		if err == nil {
			st = d.kr.State()
		}
		return err
	}); err != nil {
		t.Fatal("authority unevaluable", err)
	}
	if k := st.KeyFor(sig.KeyID(b.Public().(ed25519.PublicKey)), record.RoleDevice, ""); k == nil || k.Status != sig.KeyRevoked {
		t.Fatal("completed revocation did not take effect under the guard")
	}
}
