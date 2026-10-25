package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
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
