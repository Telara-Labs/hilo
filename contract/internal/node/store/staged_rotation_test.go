package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// rotation builds a device_rotate of previous to next, signed by both and
// authored by previous on machine.
func rotation(t *testing.T, previous, next ed25519.PrivateKey, machine, genesis string, at int64, parents ...string) SignedRecord {
	t.Helper()
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceRotate, Subject: sig.KeyRefOf(next.Public().(ed25519.PublicKey), record.RoleDevice, machine), Previous: sig.KeyID(previous.Public().(ed25519.PublicKey)), Genesis: genesis, Parents: parents}, previous.Public().(ed25519.PublicKey), machine, at, next, previous)
	if err != nil {
		t.Fatal(err)
	}
	return wire(op.Rec, op.Sigs)
}

// effectiveKey reads one device key from the effective durable key state,
// exactly as admission and the disclosure kernel see it.
func effectiveKey(t *testing.T, s *Store, key ed25519.PrivateKey) *sig.Key {
	t.Helper()
	var k *sig.Key
	if err := s.write(context.Background(), func() error {
		d, err := s.loadAuthority(context.Background())
		if err != nil {
			return err
		}
		k = d.keyState().KeyFor(sig.KeyID(key.Public().(ed25519.PublicKey)), record.RoleDevice, "")
		return nil
	}); err != nil {
		t.Fatal("authority unevaluable", err)
	}
	return k
}

func durableOp(t *testing.T, s *Store, id string) bool {
	t.Helper()
	return countRows(t, s, "SELECT count(*) FROM record WHERE id=?", id) == 1
}

// A staged device_rotate retires its previous key durably at once, across
// restart, while the successor is active only in the verification view: the
// retired key can no longer issue a control, the successor can supply one
// only through the view, and only ordinary admission activates it.
func TestStagedRotationRetiresPreviousAtOnceAndStagesActivation(t *testing.T) {
	ctx := context.Background()
	a := newWorld(t)
	b := joinDevice(t, a)
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{47}, 32))
	e := a.unsealed("staged_rotation_canary_7d21", "rot-one", 1)
	k := a.chunk(e)
	a.append(k)
	rot := rotation(t, b.key, next, joinedMachine, a.o.PinnedGenesisID, a.at+5, b.add.AdvisoryID)

	// Verification alone, the earlier staging, leaves the previous key active.
	if err := a.s.VerifyStaged(ctx, []SignedRecord{rot}); err != nil {
		t.Fatal(err)
	}
	if old := effectiveKey(t, a.s, b.key); old == nil || old.Status != sig.KeyActive {
		t.Fatal("fixture: verification changed durable key state")
	}
	if err := a.s.StageKeyOperation(ctx, rot, nil); err != nil {
		t.Fatal("staging refused", err)
	}
	for stage := range 2 {
		if durableOp(t, a.s, rot.AdvisoryID) {
			t.Fatalf("stage %d: staged rotation admitted durably", stage)
		}
		if old := effectiveKey(t, a.s, b.key); old == nil || old.Status != sig.KeyRetired {
			t.Fatalf("stage %d: previous key not retired at once: %+v", stage, old)
		}
		if nk := effectiveKey(t, a.s, next); nk != nil && nk.Status == sig.KeyActive {
			t.Fatalf("stage %d: successor activated by staging", stage)
		}
		reopenStore(t, &a.s, a.o)
	}

	// The retired key's control is refused durably, even with the view.
	byOld := deviceControl(t, b.key, joinedMachine, "rot-old", a.at+10, record.Selectors{IDs: []string{k.AdvisoryID}})
	for _, staged := range [][]SignedRecord{nil, {rot}} {
		if _, err := a.s.ApplySupplement(ctx, byOld, staged); Code(err) != "unauthorized_control" {
			t.Fatalf("retired key issued a control (view %d): %v", len(staged), err)
		}
	}
	// The successor's control is refused durably and admitted only through
	// the view.
	byNew := deviceControl(t, next, joinedMachine, "rot-new", a.at+11, record.Selectors{IDs: []string{k.AdvisoryID}})
	if _, err := a.s.ApplySupplement(ctx, byNew, nil); err == nil {
		t.Fatal("staged successor authorized a control outside the view")
	}
	if _, err := a.s.ApplySupplement(ctx, byNew, []SignedRecord{rot}); err != nil {
		t.Fatal("staged successor refused in the view", err)
	}

	// Ordinary commit activates the successor and drops the overlay row.
	if _, err := a.s.Append(ctx, rot); err != nil {
		t.Fatal("staged rotation refused at commit", err)
	}
	if countRows(t, a.s, "SELECT count(*) FROM key_restriction") != 0 {
		t.Fatal("overlay kept after commit")
	}
	if nk := effectiveKey(t, a.s, next); nk == nil || nk.Status != sig.KeyActive {
		t.Fatal("successor not active after commit")
	}
	if old := effectiveKey(t, a.s, b.key); old == nil || old.Status != sig.KeyRetired {
		t.Fatal("previous key not retired after commit")
	}
}

// A staged rotation that wins against an already committed rotation of the
// same key revokes the committed loser's subject for conflict at once and
// durably, before the winner's own subject is active anywhere but the view.
func TestStagedWinningRotationRevokesCommittedLoserAtOnce(t *testing.T) {
	ctx := context.Background()
	a := newWorld(t)
	b := joinDevice(t, a)
	loserKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{48}, 32))
	winnerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{49}, 32))
	var loser, winner SignedRecord
	for at := a.at + 1; ; at++ {
		loser = rotation(t, b.key, loserKey, joinedMachine, a.o.PinnedGenesisID, at, b.add.AdvisoryID)
		winner = rotation(t, b.key, winnerKey, joinedMachine, a.o.PinnedGenesisID, at, b.add.AdvisoryID)
		if winner.AdvisoryID < loser.AdvisoryID {
			break
		}
	}
	a.append(loser)
	if k := effectiveKey(t, a.s, loserKey); k == nil || k.Status != sig.KeyActive {
		t.Fatal("fixture: committed rotation subject not active")
	}
	if err := a.s.StageKeyOperation(ctx, winner, nil); err != nil {
		t.Fatal("staging refused", err)
	}
	for stage := range 2 {
		k := effectiveKey(t, a.s, loserKey)
		if k == nil || k.Status != sig.KeyRevoked || k.RevokedReason != "conflict" {
			t.Fatalf("stage %d: losing subject not revoked at once: %+v", stage, k)
		}
		if w := effectiveKey(t, a.s, winnerKey); w != nil && w.Status == sig.KeyActive {
			t.Fatalf("stage %d: winning subject activated by staging", stage)
		}
		reopenStore(t, &a.s, a.o)
	}
}
