package sig

import (
	"context"
	"errors"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

func TestPublicKeySnapshotsDetachEveryAuthorityMember(t *testing.T) {
	w := newWorld(t)
	child := key("snapshot-child")
	w.add("child", child, mB, w.genesis, mA, w.id("genesis"))
	w.ops["child"].Receipt = &record.Receipt{Tenant: "snapshot-tenant"}
	kr := NewKeyring(w.gid())
	parityNoError(t, kr.Add(w.ops["genesis"]))
	parityNoError(t, kr.Add(w.ops["child"]))
	for _, legacy := range []bool{false, true} {
		var st *State
		if legacy {
			st = kr.State()
			parityNoError(t, st.Err())
		} else {
			var err error
			st, err = kr.StateContext(context.Background())
			parityNoError(t, err)
		}
		st.Key(w.gid()).Pub[0] ^= 255
		st.Key(w.gid()).RevocationCauses = []string{"forged"}
		op := st.Ops[w.id("child")]
		op.Body.Parents[0] = "forged"
		op.Body.Subject.Pub = "forged"
		op.Sigs[0].Value = "forged"
		op.Receipt.Tenant = "forged"
		op.Rec.HeaderJCS[0] ^= 255
		op.Rec.BodyJCS[0] ^= 255
		op.Rec.Header.Author.KeyID = "forged"
		st.Status[w.id("genesis")] = OpInvalid
		st.Keys = map[string]*Key{}
		fresh, err := kr.StateContext(context.Background())
		parityNoError(t, err)
		parityEqual(t, pub(w.genesis), fresh.Key(w.gid()).Pub)
		parityEqual(t, OpAuthorized, fresh.Status[w.id("genesis")])
		parityEqual(t, "snapshot-tenant", fresh.Ops[w.id("child")].Receipt.Tenant)
		parityEmpty(t, fresh.Key(w.gid()).RevocationCauses)
		parityEqual(t, w.ops["child"].Body.Parents, fresh.Ops[w.id("child")].Body.Parents)
		parityEqual(t, w.ops["child"].Body.Subject.Pub, fresh.Ops[w.id("child")].Body.Subject.Pub)
		parityEqual(t, w.ops["child"].Sigs, fresh.Ops[w.id("child")].Sigs)
		parityEqual(t, w.ops["child"].Rec.HeaderJCS, fresh.Ops[w.id("child")].Rec.HeaderJCS)
		parityEqual(t, w.ops["child"].Rec.BodyJCS, fresh.Ops[w.id("child")].Rec.BodyJCS)
	}
}

func TestLegacyKeyRefusalIsNonNilAndNeverAuthorizes(t *testing.T) {
	kr := NewKeyring("")
	for n := 0; n < 4097; n++ {
		kr.ops[string(rune(n))] = nil
	}
	st := kr.State()
	if st == nil {
		t.Fatal("legacy refusal returned nil")
	}
	if !errors.Is(st.Err(), ErrHistoryBudget) {
		t.Fatal("missing explicit refusal", st.Err())
	}
	parityEmpty(t, st.Keys)
	parityEmpty(t, st.Status)
	parityEmpty(t, st.Ops)
	parityNil(t, st.Key("unknown"))
	parityNil(t, st.KeyFor("unknown", record.RoleDevice, ""))
	parityNil(t, kr.cached)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewKeyring("").StateContext(ctx)
	parityErrorIs(t, err, context.Canceled)
}

func TestKeySnapshotCopyIsPrechargedWithoutPoisoningCache(t *testing.T) {
	kr := NewKeyring("")
	cached := &State{Keys: map[string]*Key{}, Status: map[string]OpStatus{}, Ops: map[string]*KeyOp{"large": {Rec: &record.Record{HeaderJCS: make([]byte, maxHistoryBytes+1)}}}}
	kr.cached = cached
	_, err := kr.StateContext(context.Background())
	parityErrorIs(t, err, ErrHistoryBudget)
	paritySame(t, cached, kr.cached)
	delete(cached.Ops, "large")
	snapshot, err := kr.StateContext(context.Background())
	parityNoError(t, err)
	snapshot.Keys["forged"] = &Key{}
	parityEmpty(t, cached.Keys)
}

// Cancel only after two private tree puts, independent of map traversal order.
// Waiting for direct parents also exercises charges for ancestors published by
// this same invocation when the fixture starts with a cold causal cache.
type cancelCausalRebuild struct {
	context.Context
	cancel              context.CancelFunc
	keyring             *Keyring
	target              string
	parents             []string
	ready               bool
	baseline, lastBytes int
	puts                int
}

func (c *cancelCausalRebuild) Err() error {
	if err := c.Context.Err(); err != nil {
		return err
	}
	if !c.ready {
		for _, id := range c.parents {
			if c.keyring.causal[id] == nil {
				return nil
			}
		}
		c.ready = true
		c.baseline = c.keyring.causalBytes
		c.lastBytes = c.baseline
	}
	if c.keyring.causal[c.target] == nil && c.keyring.causalBytes > c.lastBytes {
		c.puts++
		c.lastBytes = c.keyring.causalBytes
	}
	if c.puts >= 2 {
		c.cancel()
		return c.Context.Err()
	}
	return nil
}

func TestAbandonedCausalRebuildChargesAreTransactional(t *testing.T) {
	for _, rebuild := range []string{"merge", "revoke"} {
		for _, warm := range []bool{false, true} {
			name := rebuild + "/cold"
			if warm {
				name = rebuild + "/warm"
			}
			t.Run(name, func(t *testing.T) {
				w := newWorld(t)
				b, c := key("rollback-b"), key("rollback-c")
				w.add("b", b, mB, w.genesis, mA, w.id("genesis"))
				parent := w.id("genesis")
				if rebuild == "revoke" {
					parent = w.id("b")
				}
				w.add("c", c, mC, w.genesis, mA, parent)
				kr := NewKeyring(w.gid())
				for _, name := range []string{"genesis", "b", "c"} {
					parityNoError(t, kr.Add(w.ops[name]))
				}
				if warm {
					_, err := kr.StateContext(context.Background())
					parityNoError(t, err)
				}
				if rebuild == "merge" {
					w.add("target", key("rollback-d"), mD, w.genesis, mA, w.id("b"), w.id("c"))
				} else {
					w.revoke("target", b, mB, "lost", w.genesis, mA, w.id("c"))
				}
				target := w.ops["target"]
				parityNoError(t, kr.Add(target))
				retained := -1
				for attempt := 0; attempt < 128; attempt++ {
					base, cancel := context.WithCancel(context.Background())
					ctx := &cancelCausalRebuild{Context: base, cancel: cancel, keyring: kr, target: target.Rec.ID, parents: target.Body.Parents}
					st, err := kr.StateContext(ctx)
					cancel()
					parityErrorIs(t, err, context.Canceled)
					parityNil(t, st)
					parityEqual(t, 2, ctx.puts)
					parityPositive(t, ctx.baseline)
					parityEqual(t, ctx.baseline, kr.causalBytes)
					parityNil(t, kr.causal[target.Rec.ID])
					parityNil(t, kr.cached)
					parityLen(t, kr.causal, 3)
					if retained < 0 {
						retained = ctx.baseline
					}
					parityEqual(t, retained, kr.causalBytes)
				}
				clone, err := kr.CloneContext(context.Background())
				parityNoError(t, err)
				parityEqual(t, retained, clone.causalBytes)
				fresh := NewKeyring(w.gid())
				for _, name := range []string{"genesis", "b", "c", "target"} {
					parityNoError(t, fresh.Add(w.ops[name]))
				}
				want, err := fresh.StateContext(context.Background())
				parityNoError(t, err)
				parityEqual(t, OpAuthorized, want.Status[target.Rec.ID])
				for _, candidate := range []*Keyring{clone, kr} {
					got, err := candidate.StateContext(context.Background())
					parityNoError(t, err)
					parityEqual(t, causalSummaryR17(want), causalSummaryR17(got))
					parityLen(t, candidate.causal, 4)
					charged := candidate.causalBytes
					_, err = candidate.StateContext(context.Background())
					parityNoError(t, err)
					parityEqual(t, charged, candidate.causalBytes)
				}
			})
		}
	}
}
