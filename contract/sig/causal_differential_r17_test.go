package sig

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// referenceStateR17 is the pre-round-17 definition: every op is authorized
// against a complete refold of its authorized ancestor history. It is cubic on
// long chains and exists only to prove the incremental causal state equal.
func referenceStateR17(k *Keyring) map[string]string {
	memo := map[string]OpStatus{}
	var decide func(string) OpStatus
	decide = func(id string) OpStatus {
		if s, ok := memo[id]; ok {
			return s
		}
		op := k.ops[id]
		for _, p := range op.Body.Parents {
			if k.ops[p] == nil || decide(p) == OpHeldParents {
				memo[id] = OpHeldParents
				return OpHeldParents
			}
		}
		seen := map[string]bool{}
		var hist []*KeyOp
		var walk func(string)
		walk = func(x string) {
			for _, p := range k.ops[x].Body.Parents {
				if seen[p] {
					continue
				}
				seen[p] = true
				if decide(p) == OpAuthorized {
					hist = append(hist, k.ops[p])
				}
				walk(p)
			}
		}
		walk(id)
		s := k.authorize(op, fold(hist, k.pinned))
		memo[id] = s
		return s
	}
	ids := make([]string, 0, len(k.ops))
	for id := range k.ops {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var all []*KeyOp
	for _, id := range ids {
		if decide(id) == OpAuthorized {
			all = append(all, k.ops[id])
		}
	}
	keys := fold(all, k.pinned)
	out := map[string]string{}
	for _, id := range ids {
		s := memo[id]
		b := k.ops[id].Body
		if s == OpAuthorized && (b.Op == record.OpDeviceRotate || b.Op == record.OpTenantKeyRotate) && keys[subjectBinding(b)] != nil && keys[subjectBinding(b)].RevokedReason == "conflict" {
			s = OpConflictLost
		}
		out["op:"+id] = string(s)
	}
	for id, key := range keys {
		out[id] = fmt.Sprint(key.Status, "/", key.RevokedReason, "/", key.RevokedSeq, "/", key.RevocationCauses, "/", key.MachineID)
	}
	return out
}

func causalSummaryR17(st *State) map[string]string {
	out := map[string]string{}
	for id, s := range st.Status {
		out["op:"+id] = string(s)
	}
	for id, key := range st.Keys {
		out[id] = fmt.Sprint(key.Status, "/", key.RevokedReason, "/", key.RevokedSeq, "/", key.RevocationCauses, "/", key.MachineID)
	}
	return out
}

// Random DAGs with merges, rotations, conflicting rotations, revocations,
// compromise cascades, rebinding attempts and unauthorized authorizers must
// produce exactly the reference statuses and keys, in any insertion order.
func TestCausalStateMatchesFullRefoldR17(t *testing.T) {
	machines := []string{mA, mB, mC, mD}
	seen := map[string]int{}
	for seed := int64(1); seed <= 150; seed++ {
		r := rand.New(rand.NewSource(seed))
		w := newWorld(t)
		pool := []ed25519.PrivateKey{w.genesis}
		for i := 0; i < 6; i++ {
			pool = append(pool, key(fmt.Sprint("diff-", seed, "-", i)))
		}
		machineOf := map[string]string{KeyID(pub(w.genesis)): mA}
		mach := func(k ed25519.PrivateKey) string {
			if m, ok := machineOf[KeyID(pub(k))]; ok && r.Intn(8) != 0 {
				return m
			}
			m := machines[r.Intn(len(machines))]
			machineOf[KeyID(pub(k))] = m
			return m
		}
		ids := []string{w.id("genesis")}
		parents := func() []string {
			ps := []string{ids[r.Intn(len(ids))]}
			if r.Intn(3) == 0 {
				if p := ids[r.Intn(len(ids))]; p != ps[0] {
					ps = append(ps, p)
				}
			}
			return ps
		}
		for n := 0; n < 24; n++ {
			name := fmt.Sprint("op-", n)
			a, b := pool[r.Intn(len(pool))], pool[r.Intn(len(pool))]
			if KeyID(pub(a)) == KeyID(pub(b)) {
				continue
			}
			switch r.Intn(5) {
			case 0, 1:
				w.add(name, b, mach(b), a, mach(a), parents()...)
			case 2, 3:
				w.rotate(name, a, b, mach(a), parents()...)
			default:
				reason := []string{"lost", "compromised", "user_request"}[r.Intn(3)]
				w.revoke(name, b, mach(b), reason, a, mach(a), parents()...)
			}
			if op := w.ops[name]; op != nil {
				w.ops[name].AdmittedSeq = int64(n + 1)
				ids = append(ids, op.Rec.ID)
			}
		}
		order := names(w)
		sort.Strings(order)
		r.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		kr := NewKeyring(w.gid())
		for _, name := range order {
			_ = kr.Add(w.ops[name])
		}
		want := referenceStateR17(kr)
		st, err := kr.StateContext(context.Background())
		parityNoError(t, err, "seed %d", seed)
		parityEqual(t, want, causalSummaryR17(st), "seed %d", seed)
		for id, v := range want {
			if id[:3] == "op:" {
				seen[v]++
			} else {
				seen["key:"+fmt.Sprint(st.Keys[id].Status, "/", st.Keys[id].RevokedReason)]++
			}
		}
		if kr.Work().HistoryEntries > 0 {
			seen["merge-or-set-fold"]++
		}
		// A clone sharing cached causal nodes must fold to the same state.
		clone, err := kr.CloneContext(context.Background())
		parityNoError(t, err)
		cst, err := clone.StateContext(context.Background())
		parityNoError(t, err)
		parityEqual(t, want, causalSummaryR17(cst), "seed %d clone", seed)
		// Incremental admission (state read after every add) must agree too.
		inc := NewKeyring(w.gid())
		for _, name := range order {
			if inc.Add(w.ops[name]) == nil {
				_, err := inc.StateContext(context.Background())
				parityNoError(t, err)
			}
		}
		ist, err := inc.StateContext(context.Background())
		parityNoError(t, err)
		parityEqual(t, want, causalSummaryR17(ist), "seed %d incremental", seed)
	}
	t.Logf("coverage %v", seen)
	for _, must := range []string{string(OpAuthorized), string(OpUnauthorized), string(OpConflictLost), "key:revoked/cascade", "key:revoked/conflict", "key:retired/", "merge-or-set-fold"} {
		parityPositive(t, seen[must], "differential corpus must exercise %s", must)
	}
}
