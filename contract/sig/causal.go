package sig

import (
	"context"
	"errors"
	"sort"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// Complex DAG histories and conflict cascades have a fixed work limit. Linear
// enrollment uses persistent causal state and does not spend ancestor-pair work.
var ErrHistoryBudget = errors.New("key_history_budget_exceeded")

const maxHistoryWork = 2_000_000
const maxHistoryBytes = 32 << 20

type HistoryWork struct{ Authorizations, HistoryEntries, FoldSteps int }

func (k *Keyring) Work() HistoryWork { return k.work }

type historyContext struct {
	context.Context
	steps int
	bytes int
}

func reserveHistory(ctx context.Context, n int) error {
	if b, ok := ctx.(*historyContext); ok {
		if n < 0 || n > maxHistoryBytes-b.bytes {
			b.bytes = maxHistoryBytes + 1
			return ErrHistoryBudget
		}
		b.bytes += n
	}
	return ctx.Err()
}
func (k *Keyring) putCausal(ctx context.Context, t *keyTree, id string, key *Key) (*keyTree, error) {
	size := 64 * (2*height(t) + 4)
	if size > maxHistoryBytes-k.causalBytes {
		return nil, ErrHistoryBudget
	}
	if err := reserveHistory(ctx, size); err != nil {
		return nil, err
	}
	k.causalBytes += size
	return treePut(t, id, key), nil
}
func (c *historyContext) Err() error {
	if err := c.Context.Err(); err != nil {
		return err
	}
	c.steps++
	if c.steps > maxHistoryWork || c.bytes > maxHistoryBytes {
		return ErrHistoryBudget
	}
	return nil
}

type causalNode struct {
	keys   *keyTree
	status OpStatus
}

// Immutable AVL nodes share all unaffected bindings between causal versions.
// Unlike copying a key map per ancestor, retained linear history uses O(n log n)
// storage. Lookups are bounded even for adversarial binding insertion order.
type keyTree struct {
	id          string
	key         *Key
	left, right *keyTree
	height      int
}

func height(t *keyTree) int {
	if t == nil {
		return 0
	}
	return t.height
}
func treeNode(id string, key *Key, l, r *keyTree) *keyTree {
	return &keyTree{id: id, key: key, left: l, right: r, height: 1 + max(height(l), height(r))}
}
func treeGet(t *keyTree, id string) *Key {
	for t != nil {
		if id == t.id {
			return t.key
		}
		if id < t.id {
			t = t.left
		} else {
			t = t.right
		}
	}
	return nil
}
func treePut(t *keyTree, id string, key *Key) *keyTree {
	if t == nil {
		return treeNode(id, key, nil, nil)
	}
	l, r := t.left, t.right
	if id < t.id {
		l = treePut(l, id, key)
	} else if id > t.id {
		r = treePut(r, id, key)
	} else {
		return treeNode(id, key, l, r)
	}
	if height(l) > height(r)+1 {
		if height(l.left) < height(l.right) {
			x := l.right
			l = treeNode(x.id, x.key, treeNode(l.id, l.key, l.left, x.left), x.right)
		}
		return treeNode(l.id, l.key, l.left, treeNode(t.id, t.key, l.right, r))
	}
	if height(r) > height(l)+1 {
		if height(r.right) < height(r.left) {
			x := r.left
			r = treeNode(x.id, x.key, x.left, treeNode(r.id, r.key, x.right, r.right))
		}
		return treeNode(r.id, r.key, treeNode(t.id, t.key, l, r.left), r.right)
	}
	return treeNode(t.id, t.key, l, r)
}

// StateContext returns a read-only folded snapshot. Each complete causal op is
// authorized once until a duplicate changes authenticated receiver facts. New
// children cannot change an existing complete History(op).
func (k *Keyring) stateContext(ctx context.Context) (*State, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if k.cached != nil {
		return k.cached, nil
	}
	if len(k.ops) > 4096 {
		return nil, ErrHistoryBudget
	}
	budget := &historyContext{Context: ctx}
	if k.causal == nil {
		k.causal = map[string]*causalNode{}
	}
	active := map[string]bool{}
	var decide func(string) (*causalNode, error)
	decide = func(id string) (*causalNode, error) {
		if err := budget.Err(); err != nil {
			return nil, err
		}
		if n := k.causal[id]; n != nil {
			return n, nil
		}
		op := k.ops[id]
		if op == nil || active[id] {
			return nil, nil
		}
		active[id] = true
		defer delete(active, id)
		var parent *causalNode
		for _, p := range op.Body.Parents {
			n, err := decide(p)
			if err != nil {
				return nil, err
			}
			if n == nil {
				return nil, nil
			}
			parent = n
		}
		// Ancestors are already published and retain their charges. This node's
		// tree stays private until complete, so cancellation or refusal must not
		// charge an abandoned rebuild against every future evaluation or clone.
		retainedBytes := k.causalBytes
		published := false
		defer func() {
			if !published {
				k.causalBytes = retainedBytes
			}
		}()
		var hist *keyTree
		if len(op.Body.Parents) == 1 {
			hist = parent.keys
		} else if len(op.Body.Parents) > 1 {
			var ops []*KeyOp
			seen := map[string]bool{}
			var collect func(string) error
			collect = func(id string) error {
				if err := budget.Err(); err != nil {
					return err
				}
				if seen[id] {
					return nil
				}
				seen[id] = true
				k.work.HistoryEntries++
				if k.causal[id].status == OpAuthorized {
					ops = append(ops, k.ops[id])
				}
				for _, p := range k.ops[id].Body.Parents {
					if err := collect(p); err != nil {
						return err
					}
				}
				return nil
			}
			for _, p := range op.Body.Parents {
				if err := collect(p); err != nil {
					return nil, err
				}
			}
			keys, err := foldContext(budget, ops, k.pinned)
			if err != nil {
				return nil, err
			}
			for id, key := range keys {
				if err := budget.Err(); err != nil {
					return nil, err
				}
				hist, err = k.putCausal(budget, hist, id, key)
				if err != nil {
					return nil, err
				}
			}
		}
		status := k.authorizeLookup(op, func(id string) *Key { return treeGet(hist, id) })
		k.work.Authorizations++
		keys := hist
		if status == OpAuthorized {
			binding := subjectBinding(op.Body)
			switch op.Body.Op {
			case record.OpGenesis, record.OpDeviceAdd, record.OpTenantKey:
				if treeGet(hist, binding) == nil {
					pub, _ := DecodePub(op.Body.Subject.Pub)
					key := &Key{KeyID: op.Body.Subject.KeyID, Pub: pub, Role: op.Body.Subject.Role, MachineID: op.Body.Subject.MachineID, Status: KeyActive}
					if key.Role == record.RoleDevice {
						key.Genesis = genesisOf(op.Body)
					} else {
						key.Tenant = genesisOf(op.Body)
					}
					var err error
					keys, err = k.putCausal(budget, hist, binding, key)
					if err != nil {
						return nil, err
					}
				}
			default:
				// Rotation/conflict/revocation are set-based. Reuse authorization decisions,
				// but budget the uncommon non-monotone fold before allocating its history.
				var ops []*KeyOp
				seen := map[string]bool{}
				var collect func(string) error
				collect = func(id string) error {
					if err := budget.Err(); err != nil {
						return err
					}
					if seen[id] {
						return nil
					}
					seen[id] = true
					k.work.HistoryEntries++
					if id == op.Rec.ID || k.causal[id].status == OpAuthorized {
						ops = append(ops, k.ops[id])
					}
					for _, p := range k.ops[id].Body.Parents {
						if err := collect(p); err != nil {
							return err
						}
					}
					return nil
				}
				if err := collect(id); err != nil {
					return nil, err
				}
				folded, err := foldContext(budget, ops, k.pinned)
				if err != nil {
					return nil, err
				}
				keys = nil
				for id, key := range folded {
					if err := budget.Err(); err != nil {
						return nil, err
					}
					keys, err = k.putCausal(budget, keys, id, key)
					if err != nil {
						return nil, err
					}
				}
			}
		}
		n := &causalNode{keys: keys, status: status}
		k.causal[id] = n
		published = true
		return n, nil
	}
	ids := make([]string, 0, len(k.ops))
	for id := range k.ops {
		if err := budget.Err(); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	st := &State{Genesis: k.pinned, Keys: map[string]*Key{}, Status: map[string]OpStatus{}, Ops: map[string]*KeyOp{}}
	var all []*KeyOp
	for _, id := range ids {
		n, err := decide(id)
		if err != nil {
			return nil, err
		}
		st.Status[id] = OpHeldParents
		if n != nil {
			st.Status[id] = n.status
			if n.status == OpAuthorized {
				all = append(all, k.ops[id])
			}
		}
		if err := budget.Err(); err != nil {
			return nil, err
		}
		st.Ops[id] = cloneOp(k.ops[id])
	}
	keys, err := foldContext(budget, all, k.pinned)
	if err != nil {
		return nil, err
	}
	st.Keys = keys
	for _, id := range ids {
		if err := budget.Err(); err != nil {
			return nil, err
		}
		b := k.ops[id].Body
		if st.Status[id] == OpAuthorized && (b.Op == record.OpDeviceRotate || b.Op == record.OpTenantKeyRotate) && st.Keys[subjectBinding(b)] != nil && st.Keys[subjectBinding(b)].RevokedReason == "conflict" {
			st.Status[id] = OpConflictLost
		}
	}
	k.work.FoldSteps += budget.steps
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	k.cached = st
	return st, nil
}

// CloneContext detaches mutable operations and folded keys. Causal tree nodes
// are immutable and can safely be shared by independent request keyrings.
func (k *Keyring) CloneContext(ctx context.Context) (*Keyring, error) {
	out := NewKeyring(k.pinned)
	out.work = k.work
	out.causalBytes = k.causalBytes
	out.causal = map[string]*causalNode{}
	for id, op := range k.ops {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out.ops[id] = cloneOp(op)
	}
	for id, n := range k.causal {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out.causal[id] = n
	}
	// Rebuild the final snapshot from the immutable causal cache on demand.
	return out, ctx.Err()
}

// Err reports a refused legacy snapshot. A failed snapshot never carries keys or
// operation authorization. Security consumers must propagate this error before
// committing authority, records or acknowledgements.
func (s *State) Err() error {
	if s == nil {
		return ErrHistoryBudget
	}
	return s.err
}

// StateContext returns a complete detached snapshot or an explicit error. Public
// maps, keys, operation records, bodies and signatures never alias the cached
// fold or causal trees. A caller may inspect or restrict its own snapshot.
func (k *Keyring) StateContext(ctx context.Context) (*State, error) {
	st, err := k.stateContext(ctx)
	if err != nil {
		return nil, err
	}
	return detachState(ctx, st)
}

// snapshotHistory accounts the bounded copy separately from the cached fold.
// Cancellation checks use Done so an inspection copy does not spend another
// full history fold's context checkpoints on a cache hit.
type snapshotHistory struct {
	ctx         context.Context
	bytes, work int
}

func (b *snapshotHistory) charge(n int) error {
	select {
	case <-b.ctx.Done():
		return b.ctx.Err()
	default:
	}
	if n < 0 || n > maxHistoryBytes-b.bytes || b.work >= maxHistoryWork {
		return ErrHistoryBudget
	}
	b.bytes += n
	b.work++
	return nil
}
func detachState(ctx context.Context, st *State) (*State, error) {
	b := &snapshotHistory{ctx: ctx}
	if err := b.charge(256); err != nil {
		return nil, err
	}
	out := &State{Genesis: st.Genesis, err: st.err, Keys: map[string]*Key{}, Status: map[string]OpStatus{}, Ops: map[string]*KeyOp{}}
	for id, key := range st.Keys {
		if err := b.charge(256 + len(id) + len(key.Pub) + 32*len(key.RevocationCauses)); err != nil {
			return nil, err
		}
		copyKey := *key
		copyKey.Pub = append([]byte(nil), key.Pub...)
		copyKey.RevocationCauses = append([]string(nil), key.RevocationCauses...)
		out.Keys[id] = &copyKey
	}
	for id, status := range st.Status {
		if err := b.charge(64 + len(id)); err != nil {
			return nil, err
		}
		out.Status[id] = status
	}
	for id, op := range st.Ops {
		n := 256 + len(id) + 256*len(op.Sigs)
		if op.Rec != nil {
			n += len(op.Rec.HeaderJCS) + len(op.Rec.BodyJCS)
		}
		if err := b.charge(n); err != nil {
			return nil, err
		}
		copyOp := cloneOp(op)
		if copyOp == nil || copyOp.Rec == nil || copyOp.Body == nil {
			return nil, ErrHistoryBudget
		}
		out.Ops[id] = copyOp
	}
	st.cutoffMu.Lock()
	defer st.cutoffMu.Unlock()
	if len(st.cutoffs) > 0 {
		out.cutoffs = map[string]cutoffResult{}
	}
	for id, cutoff := range st.cutoffs {
		if err := b.charge(96 + len(id)); err != nil {
			return nil, err
		}
		out.cutoffs[id] = cutoff
	}
	return out, nil
}

// RefusedState carries a failed authority evaluation through legacy APIs that
// cannot return an error. It grants no keys or operation authorizations.
func RefusedState(err error) *State {
	if err == nil {
		err = ErrHistoryBudget
	}
	return &State{err: err, Keys: map[string]*Key{}, Status: map[string]OpStatus{}, Ops: map[string]*KeyOp{}}
}
