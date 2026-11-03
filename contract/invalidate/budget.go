package invalidate

import (
	"context"
	"errors"

	"github.com/Telara-Labs/hilo/contract/record"
)

// Exhaustion is a refusal, never an empty/partial successful invalidation.
var ErrEvaluationBudget = errors.New("invalidation_budget_exceeded")

const maxEvaluationWork = 2_000_000
const maxEvaluationBytes = 32 << 20

type evaluationBudget struct {
	context.Context
	work, bytes int
	affects     []map[string]struct{}
	roots       map[string][]string
}

func (b *evaluationBudget) Err() error {
	if err := b.Context.Err(); err != nil {
		return err
	}
	b.work++
	if b.work > maxEvaluationWork || b.bytes > maxEvaluationBytes {
		return ErrEvaluationBudget
	}
	return nil
}
func reserveEvaluation(ctx context.Context, bytes int) error {
	if b, ok := ctx.(interface{ reserveSnapshot(int) error }); ok {
		return b.reserveSnapshot(bytes)
	}
	if b, ok := ctx.(*evaluationBudget); ok {
		if bytes < 0 || bytes > maxEvaluationBytes-b.bytes {
			return ErrEvaluationBudget
		}
		b.bytes += bytes
	}
	return ctx.Err()
}
func (m *Model) preflightEvaluation(ctx context.Context) error {
	if err := reserveEvaluation(ctx, 512*(len(m.items)+len(m.controls)+len(m.exposures))); err != nil {
		return err
	}
	for _, it := range m.items {
		if err := reserveEvaluation(ctx, 96*(len(it.Deps)+len(it.Events)+len(it.Recalls))); err != nil {
			return err
		}
	}
	// Charge the index construction and the candidate/exposure probes before
	// allocating the index. Repeated probes remain charged during evaluation.
	exposureWork := 0
	for _, e := range m.exposures {
		if len(m.items) > maxEvaluationWork-exposureWork {
			return ErrEvaluationBudget
		}
		exposureWork += len(m.items)
		if len(e.AffectsIDs) > maxEvaluationWork-exposureWork {
			return ErrEvaluationBudget
		}
		exposureWork += len(e.AffectsIDs)
		if err := reserveEvaluation(ctx, 32*len(e.AffectsIDs)); err != nil {
			return err
		}
	}
	for _, gs := range m.directGrants {
		if err := reserveEvaluation(ctx, 128*len(gs)); err != nil {
			return err
		}
	}
	for _, c := range m.controls {
		n := 0
		if c.Retraction != nil {
			n += len(c.Retraction.IDs)
		}
		if c.Withdrawal != nil {
			n += len(c.Withdrawal.IDs)
		}
		if c.Erasure != nil {
			s := c.Erasure.Selectors
			n += len(s.IDs) + len(s.Events) + len(s.LIDs) + len(s.Tasks) + len(s.Sessions) + len(s.Sources)
		}
		if err := reserveEvaluation(ctx, 128*n); err != nil {
			return err
		}
	}
	return ctx.Err()
}

type controlGroup struct {
	control *Control
	causes  []Tomb
}

// causeSet is one shared cause list. Erasure sets are attached to their
// explicit expanded targets. Retraction and withdrawal sets are attached only to
// their seed roots; a record's causes are found through its own ancestry, so
// overlapping controls never materialize controls times descendants.
type causeSet struct {
	causes []Tomb
	tenant string
	tsk    bool
	seeds  []string
}

// CausesOf expands only the requested record's cause references.
func (e *Eval) CausesOf(id string) []Tomb {
	if e == nil || e.err != nil {
		return nil
	}
	if e.Causes != nil {
		return append([]Tomb(nil), e.Causes[id]...)
	}
	out, _ := e.causesOfContext(context.Background(), id)
	return out
}

func (e *Eval) causesOfContext(ctx context.Context, id string) ([]Tomb, error) {
	var out []Tomb
	for _, set := range e.causeRefs[id] {
		if err := reserveEvaluation(ctx, 64*len(set.causes)); err != nil {
			return nil, err
		}
		out = append(out, set.causes...)
	}
	if len(e.rootSets) == 0 {
		return out, ctx.Err()
	}
	used := map[*causeSet]bool{}
	seen := map[string]bool{id: true}
	todo := []string{id}
	for len(todo) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		a := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		for _, set := range e.rootSets[a] {
			if used[set] || set.tsk && !e.hasTenantGrant(id, set.tenant) {
				continue
			}
			used[set] = true
			if err := reserveEvaluation(ctx, 64*len(set.causes)); err != nil {
				return nil, err
			}
			out = append(out, set.causes...)
		}
		for _, d := range e.deps[a] {
			if !seen[d] {
				seen[d] = true
				todo = append(todo, d)
			}
		}
	}
	return out, ctx.Err()
}

// CauseCount is the number of records a control invalidates. Root-indexed
// counts are derived on demand from the shared closure, never stored per record.
func (e *Eval) CauseCount(id string) int {
	if e == nil || e.err != nil {
		return 0
	}
	if e.Causes != nil {
		n := 0
		for _, causes := range e.Causes {
			for _, cause := range causes {
				if cause.Cause == id {
					n++
					break
				}
			}
		}
		return n
	}
	set := e.causeSetOf[id]
	if set == nil {
		return e.causeCounts[id]
	}
	count := 0
	seen := map[string]bool{}
	todo := append([]string(nil), set.seeds...)
	for len(todo) > 0 {
		x := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if seen[x] {
			continue
		}
		seen[x] = true
		if !set.tsk || e.hasTenantGrant(x, set.tenant) {
			count++
		}
		todo = append(todo, e.reverse[x]...)
	}
	return count
}

func (e *Eval) hasTenantGrant(id, tenant string) bool {
	for _, g := range e.grantSets[id] {
		if g.Tenant == tenant {
			return true
		}
	}
	return false
}

func (m *Model) downstreamContext(ctx context.Context, it *Item, index int) bool {
	e := m.exposures[index]
	if b, ok := ctx.(*evaluationBudget); ok {
		if b.affects == nil {
			if len(e.AffectsIDs) > maxEvaluationWork-b.work {
				b.work = maxEvaluationWork + 1
				return false
			}
			b.work += len(e.AffectsIDs)
			if parent, ok := b.Context.(interface{ SpendWork(int) error }); ok && parent.SpendWork(len(e.AffectsIDs)) != nil {
				b.work = maxEvaluationWork + 1
				return false
			}
			return ctx.Err() == nil && m.downstream(it, e)
		}
		if parent, ok := b.Context.(interface{ SpendWork(int) error }); ok {
			if parent.SpendWork(1) != nil {
				b.work = maxEvaluationWork + 1
				return false
			}
		}
		if ctx.Err() != nil {
			return false
		}
		if _, ok := b.affects[index][it.ID]; ok {
			return true
		}
		return m.downstreamByContext(it, e)
	}
	return ctx.Err() == nil && m.downstream(it, e)
}

// exposureRoots computes the union once per item for this evaluation. Distinct
// exposures with the same root contribute the same dependency and cause; keep
// their first matching root while retaining all distinct roots.
func (m *Model) exposureRoots(ctx context.Context, it *Item) ([]string, error) {
	b, cached := ctx.(*evaluationBudget)
	if cached && b.roots != nil {
		if roots, ok := b.roots[it.ID]; ok {
			return roots, ctx.Err()
		}
	}
	var roots []string
	seen := make(map[string]bool)
	for i, e := range m.exposures {
		if !m.downstreamContext(ctx, it, i) {
			if cached && (b.work > maxEvaluationWork || b.Context.Err() != nil) {
				return nil, ctx.Err()
			}
			continue
		}
		if !seen[e.ID] {
			if err := reserveEvaluation(ctx, 64+len(e.ID)); err != nil {
				return nil, err
			}
			seen[e.ID] = true
			roots = append(roots, e.ID)
		}
	}
	if cached && b.roots != nil {
		b.roots[it.ID] = roots
	}
	return roots, ctx.Err()
}

// Err reports a refused legacy result. A refusal never grants liveness or
// export eligibility and must be propagated before persistence or ACK.
func (e *Eval) Err() error {
	if e == nil {
		return ErrEvaluationBudget
	}
	return e.err
}

// EvaluateContext returns a detached compact snapshot. Even exported maps are
// copied: no caller mutation can change the model's cached evaluation.
func (m *Model) EvaluateContext(ctx context.Context) (*Eval, error) {
	ev, err := m.evaluateContext(ctx)
	if err != nil {
		return nil, err
	}
	return detachEvaluation(ctx, ev, false)
}

// EvaluateDetachedContext returns the legacy mutable Causes representation with
// explicit refusal. The node uses it before applying its additional local fences.
// Cause expansion is charged before allocation and never cached as partial work.
func (m *Model) EvaluateDetachedContext(ctx context.Context) (*Eval, error) {
	ev, err := m.evaluateContext(ctx)
	if err != nil {
		return nil, err
	}
	return detachEvaluation(ctx, ev, true)
}

type snapshotEvaluation struct {
	ctx         context.Context
	bytes, work int
}

func (b *snapshotEvaluation) charge(n int) error {
	select {
	case <-b.ctx.Done():
		return b.ctx.Err()
	default:
	}
	if n < 0 || n > maxEvaluationBytes-b.bytes || b.work >= maxEvaluationWork {
		return ErrEvaluationBudget
	}
	b.bytes += n
	b.work++
	return nil
}
func detachEvaluation(ctx context.Context, e *Eval, materialize bool) (*Eval, error) {
	b := &snapshotEvaluation{ctx: ctx}
	if err := b.charge(512); err != nil {
		return nil, err
	}
	out := &Eval{err: e.err, OwnerPending: map[string]bool{}, ControlComplete: map[string]bool{}, EventBans: map[string]bool{}, Tombs: map[string]Tomb{}, HoldCauses: map[string][]string{}, Status: map[string]Status{}, causeRefs: map[string][]*causeSet{}, rootSets: map[string][]*causeSet{}, causeSetOf: map[string]*causeSet{}, causeCounts: map[string]int{}, deps: map[string][]string{}, reverse: map[string][]string{}, grantSets: map[string]map[string]record.GrantRef{}}
	for _, pair := range []struct{ from, to map[string]bool }{{e.OwnerPending, out.OwnerPending}, {e.ControlComplete, out.ControlComplete}, {e.EventBans, out.EventBans}} {
		for id, v := range pair.from {
			if err := b.charge(64 + len(id)); err != nil {
				return nil, err
			}
			pair.to[id] = v
		}
	}
	for id, v := range e.Tombs {
		if err := b.charge(128 + len(id)); err != nil {
			return nil, err
		}
		out.Tombs[id] = v
	}
	for id, v := range e.Status {
		if err := b.charge(64 + len(id)); err != nil {
			return nil, err
		}
		out.Status[id] = v
	}
	for id, v := range e.causeCounts {
		if err := b.charge(64 + len(id)); err != nil {
			return nil, err
		}
		out.causeCounts[id] = v
	}
	for _, pair := range []struct{ from, to map[string][]string }{{e.HoldCauses, out.HoldCauses}, {e.deps, out.deps}, {e.reverse, out.reverse}} {
		for id, values := range pair.from {
			if err := b.charge(64 + len(id) + 32*len(values)); err != nil {
				return nil, err
			}
			pair.to[id] = append([]string(nil), values...)
		}
	}
	for id, grants := range e.grantSets {
		if err := b.charge(64 + len(id) + 128*len(grants)); err != nil {
			return nil, err
		}
		copyGrants := map[string]record.GrantRef{}
		for key, grant := range grants {
			copyGrants[key] = grant
		}
		out.grantSets[id] = copyGrants
	}
	copied := map[*causeSet]*causeSet{}
	copySet := func(set *causeSet) (*causeSet, error) {
		if set == nil {
			return nil, nil
		}
		if existing := copied[set]; existing != nil {
			return existing, nil
		}
		if err := b.charge(128 + 64*len(set.causes) + 32*len(set.seeds)); err != nil {
			return nil, err
		}
		c := *set
		c.causes = append([]Tomb(nil), set.causes...)
		c.seeds = append([]string(nil), set.seeds...)
		copied[set] = &c
		return &c, nil
	}
	for _, pair := range []struct{ from, to map[string][]*causeSet }{{e.causeRefs, out.causeRefs}, {e.rootSets, out.rootSets}} {
		for id, sets := range pair.from {
			if err := b.charge(64 + len(id) + 8*len(sets)); err != nil {
				return nil, err
			}
			for _, set := range sets {
				c, err := copySet(set)
				if err != nil {
					return nil, err
				}
				pair.to[id] = append(pair.to[id], c)
			}
		}
	}
	for id, set := range e.causeSetOf {
		if err := b.charge(64 + len(id)); err != nil {
			return nil, err
		}
		c, err := copySet(set)
		if err != nil {
			return nil, err
		}
		out.causeSetOf[id] = c
	}
	if materialize {
		out.Causes = map[string][]Tomb{}
		ids := map[string]bool{}
		addID := func(id string) error {
			if ids[id] {
				return nil
			}
			if err := b.charge(64 + len(id)); err != nil {
				return err
			}
			ids[id] = true
			return nil
		}
		for id := range e.Status {
			if err := addID(id); err != nil {
				return nil, err
			}
		}
		for id := range e.Tombs {
			if err := addID(id); err != nil {
				return nil, err
			}
		}
		for id := range e.causeRefs {
			if err := addID(id); err != nil {
				return nil, err
			}
		}
		for id := range e.rootSets {
			if err := addID(id); err != nil {
				return nil, err
			}
		}
		// Use the same compact provenance traversal, with an independent bound on
		// the legacy expanded output. Never allocate a controls-times-records map
		// before charging it or return a successful partial map.
		for id := range ids {
			causes, err := e.causesOfContext(&snapshotTraversal{Context: b.ctx, snapshotEvaluation: b}, id)
			if err != nil {
				return nil, err
			}
			if len(causes) > 0 {
				if err = b.charge(64 + len(id) + 64*len(causes)); err != nil {
					return nil, err
				}
				out.Causes[id] = append([]Tomb(nil), causes...)
			}
		}
	}
	return out, nil
}

// Traversal charges every ancestry visit while respecting real cancellation.
// It intentionally does not replay a completed evaluation's parent Err budget.
type snapshotTraversal struct {
	context.Context
	*snapshotEvaluation
}

func (b *snapshotTraversal) Err() error                  { return b.charge(16) }
func (b *snapshotTraversal) reserveSnapshot(n int) error { return b.charge(n) }
