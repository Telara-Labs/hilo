// Package invalidate is the dependency-aware invalidation of the memory node
// contract (§5): erasure, retraction and withdrawal, the invalidation
// closure over the dependency graph, grant inheritance, ancestry-pending
// and lineage-hold states.
//
// It holds no storage. Closure is a pure function. Model is an in-memory
// reference evaluator: it keeps the inputs a store keeps (admitted records,
// their dependency rows, control records, delivered sets) and derives every
// status from them, so its answers are the ones any store must reproduce
// and are independent of arrival order.
package invalidate

import (
	"sort"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// Closure returns seeds plus every node whose dependencies meet the result,
// transitively. deps maps a node to its dependency set D(n). The result does
// not depend on map or slice order.
func Closure(deps map[string][]string, seeds []string) map[string]bool {
	rev := map[string][]string{}
	for n, ds := range deps {
		for _, d := range ds {
			rev[d] = append(rev[d], n)
		}
	}
	out := map[string]bool{}
	stack := append([]string(nil), seeds...)
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if out[n] {
			continue
		}
		out[n] = true
		stack = append(stack, rev[n]...)
	}
	return out
}

// TombKind is the kind of a tomb (§5.1).
type TombKind string

const (
	Erased    TombKind = "erased"
	Retracted TombKind = "retracted"
	Withdrawn TombKind = "withdrawn"
)

// rank orders tomb kinds when one id is invalidated by several controls.
func rank(k TombKind) int {
	switch k {
	case Erased:
		return 3
	case Withdrawn:
		return 2
	case Retracted:
		return 1
	}
	return 0
}

// Tomb is one tomb row: the kind and the control that caused it.
type Tomb struct {
	Kind  TombKind
	Cause string // cause_control_id
}

// Item is what the evaluator knows about one admitted record or op-cache row.
type Item struct {
	ID         string
	LID        string
	Kind       record.Kind
	Prov       record.Prov
	TaskID     string
	SessionKey string
	Source     string
	// Owner is the owner of the verified signer (§1.3).
	Owner string
	// Deps is D(r) without links.origin: links.derived_from and body
	// manifests (session chunks, rollup covers), or an op-cache row's deps.
	Deps []string
	// Origin is links.origin; its absence never makes a record pending.
	Origin string
	// Route and, for hosted-pull, the tenant it was pulled from.
	Route       record.Route
	RouteTenant string
	// OpRow marks an op-cache row (R2.2). It is reached only by closure.
	OpRow bool
	// Lineage inputs. SessionSeq is the highest session seq the record
	// covers; Recalls are the lid@id read-backs its events recorded (chunks);
	// Scope and Explicit place explicit writes for delivered-set holds.
	SessionSeq int64
	Recalls    []Recall
	Scope      string
	Explicit   bool
}

// Recall is one Event.Recalled entry: at session seq Seq the session saw ID.
type Recall struct {
	Seq int64
	ID  string
}

// Control is a verified control record.
type Control struct {
	ID         string
	Kind       record.Kind // erasure | retraction | withdrawal
	Owner      string      // owner of the verified signer: genesis key id or "tenant:<id>"
	Erasure    *record.ErasureBody
	Retraction *record.RetractionBody
	Withdrawal *record.WithdrawalBody
}

func (c *Control) byTenant() (string, bool) {
	if len(c.Owner) > 7 && c.Owner[:7] == "tenant:" {
		return c.Owner[7:], true
	}
	return "", false
}

// Delivered is one delivered-set entry: ID was delivered to Scope at local
// admission sequence Seq.
type Delivered struct {
	Scope string
	ID    string
	Seq   int64
}

// Status of an item.
type Status string

const (
	Live            Status = "live"
	AncestryPending Status = "ancestry-pending" // shown only in S, labelled
	LineageHold     Status = "lineage-hold"     // out of H, E, P, S and export until released
	Invalidated     Status = "invalidated"
	Absent          Status = "absent"
)

// Model is the reference evaluator.
type Model struct {
	items     map[string]*Item
	seqOf     map[string]int64 // local admission order of items and controls
	controls  map[string]*Control
	delivered []Delivered
	released  map[string]bool
	seq       int64
}

// NewModel returns an empty evaluator.
func NewModel() *Model {
	return &Model{items: map[string]*Item{}, seqOf: map[string]int64{}, controls: map[string]*Control{}, released: map[string]bool{}}
}

func (m *Model) next(id string) {
	if _, ok := m.seqOf[id]; !ok {
		m.seq++
		m.seqOf[id] = m.seq
	}
}

// Admit records an admitted record or op-cache row. Admitting an id twice is
// a no-op.
func (m *Model) Admit(it Item) {
	if _, ok := m.items[it.ID]; ok {
		return
	}
	c := it
	m.items[it.ID] = &c
	m.next(it.ID)
}

// Apply records a verified control record.
func (m *Model) Apply(c Control) {
	if _, ok := m.controls[c.ID]; ok {
		return
	}
	cc := c
	m.controls[c.ID] = &cc
	m.next(c.ID)
}

// Deliver records a delivered-set entry.
func (m *Model) Deliver(d Delivered) { m.delivered = append(m.delivered, d) }

// Release lets the user release a lineage-held record.
func (m *Model) Release(id string) { m.released[id] = true }

// AdmittedSeq returns the local admission order of an id.
func (m *Model) AdmittedSeq(id string) int64 { return m.seqOf[id] }

func (m *Model) depsOf(it *Item) []string {
	d := append([]string(nil), it.Deps...)
	if it.Origin != "" {
		d = append(d, it.Origin)
	}
	return d
}

// Grants returns Grants(r): the route grant plus the grants of every
// present dependency, transitively (§5.2). Sorted.
func (m *Model) Grants(id string) []string {
	memo := map[string]map[string]bool{}
	g := m.grants(id, memo, map[string]bool{})
	out := make([]string, 0, len(g))
	for k := range g {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (m *Model) grants(id string, memo map[string]map[string]bool, visiting map[string]bool) map[string]bool {
	if g, ok := memo[id]; ok {
		return g
	}
	g := map[string]bool{}
	it := m.items[id]
	if it == nil || visiting[id] {
		return g
	}
	visiting[id] = true
	if it.Route == record.RouteHostedPull && it.RouteTenant != "" {
		g["tenant:"+it.RouteTenant] = true
	}
	for _, d := range m.depsOf(it) {
		for k := range m.grants(d, memo, visiting) {
			g[k] = true
		}
	}
	memo[id] = g
	return g
}

func (m *Model) hasGrant(id, tenant string) bool {
	for _, g := range m.Grants(id) {
		if g == "tenant:"+tenant {
			return true
		}
	}
	return false
}

// mayTarget is the §5.4 authority table for the direct targets of c.
func (m *Model) mayTarget(c *Control, it *Item) bool {
	if it.OpRow {
		return false
	}
	tenant, isTSK := c.byTenant()
	switch c.Kind {
	case record.KindErasure:
		if isTSK {
			return it.Prov == record.ProvGateway && it.Owner == c.Owner && m.hasGrant(it.ID, tenant)
		}
		return it.Owner == c.Owner || it.Prov == record.ProvGateway
	case record.KindRetraction:
		return it.Owner == c.Owner
	case record.KindWithdrawal:
		return isTSK && c.Withdrawal != nil && c.Withdrawal.Tenant == tenant && m.hasGrant(it.ID, tenant)
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// seeds resolves S0 for one control over the present items (§5.2 step 1).
// Erasure selectors match whenever the record arrives, so they also ban
// future arrivals. Listed ids match whenever the record arrives. A
// withdrawal with All covers the records present when it was applied.
func (m *Model) seeds(c *Control) []string {
	var s []string
	for id, it := range m.items {
		match := false
		switch c.Kind {
		case record.KindErasure:
			sel := c.Erasure.Selectors
			match = contains(sel.IDs, id) || contains(sel.LIDs, it.LID) ||
				(it.TaskID != "" && contains(sel.Tasks, it.TaskID)) ||
				(it.SessionKey != "" && contains(sel.Sessions, it.SessionKey)) ||
				(it.Source != "" && contains(sel.Sources, it.Source))
		case record.KindRetraction:
			match = contains(c.Retraction.IDs, id)
		case record.KindWithdrawal:
			match = contains(c.Withdrawal.IDs, id) || (c.Withdrawal.All && m.seqOf[id] < m.seqOf[c.ID])
		}
		if match && m.mayTarget(c, it) {
			s = append(s, id)
		}
	}
	return s
}

// Eval is the derived state of the model.
type Eval struct {
	Tombs  map[string]Tomb
	Status map[string]Status
}

// Evaluate derives tombs and statuses from the model's inputs.
func (m *Model) Evaluate() *Eval {
	deps := map[string][]string{}
	for id, it := range m.items {
		deps[id] = m.depsOf(it)
	}
	tombs := map[string]Tomb{}
	cids := make([]string, 0, len(m.controls))
	for id := range m.controls {
		cids = append(cids, id)
	}
	sort.Strings(cids)
	for _, cid := range cids {
		c := m.controls[cid]
		kind := map[record.Kind]TombKind{record.KindErasure: Erased, record.KindRetraction: Retracted, record.KindWithdrawal: Withdrawn}[c.Kind]
		tenant, isTSK := c.byTenant()
		for id := range Closure(deps, m.seeds(c)) {
			if _, present := m.items[id]; !present {
				continue
			}
			// R5.4: a TSK-signed control never purges content its tenant
			// did not grant.
			if isTSK && !m.hasGrant(id, tenant) {
				continue
			}
			t, ok := tombs[id]
			if !ok || rank(kind) > rank(t.Kind) || (rank(kind) == rank(t.Kind) && cid < t.Cause) {
				tombs[id] = Tomb{Kind: kind, Cause: cid}
			}
		}
	}
	ev := &Eval{Tombs: tombs, Status: map[string]Status{}}
	// ancestry-pending: some dependency (not the origin) is neither present
	// nor invalidated; propagate along dependencies
	pending := map[string]bool{}
	var isPending func(id string, seen map[string]bool) bool
	isPending = func(id string, seen map[string]bool) bool {
		if v, ok := pending[id]; ok {
			return v
		}
		if seen[id] {
			return false
		}
		seen[id] = true
		it := m.items[id]
		res := false
		for _, d := range it.Deps {
			if _, ok := m.items[d]; !ok || isPending(d, seen) {
				res = true
			}
		}
		pending[id] = res
		return res
	}
	// lineage-hold inputs
	recalls := map[string][]Recall{}
	for _, it := range m.items {
		if it.SessionKey != "" {
			recalls[it.SessionKey] = append(recalls[it.SessionKey], it.Recalls...)
		}
	}
	for id, it := range m.items {
		switch {
		case tombs[id] != (Tomb{}):
			ev.Status[id] = Invalidated
		case isPending(id, map[string]bool{}):
			ev.Status[id] = AncestryPending
		case !m.released[id] && m.held(it, tombs, recalls):
			ev.Status[id] = LineageHold
		default:
			ev.Status[id] = Live
		}
	}
	return ev
}

// held applies §5.2 step 5: a record that may repeat invalidated content
// without a dependency edge.
func (m *Model) held(it *Item, tombs map[string]Tomb, recalls map[string][]Recall) bool {
	if it.SessionKey != "" && it.SessionSeq > 0 {
		for _, r := range recalls[it.SessionKey] {
			if _, bad := tombs[r.ID]; bad && it.SessionSeq > r.Seq {
				return true
			}
		}
	}
	if it.Explicit && it.Scope != "" {
		for _, d := range m.delivered {
			if _, bad := tombs[d.ID]; bad && d.Scope == it.Scope && m.seqOf[it.ID] > d.Seq {
				return true
			}
		}
	}
	return false
}

// StatusOf returns the status of one id.
func (e *Eval) StatusOf(id string) Status {
	if s, ok := e.Status[id]; ok {
		return s
	}
	return Absent
}

// OpCacheFixedResult is the replay of an op whose result referred to
// invalidated memory (R2.2).
const OpCacheFixedResult = `{"isError":false,"content":[{"type":"text","text":"This result referred to memory that was erased or withdrawn."}]}`
