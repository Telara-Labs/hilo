// Package invalidate evaluates dependency-aware invalidation from verified
// admission facts. It stores no text or bytes; a persistent store must apply
// the returned changes atomically with admission and physical cleanup.
package invalidate

import (
	"encoding/json"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"sort"
	"strings"
)

func Closure(deps map[string][]string, seeds []string) map[string]bool {
	reverse := map[string][]string{}
	for id, ds := range deps {
		for _, d := range ds {
			reverse[d] = append(reverse[d], id)
		}
	}
	out := map[string]bool{}
	todo := append([]string(nil), seeds...)
	for len(todo) > 0 {
		id := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if out[id] {
			continue
		}
		out[id] = true
		todo = append(todo, reverse[id]...)
	}
	return out
}

type TombKind string

const (
	Erased    TombKind = "erased"
	Retracted TombKind = "retracted"
	Withdrawn TombKind = "withdrawn"
)

type Tomb struct {
	Kind  TombKind
	Cause string
}

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

type Item struct {
	Events                            []string // admitted event identities only, never salt or text
	ID, LID                           string
	Kind                              record.Kind
	Prov                              record.Prov
	TaskID, SessionKey, Source, Owner string
	Deps                              []string
	Origin                            string
	// Route facts MUST already have been authenticated by the admission layer.
	Route           record.Route
	RouteTenant     string
	GrantGeneration int64
	OriginMachine   string
	OpRow           bool
	SessionSeq      int64
	Recalls         []Recall
	Scope           string
	Explicit        bool
}
type Recall struct {
	Seq int64
	ID  string
}
type Control struct {
	ID         string
	Kind       record.Kind
	Owner      string
	Erasure    *record.ErasureBody
	Retraction *record.RetractionBody
	Withdrawal *record.WithdrawalBody
}

func (c *Control) byTenant() (string, bool) {
	if strings.HasPrefix(c.Owner, "tenant:") {
		return strings.TrimPrefix(c.Owner, "tenant:"), true
	}
	return "", false
}

// Delivered is conservative exposure, not confirmed-delivery dedup state.
type Delivered struct {
	Scope, ID string
	Seq       int64
}

// Exposure survives body deletion, compaction and late attribution. A zero
// boundary with UnknownOrder conservatively applies to all matching output.
type Exposure struct {
	OriginMachine, Scope, SessionKey, ID string
	Seq                                  int64
	UnknownOrder                         bool
	AffectsIDs                           []string
}
type Status string

const (
	Live            Status = "live"
	AncestryPending Status = "ancestry-pending"
	LineageHold     Status = "lineage-hold"
	Invalidated     Status = "invalidated"
	Absent          Status = "absent"
)

type Model struct {
	items        map[string]*Item
	controls     map[string]*Control
	seqOf        map[string]int64
	seq          int64
	exposures    []Exposure
	directGrants map[string]map[string]record.GrantRef
	released     map[string]map[string]bool
}

func NewModel() *Model {
	return &Model{items: map[string]*Item{}, controls: map[string]*Control{}, seqOf: map[string]int64{}, released: map[string]map[string]bool{}, directGrants: map[string]map[string]record.GrantRef{}}
}
func (m *Model) next(id string) {
	if _, ok := m.seqOf[id]; !ok {
		m.seq++
		m.seqOf[id] = m.seq
	}
}
func (m *Model) AdmittedSeq(id string) int64 { return m.seqOf[id] }
func (m *Model) Admit(it Item) {
	// Authenticated grants are delivery facts, independent of content dedup.
	if it.Route == record.RouteHostedPull && it.RouteTenant != "" && it.GrantGeneration > 0 {
		g := record.GrantRef{Tenant: it.RouteTenant, Generation: it.GrantGeneration}
		if m.directGrants[it.ID] == nil {
			m.directGrants[it.ID] = map[string]record.GrantRef{}
		}
		m.directGrants[it.ID][grantKey(g)] = g
	}

	if _, ok := m.items[it.ID]; ok {
		return
	}
	c := it
	c.Deps = append([]string(nil), it.Deps...)
	c.Events = append([]string(nil), it.Events...)
	c.Recalls = append([]Recall(nil), it.Recalls...)
	m.items[it.ID] = &c
	m.next(it.ID)
	for _, r := range it.Recalls {
		m.Expose(Exposure{SessionKey: it.SessionKey, ID: r.ID, Seq: r.Seq})
	}
}
func (m *Model) Apply(c Control) error {
	if c.ID == "" {
		return fmt.Errorf("control: id required")
	}
	if _, ok := m.controls[c.ID]; ok {
		return nil
	}
	switch c.Kind {
	case record.KindErasure:
		if c.Erasure == nil {
			return fmt.Errorf("control: absent erasure")
		}
	case record.KindRetraction:
		if c.Retraction == nil {
			return fmt.Errorf("control: absent retraction")
		}
	case record.KindWithdrawal:
		if c.Withdrawal == nil || c.Withdrawal.PolicySeq <= 0 {
			return fmt.Errorf("control: positive withdrawal generation required")
		}
	default:
		return fmt.Errorf("control: unsupported kind")
	}
	var cc Control
	raw, _ := json.Marshal(c)
	if err := json.Unmarshal(raw, &cc); err != nil {
		return err
	}
	m.controls[c.ID] = &cc
	m.next(c.ID)
	return nil
}
func (m *Model) Deliver(d Delivered) { m.Expose(Exposure{Scope: d.Scope, ID: d.ID, Seq: d.Seq}) }
func (m *Model) Expose(e Exposure) {
	e.AffectsIDs = append([]string(nil), e.AffectsIDs...)
	m.exposures = append(m.exposures, e)
}

// Exposures returns a detached ledger snapshot for authenticated bundle transfer.
func (m *Model) Exposures() []Exposure {
	out := make([]Exposure, len(m.exposures))
	for i, e := range m.exposures {
		e.AffectsIDs = append([]string(nil), e.AffectsIDs...)
		out[i] = e
	}
	return out
}
func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
func (m *Model) downstream(it *Item, e Exposure) bool {
	if contains(e.AffectsIDs, it.ID) {
		return true
	}
	if e.SessionKey != "" && it.SessionKey == e.SessionKey {
		return e.UnknownOrder || it.SessionSeq > e.Seq
	}
	return e.Scope != "" && it.Explicit && it.Scope == e.Scope && (e.OriginMachine == "" || it.OriginMachine == e.OriginMachine) && (e.UnknownOrder || m.seqOf[it.ID] > e.Seq)
}
func (m *Model) depsOf(it *Item) []string {
	d := append([]string(nil), it.Deps...)
	if it.Origin != "" {
		d = append(d, it.Origin)
	}
	return d
}
func grantKey(g record.GrantRef) string { return fmt.Sprintf("%s/%d", g.Tenant, g.Generation) }

// Grants computes a monotone fixed point across copied and semantic lineage.
func (m *Model) Grants(id string) []record.GrantRef {
	all := map[string]map[string]record.GrantRef{}
	for key := range m.items {
		all[key] = map[string]record.GrantRef{}
		for gkey, g := range m.directGrants[key] {
			all[key][gkey] = g
		}
	}
	changed := true
	for changed {
		changed = false
		for key, it := range m.items {
			ds := m.depsOf(it)
			for _, e := range m.exposures {
				if m.downstream(it, e) {
					ds = append(ds, e.ID)
				}
			}
			for _, d := range ds {
				for k, g := range all[d] {
					if _, ok := all[key][k]; !ok {
						all[key][k] = g
						changed = true
					}
				}
			}
		}
	}
	var out []record.GrantRef
	for _, g := range all[id] {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tenant != out[j].Tenant {
			return out[i].Tenant < out[j].Tenant
		}
		return out[i].Generation < out[j].Generation
	})
	return out
}
func (m *Model) hasGrant(id, tenant string) bool {
	for _, g := range m.Grants(id) {
		if g.Tenant == tenant {
			return true
		}
	}
	return false
}
func (m *Model) mayTarget(c *Control, it *Item) bool {
	if it.OpRow || it.Kind.IsControl() {
		return false
	}
	tenant, tsk := c.byTenant()
	switch c.Kind {
	case record.KindErasure:
		if tsk {
			return it.Prov == record.ProvGateway && it.Owner == c.Owner && m.hasGrant(it.ID, tenant)
		}
		return it.Owner == c.Owner || it.Prov == record.ProvGateway
	case record.KindRetraction:
		return it.Owner == c.Owner
	case record.KindWithdrawal:
		return tsk && c.Withdrawal.Tenant == tenant && m.hasGrant(it.ID, tenant)
	}
	return false
}
func taskMatches(xs []record.TaskSelector, it *Item) bool {
	for _, x := range xs {
		if x.Owner == it.Owner && x.TaskID == it.TaskID {
			return true
		}
	}
	return false
}
func (m *Model) seeds(c *Control) []string {
	var out []string
	// Exact device erasure/retraction ids establish a dependency tomb even when
	// the root has not arrived. Known foreign/control targets remain excluded.
	var exact []string
	switch c.Kind {
	case record.KindErasure:
		exact = c.Erasure.Selectors.IDs
	case record.KindRetraction:
		exact = c.Retraction.IDs
	case record.KindWithdrawal:
		exact = c.Withdrawal.IDs
	}
	_, tsk := c.byTenant()
	if !tsk {
		for _, id := range exact {
			if _, present := m.items[id]; !present {
				out = append(out, id)
			}
		}
	}
	for id, it := range m.items {
		match := false
		switch c.Kind {
		case record.KindErasure:
			s := c.Erasure.Selectors
			match = contains(s.IDs, id) || contains(s.LIDs, it.LID) || taskMatches(s.Tasks, it) || (it.SessionKey != "" && contains(s.Sessions, it.SessionKey)) || (it.Source != "" && contains(s.Sources, it.Source))
		case record.KindRetraction:
			match = contains(c.Retraction.IDs, id)
		case record.KindWithdrawal:
			match = contains(c.Withdrawal.IDs, id)
			if c.Withdrawal.All {
				for _, g := range m.Grants(id) {
					if g.Tenant == c.Withdrawal.Tenant && g.Generation <= c.Withdrawal.PolicySeq {
						match = true
					}
				}
			}
		}
		if match && m.mayTarget(c, it) {
			out = append(out, id)
		}
	}
	return out
}

type Eval struct {
	EventBans  map[string]bool
	Tombs      map[string]Tomb
	Causes     map[string][]Tomb
	HoldCauses map[string][]string
	Status     map[string]Status
}

func (m *Model) Evaluate() *Eval {
	deps := map[string][]string{}
	for id, it := range m.items {
		deps[id] = m.depsOf(it)
	}
	ev := &Eval{Tombs: map[string]Tomb{}, Causes: map[string][]Tomb{}, Status: map[string]Status{}, HoldCauses: map[string][]string{}, EventBans: map[string]bool{}}
	cids := make([]string, 0, len(m.controls))
	for id := range m.controls {
		cids = append(cids, id)
	}
	sort.Strings(cids)
	for _, cid := range cids {
		c := m.controls[cid]
		kind := map[record.Kind]TombKind{record.KindErasure: Erased, record.KindRetraction: Retracted, record.KindWithdrawal: Withdrawn}[c.Kind]
		tenant, tsk := c.byTenant()
		targets := Closure(deps, m.seeds(c))
		if c.Kind == record.KindErasure {
			controlBans := map[string]bool{}
			changed := true
			for changed {
				changed = false
				for id := range targets {
					it := m.items[id]
					if it == nil || tsk && !m.hasGrant(id, tenant) {
						continue
					}
					for _, eventID := range it.Events {
						key := eventBanKey(it.Owner, it.SessionKey, eventID)
						if !controlBans[key] {
							controlBans[key] = true
							ev.EventBans[key] = true
							changed = true
						}
					}
				}
				for id, it := range m.items {
					if targets[id] || tsk && !m.hasGrant(id, tenant) {
						continue
					}
					for _, eventID := range it.Events {
						if controlBans[eventBanKey(it.Owner, it.SessionKey, eventID)] {
							targets[id] = true
							changed = true
						}
					}
				}
				if changed {
					seeds := []string{}
					for id := range targets {
						seeds = append(seeds, id)
					}
					targets = Closure(deps, seeds)
				}
			}
		}
		for id := range targets {
			if tsk && !m.hasGrant(id, tenant) {
				continue
			}
			t := Tomb{Kind: kind, Cause: cid}
			ev.Causes[id] = append(ev.Causes[id], t)
			old, ok := ev.Tombs[id]
			if !ok || rank(kind) > rank(old.Kind) || (rank(kind) == rank(old.Kind) && cid < old.Cause) {
				ev.Tombs[id] = t
			}
		}
	}
	// A dependency cycle is unresolved, not a proof of complete ancestry.
	pending := map[string]bool{}
	var visit func(string, map[string]bool) bool
	visit = func(id string, path map[string]bool) bool {
		if v, ok := pending[id]; ok {
			return v
		}
		if path[id] {
			return true
		}
		it := m.items[id]
		if it == nil {
			return ev.Tombs[id] == (Tomb{})
		}
		path[id] = true
		defer delete(path, id)
		res := it.Route == record.RouteHostedPull && len(m.directGrants[id]) == 0
		pendingDeps := append([]string(nil), it.Deps...)
		if it.Origin != "" && m.items[it.Origin] != nil {
			pendingDeps = append(pendingDeps, it.Origin)
		}
		for _, d := range pendingDeps {
			if visit(d, path) {
				res = true
			}
		}
		for _, e := range m.exposures {
			if m.downstream(it, e) && ev.Tombs[e.ID] == (Tomb{}) && visit(e.ID, path) {
				res = true
			}
		}
		pending[id] = res
		return res
	}
	// Semantic holds propagate through both copied and recalled lineage. Keep
	// every underlying cause even when an intermediate record was reviewed/released.
	holds := map[string]map[string]bool{}
	for id := range m.items {
		holds[id] = map[string]bool{}
	}
	changed := true
	for changed {
		changed = false
		for id, it := range m.items {
			add := func(token string) {
				if !holds[id][token] {
					holds[id][token] = true
					changed = true
				}
			}
			for _, d := range m.depsOf(it) {
				for token := range holds[d] {
					add(token)
				}
			}
			for _, e := range m.exposures {
				if !m.downstream(it, e) {
					continue
				}
				for _, cause := range ev.Causes[e.ID] {
					add(e.ID + "/" + cause.Cause)
				}
				for token := range holds[e.ID] {
					add(token)
				}
			}
		}
	}
	for id, tokens := range holds {
		for token := range tokens {
			ev.HoldCauses[id] = append(ev.HoldCauses[id], token)
		}
		sort.Strings(ev.HoldCauses[id])
	}
	for id, it := range m.items {
		switch {
		case ev.Tombs[id] != (Tomb{}):
			ev.Status[id] = Invalidated
		case m.hasUnreleasedExposure(it, ev):
			ev.Status[id] = LineageHold
		case visit(id, map[string]bool{}):
			ev.Status[id] = AncestryPending
		default:
			ev.Status[id] = Live
		}
	}
	return ev
}
func (m *Model) hasUnreleasedExposure(it *Item, ev *Eval) bool {
	for _, token := range ev.HoldCauses[it.ID] {
		if !m.released[it.ID][token] {
			return true
		}
	}
	return false
}

// Release authorizes only already reviewed cause tokens of this exact record.
func (m *Model) Release(id string) {
	ev := m.Evaluate()
	if m.items[id] == nil {
		return
	}
	if m.released[id] == nil {
		m.released[id] = map[string]bool{}
	}
	for _, token := range ev.HoldCauses[id] {
		m.released[id][token] = true
	}
}
func (e *Eval) StatusOf(id string) Status {
	if s, ok := e.Status[id]; ok {
		return s
	}
	return Absent
}
func (m *Model) ExportEligible(id string) bool {
	return m.Evaluate().StatusOf(id) == Live && len(m.Grants(id)) == 0
}

const OpCacheFixedResult = `{"isError":false,"content":[{"type":"text","text":"The operation was recorded, but its prior memory content is no longer available to this caller."}]}`

func eventBanKey(owner, session, eventID string) string {
	return record.H("erased-event", owner, session, eventID)
}

// EventErased must be checked before capture sealing; it retains only source identity.
func (m *Model) EventErased(owner, session, eventID string) bool {
	return m.Evaluate().EventBans[eventBanKey(owner, session, eventID)]
}
