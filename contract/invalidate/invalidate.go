// Package invalidate evaluates dependency-aware invalidation from verified
// admission facts. It stores no text or bytes; a persistent store must apply
// the returned changes atomically with admission and physical cleanup.
package invalidate

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"sort"
	"strings"
)

func Closure(deps map[string][]string, seeds []string) map[string]bool {
	out, _ := ClosureContext(context.Background(), deps, seeds)
	return out
}

func ClosureContext(ctx context.Context, deps map[string][]string, seeds []string) (map[string]bool, error) {
	reverse := map[string][]string{}
	for id, ds := range deps {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, d := range ds {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			reverse[d] = append(reverse[d], id)
		}
	}
	return closureContext(ctx, reverse, seeds)
}
func closureContext(ctx context.Context, reverse map[string][]string, seeds []string) (map[string]bool, error) {
	out := map[string]bool{}
	todo := append([]string(nil), seeds...)
	for len(todo) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if out[id] {
			continue
		}
		if err := reserveEvaluation(ctx, 96+16*len(reverse[id])); err != nil {
			return nil, err
		}
		out[id] = true
		todo = append(todo, reverse[id]...)
	}
	return out, ctx.Err()
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
	EventMembershipComplete           bool     // verified complete membership, including an empty set
	BodyAvailable                     bool     // full call body/key provenance verified
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
	cached       *Eval
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
		if _, ok := m.directGrants[it.ID][grantKey(g)]; !ok {
			m.cached = nil
		}
		m.directGrants[it.ID][grantKey(g)] = g
	}

	if old, ok := m.items[it.ID]; ok {
		if !old.EventMembershipComplete && it.EventMembershipComplete {
			old.Events = append([]string(nil), it.Events...)
			old.EventMembershipComplete = true
			m.cached = nil
		}
		if it.BodyAvailable && !old.BodyAvailable {
			m.cached = nil
			old.BodyAvailable = true
		}
		return
	}
	c := it
	c.Deps = append([]string(nil), it.Deps...)
	c.Events = append([]string(nil), it.Events...)
	c.Recalls = append([]Recall(nil), it.Recalls...)
	m.cached = nil
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
		if c.Erasure == nil || c.Erasure.EventCoverage != "complete" {
			return fmt.Errorf("control: absent erasure")
		}
		for _, e := range c.Erasure.Selectors.Events {
			if _, tsk := c.byTenant(); tsk || e.Owner != c.Owner || !record.ValidOwner(e.Owner) || !record.IsSessionKey(e.SessionKey) || !record.IsEventID(e.EventID) {
				return fmt.Errorf("control: event scope violation")
			}
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
	m.cached = nil
	m.controls[c.ID] = &cc
	m.next(c.ID)
	return nil
}
func (m *Model) Deliver(d Delivered) { m.Expose(Exposure{Scope: d.Scope, ID: d.ID, Seq: d.Seq}) }
func (m *Model) Expose(e Exposure) {
	e.AffectsIDs = append([]string(nil), e.AffectsIDs...)
	m.cached = nil
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
	out, _ := m.grantsContext(context.Background(), id)
	return out
}
func (m *Model) grantSetsContext(ctx context.Context) (map[string]map[string]record.GrantRef, error) {
	all := map[string]map[string]record.GrantRef{}
	for key := range m.items {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		all[key] = map[string]record.GrantRef{}
		for gkey, g := range m.directGrants[key] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			all[key][gkey] = g
		}
	}
	changed := true
	for changed {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		changed = false
		for key, it := range m.items {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			ds := m.depsOf(it)
			for _, e := range m.exposures {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if m.downstreamContext(ctx, it, e) {
					ds = append(ds, e.ID)
				}
			}
			for _, d := range ds {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				for k, g := range all[d] {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					if _, ok := all[key][k]; !ok {
						if err := reserveEvaluation(ctx, 128); err != nil {
							return nil, err
						}
						all[key][k] = g
						changed = true
					}
				}
			}
		}
	}
	return all, ctx.Err()
}
func (m *Model) grantsContext(ctx context.Context, id string) ([]record.GrantRef, error) {
	all, err := m.grantSetsContext(ctx)
	if err != nil {
		return nil, err
	}
	return sortedGrants(ctx, all[id])
}
func sortedGrants(ctx context.Context, set map[string]record.GrantRef) ([]record.GrantRef, error) {
	var out []record.GrantRef
	for _, g := range set {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tenant != out[j].Tenant {
			return out[i].Tenant < out[j].Tenant
		}
		return out[i].Generation < out[j].Generation
	})
	return out, ctx.Err()
}
func (m *Model) hasGrant(id, tenant string) bool {
	for _, g := range m.Grants(id) {
		if g.Tenant == tenant {
			return true
		}
	}
	return false
}
func (m *Model) mayTarget(c *Control, it *Item, hasGrant func(string, string) bool) bool {
	if it.OpRow || it.Kind.IsControl() {
		return false
	}
	tenant, tsk := c.byTenant()
	switch c.Kind {
	case record.KindErasure:
		if tsk {
			return it.Prov == record.ProvGateway && it.Owner == c.Owner && hasGrant(it.ID, tenant)
		}
		return it.Owner == c.Owner || it.Prov == record.ProvGateway
	case record.KindRetraction:
		return it.Owner == c.Owner
	case record.KindWithdrawal:
		return tsk && c.Withdrawal.Tenant == tenant && hasGrant(it.ID, tenant)
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
func (m *Model) seeds(ctx context.Context, c *Control, hasGrant func(string, string) bool, grants func(string) []record.GrantRef) ([]string, error) {
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
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if _, present := m.items[id]; !present {
				out = append(out, id)
			}
		}
	}
	// Exact-only selectors need no retained-item scan. Wider selectors retain
	// their existing matching semantics.
	candidates := m.items
	exactOnly := c.Kind == record.KindRetraction || c.Kind == record.KindWithdrawal && !c.Withdrawal.All
	if c.Kind == record.KindErasure {
		s := c.Erasure.Selectors
		exactOnly = len(s.Events)+len(s.LIDs)+len(s.Tasks)+len(s.Sessions)+len(s.Sources) == 0
	}
	if exactOnly {
		candidates = map[string]*Item{}
		for _, id := range exact {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if it := m.items[id]; it != nil {
				candidates[id] = it
			}
		}
	}
	exactIDs, lids, sessions, sources, tasks, events := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	if !exactOnly {
		for _, id := range exact {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			exactIDs[id] = true
		}
		if c.Erasure != nil {
			ss := c.Erasure.Selectors
			for _, id := range ss.LIDs {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				lids[id] = true
			}
			for _, id := range ss.Sessions {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				sessions[id] = true
			}
			for _, id := range ss.Sources {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				sources[id] = true
			}
			for _, t := range ss.Tasks {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				tasks[t.Owner+"\x00"+t.TaskID] = true
			}
			for _, e := range ss.Events {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				events[eventBanKey(e.Owner, e.SessionKey, e.EventID)] = true
			}
		}
	}
	for id, it := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		match := exactOnly
		if !exactOnly {
			switch c.Kind {
			case record.KindErasure:
				match = exactIDs[id] || lids[it.LID] || tasks[it.Owner+"\x00"+it.TaskID] || it.SessionKey != "" && sessions[it.SessionKey] || it.Source != "" && sources[it.Source]
				if len(events) > 0 {
					for _, event := range it.Events {
						if err := ctx.Err(); err != nil {
							return nil, err
						}
						if events[eventBanKey(it.Owner, it.SessionKey, event)] {
							match = true
						}
					}
				}
			case record.KindRetraction:
				match = exactIDs[id]
			case record.KindWithdrawal:
				match = exactIDs[id]
				if c.Withdrawal.All {
					for _, g := range grants(id) {
						if err := ctx.Err(); err != nil {
							return nil, err
						}
						if g.Tenant == c.Withdrawal.Tenant && g.Generation <= c.Withdrawal.PolicySeq {
							match = true
						}
					}
				}
			}
		}
		if match && m.mayTarget(c, it, hasGrant) {
			out = append(out, id)
		}
	}
	return out, ctx.Err()
}

type Eval struct {
	err error
	// Causes is the detached complete legacy cause map returned by Evaluate.
	// Context evaluations use compact indexes and CausesOf instead.
	Causes          map[string][]Tomb
	OwnerPending    map[string]bool
	ControlComplete map[string]bool
	EventBans       map[string]bool
	Tombs           map[string]Tomb
	causeRefs       map[string][]*causeSet // erasure sets, by expanded target
	causeCounts     map[string]int
	rootSets        map[string][]*causeSet // retraction/withdrawal sets, by seed root
	causeSetOf      map[string]*causeSet
	deps, reverse   map[string][]string
	grantSets       map[string]map[string]record.GrantRef
	HoldCauses      map[string][]string
	Status          map[string]Status
}

// Evaluate returns a read-only evaluation, reused until an actual mutation.
// Model and its evaluations are confined to their owning admission transaction.
func (m *Model) Evaluate() *Eval {
	ev, err := m.EvaluateDetachedContext(context.Background())
	if err != nil {
		return &Eval{err: err, Causes: map[string][]Tomb{}, Status: map[string]Status{}, Tombs: map[string]Tomb{}, HoldCauses: map[string][]string{}, OwnerPending: map[string]bool{}, ControlComplete: map[string]bool{}, EventBans: map[string]bool{}}
	}
	return ev
}

// EvaluateContext never caches a cancelled or partial evaluation.
func (m *Model) evaluateContext(ctx context.Context) (*Eval, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.cached != nil {
		return m.cached, nil
	}
	budget := &evaluationBudget{Context: ctx}
	ctx = budget
	// Charge retained graph shape before building indexes or expanded closures.
	if err := m.preflightEvaluation(ctx); err != nil {
		return nil, err
	}
	var evaluationErr error
	var grantSets map[string]map[string]record.GrantRef
	grants := func(id string) []record.GrantRef {
		if evaluationErr != nil {
			return nil
		}
		if grantSets == nil {
			var err error
			grantSets, err = m.grantSetsContext(ctx)
			if err != nil {
				evaluationErr = err
				return nil
			}
		}
		gs, err := sortedGrants(ctx, grantSets[id])
		if err != nil {
			evaluationErr = err
		}
		return gs
	}
	hasGrant := func(id, tenant string) bool {
		for _, g := range grants(id) {
			if err := ctx.Err(); err != nil {
				return false
			}
			if g.Tenant == tenant {
				return true
			}
		}
		return false
	}
	deps := map[string][]string{}
	reverse := map[string][]string{}
	eventItems := map[string]*Item{}
	for id, it := range m.items {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(it.Events) > 0 {
			eventItems[id] = it
		}
		deps[id] = m.depsOf(it)
		for _, d := range deps[id] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			reverse[d] = append(reverse[d], id)
		}
	}
	ev := &Eval{OwnerPending: map[string]bool{}, ControlComplete: map[string]bool{}, Tombs: map[string]Tomb{}, causeRefs: map[string][]*causeSet{}, causeCounts: map[string]int{}, rootSets: map[string][]*causeSet{}, causeSetOf: map[string]*causeSet{}, deps: deps, reverse: reverse, Status: map[string]Status{}, HoldCauses: map[string][]string{}, EventBans: map[string]bool{}}
	cids := make([]string, 0, len(m.controls))
	for id := range m.controls {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cids = append(cids, id)
	}
	sort.Strings(cids)
	// Authenticated supplemental coverage can complete earlier controls, without
	// requiring the receiver to possess a private signing key.
	signedBans := map[string]bool{}
	coveredSessions := map[string]bool{}
	for _, c := range m.controls {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if c.Erasure != nil {
			for _, session := range c.Erasure.Selectors.Sessions {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				coveredSessions[c.Owner+"\x00"+session] = true
			}
			for _, e := range c.Erasure.Selectors.Events {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				signedBans[eventBanKey(e.Owner, e.SessionKey, e.EventID)] = true
				ev.EventBans[eventBanKey(e.Owner, e.SessionKey, e.EventID)] = true
			}
		}
	}
	// Controls with identical selectors share reachability and one cause set.
	// Signed IDs remain independent causes and are never discarded.
	groups := map[string]*controlGroup{}
	ordered := []*controlGroup{}
	for _, cid := range cids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c := *m.controls[cid]
		c.ID = ""
		raw, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		key := string(raw)
		g := groups[key]
		if g == nil {
			if err := reserveEvaluation(ctx, 256+len(key)); err != nil {
				return nil, err
			}
			g = &controlGroup{control: m.controls[cid]}
			groups[key] = g
			ordered = append(ordered, g)
		}
		if err := reserveEvaluation(ctx, 32); err != nil {
			return nil, err
		}
		g.causes = append(g.causes, Tomb{Cause: cid})
	}
	roots := map[string]map[string]bool{}
	rootClosure := func(seeds []string) (map[string]bool, error) {
		if len(seeds) == 1 {
			if found := roots[seeds[0]]; found != nil {
				return found, nil
			}
			found, err := closureContext(ctx, reverse, seeds)
			if err != nil {
				return nil, err
			}
			roots[seeds[0]] = found
			return found, nil
		}
		return closureContext(ctx, reverse, seeds)
	}
	var rootIndexed []*causeSet
	for _, group := range ordered {
		cid := group.control.ID

		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c := m.controls[cid]
		kind := map[record.Kind]TombKind{record.KindErasure: Erased, record.KindRetraction: Retracted, record.KindWithdrawal: Withdrawn}[c.Kind]
		tenant, tsk := c.byTenant()
		seeds, err := m.seeds(ctx, c, hasGrant, grants)
		if err != nil {
			return nil, err
		}
		if c.Kind != record.KindErasure {
			// Exact retraction/withdrawal targets are the closure of their seeds.
			// Attach one shared set to each seed root; tombs are propagated once
			// per tenant domain below, independent of the number of controls.
			set := &causeSet{causes: group.causes, tenant: tenant, tsk: tsk, seeds: seeds}
			if err := reserveEvaluation(ctx, 16*len(seeds)+48*len(set.causes)); err != nil {
				return nil, err
			}
			for n := range set.causes {
				set.causes[n].Kind = kind
				ev.causeSetOf[set.causes[n].Cause] = set
			}
			for _, root := range seeds {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				ev.rootSets[root] = append(ev.rootSets[root], set)
			}
			rootIndexed = append(rootIndexed, set)
			continue
		}
		targets, err := rootClosure(seeds)
		if err != nil {
			return nil, err
		}
		if c.Kind == record.KindErasure {
			// Expansion owns its target set; the root cache stays immutable.
			if len(eventItems) > 0 {
				copyTargets := map[string]bool{}
				for id := range targets {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					if err := reserveEvaluation(ctx, 96); err != nil {
						return nil, err
					}
					copyTargets[id] = true
				}
				targets = copyTargets
			}
			controlBans := map[string]bool{}
			for _, e := range c.Erasure.Selectors.Events {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				controlBans[eventBanKey(e.Owner, e.SessionKey, e.EventID)] = true
			}
			ev.ControlComplete[cid] = true
			changed := true
			for changed {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				changed = false
				for id := range targets {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					it := m.items[id]
					if it == nil || tsk && !hasGrant(id, tenant) {
						continue
					}
					// A signed session ban covers every possible member without
					// recovering the body. Unknown scope still requires a hold.
					if (it.Kind == record.KindChunk || it.Kind == record.KindSession) && !it.EventMembershipComplete && !(it.SessionKey != "" && coveredSessions[it.Owner+"\x00"+it.SessionKey]) {
						ev.OwnerPending[c.Owner] = true
						ev.ControlComplete[cid] = false
					}
					for _, eventID := range it.Events {
						if err := ctx.Err(); err != nil {
							return nil, err
						}
						key := eventBanKey(it.Owner, it.SessionKey, eventID)
						if !signedBans[key] && !(it.SessionKey != "" && coveredSessions[it.Owner+"\x00"+it.SessionKey]) {
							ev.OwnerPending[c.Owner] = true
							ev.ControlComplete[cid] = false
						}
						if !controlBans[key] {
							if err := reserveEvaluation(ctx, 192); err != nil {
								return nil, err
							}
							controlBans[key] = true
							ev.EventBans[key] = true
							changed = true
						}
					}
				}
				for id, it := range eventItems {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					if targets[id] || tsk && !hasGrant(id, tenant) {
						continue
					}
					for _, eventID := range it.Events {
						if err := ctx.Err(); err != nil {
							return nil, err
						}
						if controlBans[eventBanKey(it.Owner, it.SessionKey, eventID)] {
							if err := reserveEvaluation(ctx, 96); err != nil {
								return nil, err
							}
							targets[id] = true
							changed = true
						}
					}
				}
				if changed {
					seeds := []string{}
					for id := range targets {
						if err := ctx.Err(); err != nil {
							return nil, err
						}
						seeds = append(seeds, id)
					}
					targets, err = closureContext(ctx, reverse, seeds)
					if err != nil {
						return nil, err
					}
				}
			}
		}
		set := &causeSet{causes: group.causes}
		for n := range set.causes {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			set.causes[n].Kind = kind
			if c.Kind == record.KindErasure {
				ev.ControlComplete[set.causes[n].Cause] = ev.ControlComplete[cid]
			}
		}
		count := 0
		for id := range targets {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if tsk && !hasGrant(id, tenant) {
				continue
			}
			t := Tomb{Kind: kind, Cause: cid}
			if err := reserveEvaluation(ctx, 24); err != nil {
				return nil, err
			}
			ev.causeRefs[id] = append(ev.causeRefs[id], set)
			count++
			old, ok := ev.Tombs[id]
			if !ok || rank(kind) > rank(old.Kind) || (rank(kind) == rank(old.Kind) && cid < old.Cause) {
				ev.Tombs[id] = t
			}
		}
		for _, cause := range set.causes {
			ev.causeCounts[cause.Cause] = count
		}
	}
	if err := m.propagateRootTombs(ctx, ev, rootIndexed, grants); err != nil {
		return nil, err
	}
	if evaluationErr != nil {
		return nil, evaluationErr
	}
	ev.grantSets = grantSets // tenant-filtered root causes read these immutable sets
	// Calls require the COMPLETE recursive signed graph, including every origin.
	// The ordinary metadata-origin exception cannot make a comparator usable.
	strictMemo := map[string]bool{}
	var strictPending func(string, map[string]bool) bool
	strictPending = func(id string, path map[string]bool) (result bool) {
		if v, ok := strictMemo[id]; ok {
			return v
		}
		defer func() { strictMemo[id] = result }()
		if ctx.Err() != nil {
			return true
		}
		if path[id] {
			return true
		}
		it := m.items[id]
		if it == nil {
			return ev.Tombs[id] == (Tomb{})
		}
		if it.Kind == record.KindCall && !it.BodyAvailable {
			return true
		}
		path[id] = true
		defer delete(path, id)
		for _, d := range m.depsOf(it) {
			if ctx.Err() != nil {
				return true
			}
			if strictPending(d, path) {
				return true
			}
		}
		return false
	}
	// A dependency cycle is unresolved, not a proof of complete ancestry.
	pending := map[string]bool{}
	var visit func(string, map[string]bool) bool
	visit = func(id string, path map[string]bool) bool {
		if ctx.Err() != nil {
			return true
		}
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
		res := it.Route == record.RouteHostedPull && len(m.directGrants[id]) == 0 || it.Kind == record.KindCall && !it.BodyAvailable
		pendingDeps := append([]string(nil), it.Deps...)
		if it.Origin != "" && (m.items[it.Origin] != nil || it.Kind == record.KindCall) {
			pendingDeps = append(pendingDeps, it.Origin)
		}
		for _, d := range pendingDeps {
			if ctx.Err() != nil {
				return true
			}
			if visit(d, path) {
				res = true
			}
		}
		for _, e := range m.exposures {
			if ctx.Err() != nil {
				return true
			}
			if m.downstreamContext(ctx, it, e) && ev.Tombs[e.ID] == (Tomb{}) && visit(e.ID, path) {
				res = true
			}
		}
		if it.Kind == record.KindCall && strictPending(id, map[string]bool{}) {
			res = true
		}
		pending[id] = res
		return res
	}
	// Semantic holds propagate through both copied and recalled lineage. Keep
	// every underlying cause even when an intermediate record was reviewed/released.
	holds := map[string]map[string]bool{}
	exposureCauses := map[string][]Tomb{}
	for id := range m.items {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		holds[id] = map[string]bool{}
	}
	changed := true
	for changed {
		if evaluationErr != nil {
			return nil, evaluationErr
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		changed = false
		for id, it := range m.items {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			add := func(token string) {
				if !holds[id][token] {
					if err := reserveEvaluation(ctx, 96+len(token)); err != nil {
						evaluationErr = err
						return
					}
					holds[id][token] = true
					changed = true
				}
			}
			for _, d := range m.depsOf(it) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				for token := range holds[d] {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					add(token)
				}
			}
			for _, e := range m.exposures {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if !m.downstreamContext(ctx, it, e) {
					continue
				}
				causes, ok := exposureCauses[e.ID]
				if !ok {
					var err error
					if causes, err = ev.causesOfContext(ctx, e.ID); err != nil {
						return nil, err
					}
					if err := reserveEvaluation(ctx, 64+24*len(causes)); err != nil {
						return nil, err
					}
					exposureCauses[e.ID] = causes
				}
				for _, cause := range causes {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					add(e.ID + "/" + cause.Cause)
				}
				for token := range holds[e.ID] {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					add(token)
				}
			}
		}
	}
	for id, tokens := range holds {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for token := range tokens {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			ev.HoldCauses[id] = append(ev.HoldCauses[id], token)
		}
		sort.Strings(ev.HoldCauses[id])
	}
	for id, it := range m.items {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		switch {
		case ev.Tombs[id] != (Tomb{}):
			ev.Status[id] = Invalidated
		case ev.OwnerPending[it.Owner]:
			ev.Status[id] = LineageHold
		case m.hasUnreleasedExposure(it, ev):
			ev.Status[id] = LineageHold
		case visit(id, map[string]bool{}):
			ev.Status[id] = AncestryPending
		default:
			ev.Status[id] = Live
		}
	}
	if evaluationErr != nil {
		return nil, evaluationErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ev.grantSets = grantSets
	m.cached = ev
	return ev, nil
}

// propagateRootTombs assigns each record the best root-indexed tomb. Roots are
// visited best tomb first and every record is visited once per tenant domain,
// so the cost is the graph size, not controls times descendants.
func (m *Model) propagateRootTombs(ctx context.Context, ev *Eval, sets []*causeSet, grants func(string) []record.GrantRef) error {
	type rootTomb struct {
		root string
		tomb Tomb
	}
	domains := map[string][]rootTomb{}
	order := []string{}
	for _, set := range sets {
		if err := ctx.Err(); err != nil {
			return err
		}
		domain := "device"
		if set.tsk {
			domain = "tenant:" + set.tenant
			grants("") // grant sets are required to filter tenant targets
		}
		if domains[domain] == nil {
			order = append(order, domain)
		}
		// group.causes are in sorted control order; the first is the lowest id.
		best := set.causes[0]
		for _, root := range set.seeds {
			if err := reserveEvaluation(ctx, 48); err != nil {
				return err
			}
			domains[domain] = append(domains[domain], rootTomb{root, best})
		}
	}
	for _, domain := range order {
		roots := domains[domain]
		sort.SliceStable(roots, func(i, j int) bool {
			a, b := roots[i].tomb, roots[j].tomb
			if rank(a.Kind) != rank(b.Kind) {
				return rank(a.Kind) > rank(b.Kind)
			}
			return a.Cause < b.Cause
		})
		tenant, tsk := strings.CutPrefix(domain, "tenant:")
		visited := map[string]bool{}
		for _, rt := range roots {
			todo := []string{rt.root}
			for len(todo) > 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
				id := todo[len(todo)-1]
				todo = todo[:len(todo)-1]
				if visited[id] {
					continue
				}
				if err := reserveEvaluation(ctx, 96+16*len(ev.reverse[id])); err != nil {
					return err
				}
				visited[id] = true
				todo = append(todo, ev.reverse[id]...)
				if tsk {
					granted := false
					for _, g := range grants(id) {
						if g.Tenant == tenant {
							granted = true
						}
					}
					if !granted {
						continue
					}
				}
				old, ok := ev.Tombs[id]
				t := rt.tomb
				if !ok || rank(t.Kind) > rank(old.Kind) || (rank(t.Kind) == rank(old.Kind) && t.Cause < old.Cause) {
					ev.Tombs[id] = t
				}
			}
		}
	}
	return ctx.Err()
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
	ev, err := m.evaluateContext(context.Background())
	if err != nil || m.items[id] == nil {
		return
	}
	if m.released[id] == nil {
		m.released[id] = map[string]bool{}
	}
	for _, token := range ev.HoldCauses[id] {
		if !m.released[id][token] {
			m.cached = nil
		}
		m.released[id][token] = true
	}
}
func (e *Eval) StatusOf(id string) Status {
	if e == nil || e.err != nil {
		return LineageHold
	}
	if s, ok := e.Status[id]; ok {
		return s
	}
	return Absent
}
func (m *Model) ExportEligible(id string) bool {
	ev, err := m.evaluateContext(context.Background())
	if err != nil {
		return false
	}
	return ev.StatusOf(id) == Live && len(m.Grants(id)) == 0
}

const OpCacheFixedResult = `{"isError":false,"content":[{"type":"text","text":"The operation was recorded, but its prior memory content is no longer available to this caller."}]}`

func eventBanKey(owner, session, eventID string) string {
	return record.H("erased-event", owner, session, eventID)
}

// EventErased must be checked before capture sealing; it retains only source identity.
func (m *Model) EventErased(owner, session, eventID string) bool {
	for _, c := range m.controls {
		if c.Erasure != nil && c.Owner == owner && contains(c.Erasure.Selectors.Sessions, session) {
			return true
		}
	}
	ev := m.Evaluate()
	return ev == nil || ev.Err() != nil || ev.EventBans[eventBanKey(owner, session, eventID)]
}

func eventSelectorMatches(xs []record.EventSelector, it *Item) bool {
	for _, e := range xs {
		if e.Owner == it.Owner && e.SessionKey == it.SessionKey && contains(it.Events, e.EventID) {
			return true
		}
	}
	return false
}
func sessionCovered(controls map[string]*Control, owner, session string) bool {
	if session == "" {
		return false
	}
	for _, c := range controls {
		if c.Erasure != nil && c.Owner == owner && contains(c.Erasure.Selectors.Sessions, session) {
			return true
		}
	}
	return false
}
