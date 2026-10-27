package invalidate

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// randomModelR17 builds DAGs with device and tenant owners, hosted grants,
// events, exposures, absent exact targets and overlapping/duplicate controls.
func randomModelR17(seed int64) *Model {
	r := rand.New(rand.NewSource(seed))
	m := NewModel()
	n := 8 + r.Intn(30)
	ids := []string{}
	for i := 0; i < n; i++ {
		it := Item{ID: hx(fmt.Sprint(seed, "-item-", i)), LID: hx(fmt.Sprint(seed, "-lid-", i)), Kind: record.KindDigest, Prov: record.ProvDerived, Owner: G, Route: record.RouteLocal, EventMembershipComplete: true}
		for _, p := range r.Perm(len(ids))[:min(len(ids), r.Intn(3))] {
			it.Deps = append(it.Deps, ids[p])
		}
		if r.Intn(9) == 0 {
			it.Deps = append(it.Deps, hx(fmt.Sprint(seed, "-absent-", r.Intn(4))))
		}
		switch r.Intn(6) {
		case 0:
			it.Prov, it.Owner, it.Route, it.RouteTenant, it.GrantGeneration = record.ProvGateway, "tenant:acme", record.RouteHostedPull, "acme", int64(1+r.Intn(5))
		case 1:
			it.Kind, it.SessionKey = record.KindSession, fmt.Sprint("s", r.Intn(3))
			it.Events = []string{fmt.Sprint("e", r.Intn(4))}
			it.EventMembershipComplete = r.Intn(3) != 0
		case 2:
			it.SessionKey, it.SessionSeq = fmt.Sprint("s", r.Intn(3)), int64(r.Intn(5))
		}
		m.Admit(it)
		ids = append(ids, it.ID)
	}
	pick := func() string {
		if r.Intn(7) == 0 {
			return hx(fmt.Sprint(seed, "-absent-", r.Intn(4)))
		}
		return ids[r.Intn(len(ids))]
	}
	for c := 0; c < 2+r.Intn(14); c++ {
		id := hx(fmt.Sprint(seed, "-control-", c))
		targets := []string{pick()}
		for r.Intn(3) == 0 {
			targets = append(targets, pick())
		}
		reason := []string{"redaction_repair", "rule_removed"}[r.Intn(2)]
		if r.Intn(3) == 0 {
			targets = []string{ids[0]} // overlapping controls on one root
		}
		switch r.Intn(5) {
		case 0, 1:
			_ = m.Apply(Control{ID: id, Kind: record.KindRetraction, Owner: G, Retraction: &record.RetractionBody{IDs: targets, Reason: reason}})
		case 2:
			sel := record.Selectors{IDs: targets}
			if r.Intn(4) == 0 {
				sel.Events = []record.EventSelector{{Owner: G, SessionKey: "s0", EventID: "e1"}}
			}
			_ = m.Apply(Control{ID: id, Kind: record.KindErasure, Owner: G, Erasure: &record.ErasureBody{EventCoverage: "complete", Selectors: sel, Reason: "user_request"}})
		case 3:
			_ = m.Apply(Control{ID: id, Kind: record.KindWithdrawal, Owner: "tenant:acme", Withdrawal: &record.WithdrawalBody{Tenant: "acme", PolicySeq: int64(1 + r.Intn(5)), IDs: targets, All: r.Intn(2) == 0, Reason: "offboarded"}})
		default:
			_ = m.Apply(Control{ID: id, Kind: record.KindRetraction, Owner: "tenant:acme", Retraction: &record.RetractionBody{IDs: targets, Reason: reason}})
		}
	}
	for e := 0; e < r.Intn(4); e++ {
		x := Exposure{ID: ids[r.Intn(len(ids))], SessionKey: fmt.Sprint("s", r.Intn(3)), Seq: int64(r.Intn(4))}
		if r.Intn(2) == 0 {
			x.AffectsIDs = []string{ids[r.Intn(len(ids))]}
		}
		m.Expose(x)
	}
	return m
}

// evalDigestR17 is an order-independent rendering of every evaluation output.
func evalDigestR17(m *Model, ev *Eval) string {
	var lines []string
	add := func(format string, a ...any) { lines = append(lines, fmt.Sprintf(format, a...)) }
	keys := map[string]bool{}
	for id := range m.items {
		keys[id] = true
		for _, d := range m.items[id].Deps {
			keys[d] = true
		}
	}
	for id := range ev.Tombs {
		keys[id] = true
	}
	for id := range keys {
		add("tomb %s %v", id, ev.Tombs[id])
		add("status %s %s", id, ev.Status[id])
		add("holds %s %v", id, ev.HoldCauses[id])
		causes := ev.CausesOf(id)
		sort.Slice(causes, func(i, j int) bool {
			if causes[i].Cause != causes[j].Cause {
				return causes[i].Cause < causes[j].Cause
			}
			return causes[i].Kind < causes[j].Kind
		})
		add("causes %s %v", id, causes)
	}
	for cid := range m.controls {
		add("count %s %d", cid, ev.CauseCount(cid))
		add("complete %s %v", cid, ev.ControlComplete[cid])
	}
	for owner, v := range ev.OwnerPending {
		add("pending %s %v", owner, v)
	}
	for ban, v := range ev.EventBans {
		add("ban %s %v", ban, v)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// referenceCausesR17 is the pre-compaction definition for non-erasure
// controls: one explicit closure per control, one cause per descendant.
func referenceCausesR17(t *testing.T, m *Model) (map[string]map[string]bool, map[string]int) {
	causes, counts := map[string]map[string]bool{}, map[string]int{}
	deps := map[string][]string{}
	for id, it := range m.items {
		deps[id] = m.depsOf(it)
	}
	for cid, c := range m.controls {
		if c.Kind == record.KindErasure {
			continue
		}
		seeds, err := m.seeds(context.Background(), c, m.hasGrant, m.Grants)
		parityNoError(t, err)
		tenant, tsk := c.byTenant()
		for id := range Closure(deps, seeds) {
			if tsk && !m.hasGrant(id, tenant) {
				continue
			}
			if causes[id] == nil {
				causes[id] = map[string]bool{}
			}
			causes[id][cid] = true
			counts[cid]++
		}
	}
	return causes, counts
}

func TestCompactCausesMatchExplicitClosuresR17(t *testing.T) {
	covered := map[string]int{}
	for seed := int64(1); seed <= 400; seed++ {
		m := randomModelR17(seed)
		ev, err := m.EvaluateContext(context.Background())
		parityNoError(t, err, "seed %d", seed)
		want, counts := referenceCausesR17(t, m)
		for cid, c := range m.controls {
			if c.Kind == record.KindErasure {
				continue
			}
			parityEqual(t, counts[cid], ev.CauseCount(cid), "seed %d count %s", seed, cid)
			covered["count"] += counts[cid]
		}
		ids := map[string]bool{}
		for id := range want {
			ids[id] = true
		}
		for id := range m.items {
			ids[id] = true
		}
		for id := range ids {
			got := map[string]bool{}
			for _, cause := range ev.CausesOf(id) {
				if m.controls[cause.Cause].Kind != record.KindErasure {
					got[cause.Cause] = true
				}
			}
			if want[id] == nil {
				want[id] = map[string]bool{}
			}
			parityEqual(t, want[id], got, "seed %d causes %s", seed, id)
			if len(got) > 1 {
				covered["overlap"]++
			}
			if strings.HasPrefix(m.controlsOwner(got), "tenant:") {
				covered["tenant"]++
			}
		}
	}
	t.Logf("coverage %v", covered)
	parityPositive(t, covered["overlap"])
	parityPositive(t, covered["tenant"])
}

func (m *Model) controlsOwner(cids map[string]bool) string {
	for cid := range cids {
		if strings.HasPrefix(m.controls[cid].Owner, "tenant:") {
			return m.controls[cid].Owner
		}
	}
	return ""
}
