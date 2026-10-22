package invalidate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

func hx(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

const G = "a91c0e00112233445566778899aabbcc" // this node's genesis

func item(name string, deps ...string) Item {
	var d []string
	for _, x := range deps {
		d = append(d, hx(x))
	}
	return Item{ID: hx(name), LID: hx("lid-" + name), Kind: record.KindDigest, Prov: record.ProvDerived, Owner: G, Deps: d, Route: record.RouteLocal}
}

func erase(name string, sel record.Selectors) Control {
	return Control{ID: hx("ctl-" + name), Kind: record.KindErasure, Owner: G, Erasure: &record.ErasureBody{Selectors: sel, Reason: "user_request"}}
}

type event struct {
	item *Item
	ctl  *Control
}

func run(events []event) *Eval {
	m := NewModel()
	for _, e := range events {
		if e.item != nil {
			m.Admit(*e.item)
		} else {
			m.Apply(*e.ctl)
		}
	}
	return m.Evaluate()
}

func perms(n int) [][]int {
	if n == 0 {
		return [][]int{{}}
	}
	var out [][]int
	for _, p := range perms(n - 1) {
		for i := 0; i <= len(p); i++ {
			q := append(append(append([]int(nil), p[:i]...), n-1), p[i:]...)
			out = append(out, q)
		}
	}
	return out
}

func TestClosure(t *testing.T) {
	deps := map[string][]string{"b": {"a"}, "c": {"b"}, "d": {"x"}, "e": {"c", "d"}}
	got := Closure(deps, []string{"a"})
	for _, want := range []string{"a", "b", "c", "e"} {
		if !got[want] {
			t.Errorf("missing %s", want)
		}
	}
	if got["d"] || got["x"] || len(got) != 4 {
		t.Fatalf("%v", got)
	}
	if len(Closure(deps, nil)) != 0 {
		t.Fatal("empty seeds")
	}
}

func TestErasureChainEveryOrder(t *testing.T) {
	a, b, c := item("A"), item("B", "A"), item("C", "B")
	e := erase("A", record.Selectors{IDs: []string{a.ID}})
	events := []event{{item: &a}, {item: &b}, {item: &c}, {ctl: &e}}
	for _, p := range perms(len(events)) {
		var order []event
		for _, i := range p {
			order = append(order, events[i])
		}
		ev := run(order)
		for _, id := range []string{a.ID, b.ID, c.ID} {
			if ev.StatusOf(id) != Invalidated || ev.Tombs[id].Kind != Erased || ev.Tombs[id].Cause != e.ID {
				t.Fatalf("order %v: %s %s %+v", p, id[:6], ev.StatusOf(id), ev.Tombs[id])
			}
		}
	}
}

func TestErasureSelectorKinds(t *testing.T) {
	base := Item{Kind: record.KindChunk, Prov: record.ProvTranscript, Owner: G, Route: record.RouteLocal,
		TaskID: "3f2a91c0-1111-4222-8333-444455556666", SessionKey: "sk1:" + hx("s"), Source: hx("src")}
	cases := map[string]record.Selectors{
		"ids":      {IDs: []string{hx("r")}},
		"lids":     {LIDs: []string{hx("l")}},
		"tasks":    {Tasks: []string{base.TaskID}},
		"sessions": {Sessions: []string{base.SessionKey}},
		"sources":  {Sources: []string{base.Source}},
	}
	for name, sel := range cases {
		r := base
		r.ID, r.LID = hx("r"), hx("l")
		other := item("other")
		e := erase(name, sel)
		for _, order := range [][]event{{{item: &r}, {item: &other}, {ctl: &e}}, {{ctl: &e}, {item: &other}, {item: &r}}} {
			ev := run(order)
			if ev.StatusOf(r.ID) != Invalidated || ev.StatusOf(other.ID) != Live {
				t.Errorf("%s: %s %s", name, ev.StatusOf(r.ID), ev.StatusOf(other.ID))
			}
		}
	}
}

func TestAncestryPendingAndRebuild(t *testing.T) {
	a, b, c := item("A"), item("B", "A"), item("C", "B")
	m := NewModel()
	m.Admit(a)
	m.Admit(c)
	if s := m.Evaluate().StatusOf(c.ID); s != AncestryPending {
		t.Fatalf("C without B: %s", s)
	}
	m.Admit(b)
	if s := m.Evaluate().StatusOf(c.ID); s != Live {
		t.Fatalf("C after B: %s", s)
	}
	// origin absence never makes a record pending
	v := item("V")
	v.Origin = hx("not-here")
	m.Admit(v)
	if s := m.Evaluate().StatusOf(v.ID); s != Live {
		t.Fatalf("variant: %s", s)
	}
	// erase B: C invalidated; a digest rebuilt from survivors is admitted live
	e := erase("B", record.Selectors{IDs: []string{b.ID}})
	m.Apply(e)
	rebuilt := item("C2", "A")
	rebuilt.LID = c.LID
	m.Admit(rebuilt)
	ev := m.Evaluate()
	if ev.StatusOf(c.ID) != Invalidated || ev.StatusOf(rebuilt.ID) != Live || ev.StatusOf(a.ID) != Live {
		t.Fatalf("%s %s %s", ev.StatusOf(c.ID), ev.StatusOf(rebuilt.ID), ev.StatusOf(a.ID))
	}
	// a pending record whose missing dep gets erased is invalidated
	p := item("P", "missing")
	m.Admit(p)
	m.Apply(erase("missing", record.Selectors{IDs: []string{hx("missing")}}))
	m.Admit(item("missing"))
	if s := m.Evaluate().StatusOf(p.ID); s != Invalidated {
		t.Fatalf("pending descendant of erased: %s", s)
	}
}

func TestRetractionClosureAndReplacement(t *testing.T) {
	src := item("src")
	digest := item("digest", "src")
	variant := item("variant")
	variant.Origin = src.ID
	m := NewModel()
	for _, it := range []Item{src, digest, variant} {
		m.Admit(it)
	}
	m.Apply(Control{ID: hx("ret"), Kind: record.KindRetraction, Owner: G, Retraction: &record.RetractionBody{IDs: []string{src.ID}, Reason: "redaction_repair"}})
	repl := item("src-v2")
	repl.LID = src.LID
	m.Admit(repl)
	ev := m.Evaluate()
	for _, id := range []string{src.ID, digest.ID, variant.ID} {
		if ev.StatusOf(id) != Invalidated || ev.Tombs[id].Kind != Retracted {
			t.Fatalf("%s %s", id[:6], ev.StatusOf(id))
		}
	}
	if ev.StatusOf(repl.ID) != Live {
		t.Fatal("a replacement with the same LID is admitted")
	}
}

func TestAuthority(t *testing.T) {
	gw := item("gw")
	gw.Prov, gw.Owner, gw.Route, gw.RouteTenant = record.ProvGateway, "tenant:acme", record.RouteHostedPull, "acme"
	mine := item("mine")
	theirs := item("theirs")
	theirs.Owner = "tenant:acme"
	theirs.Prov = record.ProvGateway
	m := NewModel()
	for _, it := range []Item{gw, mine, theirs} {
		m.Admit(it)
	}
	// TSK erasure may target gateway records of its tenant only (with grant)
	m.Apply(Control{ID: hx("e1"), Kind: record.KindErasure, Owner: "tenant:acme",
		Erasure: &record.ErasureBody{Selectors: record.Selectors{IDs: []string{gw.ID, mine.ID, theirs.ID}}, Reason: "user_request"}})
	ev := m.Evaluate()
	if ev.StatusOf(gw.ID) != Invalidated || ev.StatusOf(mine.ID) != Live || ev.StatusOf(theirs.ID) != Live {
		t.Fatalf("TSK erasure: %s %s %s", ev.StatusOf(gw.ID), ev.StatusOf(mine.ID), ev.StatusOf(theirs.ID))
	}
	// retraction by another owner does nothing; a device may not withdraw
	m.Apply(Control{ID: hx("r1"), Kind: record.KindRetraction, Owner: "b0000000000000000000000000000000",
		Retraction: &record.RetractionBody{IDs: []string{mine.ID}, Reason: "rule_removed"}})
	m.Apply(Control{ID: hx("w1"), Kind: record.KindWithdrawal, Owner: G,
		Withdrawal: &record.WithdrawalBody{Tenant: "acme", All: true, Reason: "user_removed"}})
	if s := m.Evaluate().StatusOf(mine.ID); s != Live {
		t.Fatalf("unauthorised control applied: %s", s)
	}
	// device erasure may target gateway records in its stream
	m.Apply(erase("dev", record.Selectors{IDs: []string{theirs.ID}}))
	if s := m.Evaluate().StatusOf(theirs.ID); s != Invalidated {
		t.Fatalf("device erasure of gateway record: %s", s)
	}
}

func TestWithdrawalByGrant(t *testing.T) {
	pulled := item("pulled")
	pulled.Route, pulled.RouteTenant, pulled.Owner = record.RouteHostedPull, "acme", "tenant:acme"
	digest := item("digest", "pulled") // local derivative inherits the grant
	local := item("local")
	bundled := item("bundled", "pulled") // arrived by another route; grant follows content
	bundled.Route = record.RouteBundleImport
	m := NewModel()
	for _, it := range []Item{pulled, digest, local, bundled} {
		m.Admit(it)
	}
	if g := m.Grants(digest.ID); len(g) != 1 || g[0] != "tenant:acme" {
		t.Fatalf("grants %v", g)
	}
	w := Control{ID: hx("w"), Kind: record.KindWithdrawal, Owner: "tenant:acme",
		Withdrawal: &record.WithdrawalBody{Tenant: "acme", PolicySeq: 4, All: true, Reason: "policy_narrowed"}}
	m.Apply(w)
	reissued := item("pulled-v2")
	reissued.Route, reissued.RouteTenant, reissued.Owner = record.RouteHostedPull, "acme", "tenant:acme"
	m.Admit(reissued)
	ev := m.Evaluate()
	for _, id := range []string{pulled.ID, digest.ID, bundled.ID} {
		if ev.StatusOf(id) != Invalidated || ev.Tombs[id].Kind != Withdrawn {
			t.Fatalf("%s %s", id[:6], ev.StatusOf(id))
		}
	}
	if ev.StatusOf(local.ID) != Live || ev.StatusOf(reissued.ID) != Live {
		t.Fatal("local-only and re-issued records are kept")
	}
	// withdrawal by exact id is permanent for that id, whenever it arrives
	m2 := NewModel()
	m2.Apply(Control{ID: hx("w2"), Kind: record.KindWithdrawal, Owner: "tenant:acme",
		Withdrawal: &record.WithdrawalBody{Tenant: "acme", IDs: []string{pulled.ID}, Reason: "user_removed"}})
	m2.Admit(pulled)
	if s := m2.Evaluate().StatusOf(pulled.ID); s != Invalidated {
		t.Fatalf("late arrival of a withdrawn id: %s", s)
	}
}

func TestLineageHold(t *testing.T) {
	a := item("A")
	sk := "sk1:" + hx("S")
	chunk := Item{ID: hx("chunk"), LID: hx("cl"), Kind: record.KindChunk, Prov: record.ProvTranscript, Owner: G, SessionKey: sk,
		Recalls: []Recall{{Seq: 5, ID: a.ID}}, Route: record.RouteLocal}
	later := Item{ID: hx("concl"), LID: hx("c1"), Kind: record.KindConclusion, Prov: record.ProvTranscript, Owner: G, SessionKey: sk, SessionSeq: 9}
	earlier := Item{ID: hx("concl0"), LID: hx("c0"), Kind: record.KindConclusion, Prov: record.ProvTranscript, Owner: G, SessionKey: sk, SessionSeq: 3}
	m := NewModel()
	for _, it := range []Item{a, chunk, later, earlier} {
		m.Admit(it)
	}
	m.Deliver(Delivered{Scope: "stdio:claude-code", ID: a.ID, Seq: m.AdmittedSeq(a.ID)})
	explicit := Item{ID: hx("cp"), LID: hx("cpl"), Kind: record.KindCheckpoint, Prov: record.ProvMCPExplicit, Owner: G, Scope: "stdio:claude-code", Explicit: true}
	m.Admit(explicit)
	if s := m.Evaluate().StatusOf(later.ID); s != Live {
		t.Fatalf("before erasure: %s", s)
	}
	m.Apply(erase("A", record.Selectors{IDs: []string{a.ID}}))
	ev := m.Evaluate()
	if ev.StatusOf(a.ID) != Invalidated || ev.StatusOf(later.ID) != LineageHold || ev.StatusOf(earlier.ID) != Live ||
		ev.StatusOf(explicit.ID) != LineageHold || ev.StatusOf(chunk.ID) != Live {
		t.Fatalf("a=%s later=%s earlier=%s explicit=%s chunk=%s", ev.StatusOf(a.ID), ev.StatusOf(later.ID),
			ev.StatusOf(earlier.ID), ev.StatusOf(explicit.ID), ev.StatusOf(chunk.ID))
	}
	m.Release(later.ID)
	if s := m.Evaluate().StatusOf(later.ID); s != Live {
		t.Fatalf("released: %s", s)
	}
}

func TestOpCacheRows(t *testing.T) {
	cp := item("checkpoint")
	row := Item{ID: "op:" + hx("op"), OpRow: true, Deps: []string{cp.ID}}
	m := NewModel()
	m.Admit(cp)
	m.Admit(row)
	m.Apply(erase("cp", record.Selectors{IDs: []string{cp.ID}}))
	if s := m.Evaluate().StatusOf(row.ID); s != Invalidated {
		t.Fatalf("op row: %s", s)
	}
	// op rows are never matched by selectors directly
	m2 := NewModel()
	m2.Admit(row)
	m2.Apply(erase("row", record.Selectors{IDs: []string{row.ID}}))
	if s := m2.Evaluate().StatusOf(row.ID); s == Invalidated {
		t.Fatal("op row targeted directly")
	}
}

// Random DAGs and controls: every arrival order yields the same statuses.
func TestOrderIndependenceProperty(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for trial := 0; trial < 60; trial++ {
		n := 4 + r.Intn(6)
		var items []Item
		for i := 0; i < n; i++ {
			var deps []string
			for j := 0; j < i; j++ {
				if r.Intn(3) == 0 {
					deps = append(deps, fmt.Sprint(j))
				}
			}
			it := item(fmt.Sprint(i), deps...)
			it.SessionKey = "sk1:" + hx(fmt.Sprint(i%2))
			items = append(items, it)
		}
		var ctls []Control
		for k := 0; k < 1+r.Intn(3); k++ {
			target := items[r.Intn(n)]
			if r.Intn(2) == 0 {
				ctls = append(ctls, erase(fmt.Sprint(trial, k), record.Selectors{IDs: []string{target.ID}}))
			} else {
				ctls = append(ctls, Control{ID: hx(fmt.Sprint("ret", trial, k)), Kind: record.KindRetraction, Owner: G,
					Retraction: &record.RetractionBody{IDs: []string{target.ID}, Reason: "rule_removed"}})
			}
		}
		var events []event
		for i := range items {
			events = append(events, event{item: &items[i]})
		}
		for i := range ctls {
			events = append(events, event{ctl: &ctls[i]})
		}
		var ref string
		for k := 0; k < 40; k++ {
			order := append([]event(nil), events...)
			r.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
			ev := run(order)
			got := fmt.Sprint(ev.Status, ev.Tombs)
			if ref == "" {
				ref = got
			} else if got != ref {
				t.Fatalf("trial %d: order dependence", trial)
			}
		}
	}
}
