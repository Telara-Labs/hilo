package invalidate

import (
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
)

func TestV3MissingMembershipSessionBanRecovery(t *testing.T) {
	for _, kind := range []record.Kind{record.KindChunk, record.KindSession} {
		for _, supplemental := range []bool{false, true} {
			t.Run(string(kind)+map[bool]string{false: "/direct", true: "/supplemental"}[supplemental], func(t *testing.T) {
				m := NewModel()
				session := "sk1:" + hx("unresolved-session")
				source := item("unknown-membership")
				source.Kind, source.SessionKey = kind, session
				survivor := item("survivor")
				m.Admit(source)
				m.Admit(survivor)
				primary := erase("primary", record.Selectors{IDs: []string{source.ID}})
				if supplemental {
					if err := m.Apply(primary); err != nil {
						t.Fatal(err)
					}
					ev := m.Evaluate()
					if !ev.OwnerPending[G] || ev.ControlComplete[primary.ID] || ev.StatusOf(survivor.ID) != LineageHold {
						t.Fatal("unavailable membership did not block owner")
					}
				}
				broad := erase("broad", record.Selectors{Sessions: []string{session}})
				if err := m.Apply(broad); err != nil {
					t.Fatal(err)
				}
				ev := m.Evaluate()
				if ev.OwnerPending[G] || !ev.ControlComplete[broad.ID] || supplemental && !ev.ControlComplete[primary.ID] || ev.StatusOf(survivor.ID) != Live || ev.StatusOf(source.ID) != Invalidated {
					t.Fatal("signed broader ban did not complete pending controls and release owner")
				}
				if !m.EventErased(G, session, "ev1:"+hx("never-seen-event")) {
					t.Fatal("broader session coverage lost future event ban")
				}
				if m.items[source.ID].EventMembershipComplete || len(m.items[source.ID].Events) != 0 {
					t.Fatal("recovery invented membership")
				}
			})
		}
	}
}

func TestV3MissingMembershipAllNamespacesRequired(t *testing.T) {
	m := NewModel()
	a, b := item("a"), item("b", "a")
	a.Kind, b.Kind = record.KindChunk, record.KindSession
	a.SessionKey, b.SessionKey = "sk1:"+hx("a"), "sk1:"+hx("b")
	a.Source, b.Source = hx("source"), hx("source")
	survivor := item("survivor")
	for _, it := range []Item{a, b, survivor} {
		m.Admit(it)
	}
	primary := erase("primary", record.Selectors{IDs: []string{a.ID}})
	if err := m.Apply(primary); err != nil {
		t.Fatal(err)
	}
	for i, c := range []Control{
		erase("source-only", record.Selectors{Sources: []string{hx("source")}}),
		erase("wrong-session", record.Selectors{Sessions: []string{"sk1:" + hx("other")}}),
		func() Control {
			c := erase("wrong-owner", record.Selectors{Sessions: []string{a.SessionKey, b.SessionKey}})
			c.Owner = "00112233445566778899aabbccddeeff"
			return c
		}(),
		erase("only-a", record.Selectors{Sessions: []string{a.SessionKey}}),
	} {
		if err := m.Apply(c); err != nil {
			t.Fatal(err)
		}
		ev := m.Evaluate()
		if !ev.OwnerPending[G] || ev.ControlComplete[primary.ID] || ev.StatusOf(survivor.ID) != LineageHold {
			t.Fatalf("insufficient coverage %d released owner", i)
		}
	}
	if err := m.Apply(erase("also-b", record.Selectors{Sessions: []string{b.SessionKey}})); err != nil {
		t.Fatal(err)
	}
	ev := m.Evaluate()
	if ev.OwnerPending[G] || !ev.ControlComplete[primary.ID] || ev.StatusOf(survivor.ID) != Live {
		t.Fatal("complete session namespace union did not recover owner")
	}
	// A newly discovered unresolved namespace reinstates the hold.
	late := item("late", "b")
	late.Kind = record.KindChunk
	late.SessionKey = "sk1:" + hx("late")
	m.Admit(late)
	if !m.Evaluate().OwnerPending[G] || m.Evaluate().ControlComplete[primary.ID] {
		t.Fatal("new unresolved closure namespace did not reblock completion")
	}
	if err := m.Apply(erase("also-late", record.Selectors{Sessions: []string{late.SessionKey}})); err != nil {
		t.Fatal(err)
	}
	if m.Evaluate().OwnerPending[G] || !m.Evaluate().ControlComplete[primary.ID] {
		t.Fatal("late namespace ban did not complete recovery")
	}
	unknown := item("unknown-scope", "late")
	unknown.Kind = record.KindChunk
	m.Admit(unknown)
	if !m.Evaluate().OwnerPending[G] || m.Evaluate().ControlComplete[primary.ID] {
		t.Fatal("unknown session scope inferred to be covered")
	}
}
