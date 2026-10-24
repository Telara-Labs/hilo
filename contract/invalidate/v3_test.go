package invalidate

import (
	"github.com/Telara-Labs/telara-memory/contract/record"
	"testing"
)

func TestV3SignedCrossDeviceEventErasure(t *testing.T) {
	session := "sk1:" + hx("session")
	eventID := "ev1:" + hx("native-event")
	sibling := item("device-b")
	sibling.Kind = record.KindChunk
	sibling.SessionKey = session
	sibling.Events = []string{eventID}
	sibling.EventMembershipComplete = true
	c := erase("remote-issuer", record.Selectors{IDs: []string{hx("unseen-device-a")}, Events: []record.EventSelector{{Owner: G, SessionKey: session, EventID: eventID}}})
	for _, controlFirst := range []bool{true, false} {
		m := NewModel()
		if controlFirst {
			if err := m.Apply(c); err != nil {
				t.Fatal(err)
			}
		}
		m.Admit(sibling)
		if !controlFirst {
			if err := m.Apply(c); err != nil {
				t.Fatal(err)
			}
		}
		if m.Evaluate().StatusOf(sibling.ID) != Invalidated || !m.EventErased(G, session, eventID) || m.EventErased(G, "sk1:"+hx("other"), eventID) {
			t.Fatal("signed namespace lost or broadened")
		}
		late := sibling
		late.ID = hx("repack-device-c")
		m.Admit(late)
		if m.Evaluate().StatusOf(late.ID) != Invalidated {
			t.Fatal("late event recapture")
		}
	}
	c.Owner = "tenant:acme"
	if NewModel().Apply(c) == nil {
		t.Fatal("TSK event scope spoof")
	}
	c.Owner = G
	c.Erasure.EventCoverage = ""
	if NewModel().Apply(c) == nil {
		t.Fatal("legacy incomplete control accepted")
	}
}
func TestV3SupplementalCoveragePendingAndRecovery(t *testing.T) {
	session := "sk1:" + hx("s")
	e1, e2 := "ev1:"+hx("e1"), "ev1:"+hx("e2")
	source := item("source")
	source.Kind = record.KindChunk
	source.EventMembershipComplete = true
	source.SessionKey = session
	source.Events = []string{e1, e2}
	sibling := item("sibling")
	sibling.Kind = record.KindChunk
	sibling.EventMembershipComplete = true
	sibling.SessionKey = session
	sibling.Events = []string{e1}
	other := item("same-owner-survivor")
	m := NewModel()
	m.Admit(source)
	m.Admit(sibling)
	m.Admit(other)
	c1 := erase("c1", record.Selectors{IDs: []string{source.ID}, Events: []record.EventSelector{{Owner: G, SessionKey: session, EventID: e1}}})
	if m.Apply(c1) != nil {
		t.Fatal("c1")
	}
	ev := m.Evaluate()
	if !ev.OwnerPending[G] || ev.ControlComplete[c1.ID] || ev.StatusOf(other.ID) != LineageHold {
		t.Fatal("omitted event coverage acknowledged")
	}
	// No local signing key is involved in receipt of an authorized supplement.
	c2 := erase("c2", record.Selectors{Events: []record.EventSelector{{Owner: G, SessionKey: session, EventID: e2}}})
	if m.Apply(c2) != nil {
		t.Fatal("c2")
	}
	ev = m.Evaluate()
	if ev.OwnerPending[G] || !ev.ControlComplete[c1.ID] || ev.StatusOf(other.ID) != Live {
		t.Fatal("authorized supplemental coverage did not complete")
	}
	unknown := source
	unknown.ID = hx("missing-membership")
	unknown.EventMembershipComplete = false
	unknown.Events = nil
	m.Admit(unknown)
	c3 := erase("c3", record.Selectors{IDs: []string{unknown.ID}})
	m.Apply(c3)
	if !m.Evaluate().OwnerPending[G] {
		t.Fatal("unknown membership treated as zero")
	}
}
func TestV3CallOriginAncestryNeverDefaultEmpty(t *testing.T) {
	call := item("call")
	call.Kind = record.KindCall
	call.BodyAvailable = true
	root := item("metadata-root")
	root.Origin = hx("absent-source")
	call.Deps = []string{root.ID}
	m := NewModel()
	m.Admit(root)
	m.Admit(call)
	if m.Evaluate().StatusOf(call.ID) != AncestryPending {
		t.Fatal("call dependency origin exception leaked comparator")
	}
}
