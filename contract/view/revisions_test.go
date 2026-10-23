package view

import (
	"encoding/json"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"strings"
	"testing"
)

func TestSaltedIndependentCapturesAndCausalOccurrences(t *testing.T) {
	id := "ev1:" + record.H("independent")
	a := rev(t, id, 0, "original-private")
	a2 := rev(t, id, 0, "original-private")
	b := rev(t, id, 0, "corrected", a.Revision)
	if a.Revision == a2.Revision {
		t.Fatal("independent capture did not salt separately")
	}
	copies := []EventVersion{version(a), version(a2), version(b)}
	for _, order := range [][]int{{0, 1, 2}, {2, 1, 0}, {1, 2, 0}} {
		xs := []EventVersion{}
		for _, n := range order {
			xs = append(xs, copies[n])
		}
		out, err := EventHeads(xs, nil)
		if err != nil || out[id].Pending || out[id].Conflict || len(out[id].Heads) != 1 || out[id].Heads[0].Revision != b.Revision {
			t.Fatal("stale independent capture defeated correction", out, err)
		}
	}
	restored := rev(t, id, 0, "original-private", b.Revision)
	out, err := EventHeads(append(copies, version(restored)), nil)
	if err != nil || out[id].Pending || out[id].Conflict || len(out[id].Heads) != 1 || out[id].Heads[0].Revision != restored.Revision {
		t.Fatal("intentional revert collapsed into old occurrence", out, err)
	}
	noop := rev(t, id, 0, "original-private", restored.Revision)
	out, err = EventHeads(append(copies, version(restored), version(noop)), nil)
	if err != nil || out[id].Pending || len(out[id].Heads) != 1 || out[id].Heads[0].Revision != noop.Revision {
		t.Fatal("equal no-op successor hidden", out, err)
	}
}
func TestEqualityWitnessDependencyInvalidationAndRestart(t *testing.T) {
	id := "ev1:" + record.H("dependencies")
	p, q := rev(t, id, 0, "parent"), rev(t, id, 0, "parent")
	a, b := rev(t, id, 0, "child", p.Revision), rev(t, id, 0, "child", q.Revision)
	out, err := EventHeads([]EventVersion{version(p), version(q), version(a), version(b)}, nil)
	if err != nil || out[id].Conflict || out[id].Pending {
		t.Fatal(out, err)
	}
	facts := out[id].Facts
	correction := rev(t, id, 0, "new", a.Revision)
	out, err = EventHeads([]EventVersion{version(b), version(correction)}, nil, facts)
	if err != nil || out[id].Conflict || len(out[id].Heads) != 1 {
		t.Fatal("restart lost admissible witnesses", out, err)
	}
	for i := range facts.Witnesses {
		w := &facts.Witnesses[i]
		if w.A == p.Revision && w.B == q.Revision || w.A == q.Revision && w.B == p.Revision {
			w.Admissible = false
		}
	}
	out, err = EventHeads([]EventVersion{version(b), version(correction)}, nil, facts)
	if err != nil || !out[id].Conflict {
		t.Fatal("dependent child alias survived parent proof invalidation", out, err)
	}
	raw, _ := json.Marshal(facts)
	if strings.Contains(string(raw), p.Salt) || strings.Contains(string(raw), "parent") {
		t.Fatal("retained fact leaked salt or payload")
	}
	records, err := EventErasureRecords(facts, "owner", "session", id)
	if err != nil || len(records) != 4 {
		t.Fatal("event source erasure missed equivalent/revert records", records, err)
	}
}
func TestKnownErasedVersusUnknownPredecessorAndHeadLimit(t *testing.T) {
	id := "ev1:" + record.H("presence")
	a := rev(t, id, 0, "old")
	b := rev(t, id, 0, "new", a.Revision)
	out, _ := EventHeads([]EventVersion{version(b)}, nil)
	if !out[id].Pending {
		t.Fatal("never-seen predecessor not pending")
	}
	out, err := EventHeads([]EventVersion{version(b)}, nil, EventFacts{V: record.Version, Presence: []RevisionPresence{presence(a)}})
	if err != nil || out[id].Pending || len(out[id].Heads) != 1 {
		t.Fatal("known erased predecessor blocked complete causal proof", out, err)
	}
	copies := []EventVersion{}
	for i := 0; i < 9; i++ {
		copies = append(copies, version(rev(t, id, 0, string(rune('A'+i)))))
	}
	out, err = EventHeads(copies, nil)
	if err != nil || !out[id].Pending {
		t.Fatal("more than8 heads silently resolved")
	}
	if _, err = EventHeads([]EventVersion{version(a)}, nil, EventFacts{V: 1}); err == nil {
		t.Fatal("legacy unsalted fact index accepted")
	}
}

func TestAvailableInvalidBodyCannotReauthorizePresence(t *testing.T) {
	id := "ev1:" + record.H("invalid-body")
	a := rev(t, id, 0, "old")
	b := rev(t, id, 0, "new", a.Revision)
	oldFacts := EventFacts{V: record.Version, Presence: []RevisionPresence{presence(a)}}
	bad := version(a)
	bad.Live = false
	bad.Admissible = false
	out, err := EventHeads([]EventVersion{bad, version(b)}, nil, oldFacts)
	if err != nil || !out[id].Pending {
		t.Fatal("available invalid predecessor body reauthorized past presence", out, err)
	}
	legacy := EventFacts{V: 1, Presence: []RevisionPresence{presence(a)}, Witnesses: []EqualityWitness{{EventID: id, A: a.Revision, B: b.Revision, Owner: "owner", SessionKey: "session", RecordA: version(a).RecordID, RecordB: version(b).RecordID, Admissible: true}}}
	if _, err = EventHeads([]EventVersion{version(b)}, []EventPair{{EventID: id, From: b.Revision, To: a.Revision, Owner: "owner", SessionKey: "session", RecordID: version(b).RecordID}}, legacy); err == nil {
		t.Fatal("populated legacy revision metadata entered protected path")
	}
}
func TestEqualCaptureTaintAndComplementaryCoverage(t *testing.T) {
	sk := "sk1:" + record.H("taint-session")
	eventID := "ev1:" + record.H("same-event")
	a, b := rev(t, eventID, 0, "same"), rev(t, eventID, 0, "same")
	if a.Revision > b.Revision {
		a, b = b, a
	}
	chunk := func(id string, e record.Event, taint bool) Observed {
		r := &record.Record{ID: id, Header: record.Header{Type: record.KindChunk, Subj: record.Subject{SessionKey: sk}}, Body: &record.ChunkBody{Events: []record.Event{e}}}
		if taint {
			r.Header.Trust.Taint = []string{"web"}
		}
		return Observed{Record: r, Owner: "owner", Live: true, Admissible: true}
	}
	snapshot := func(id, machine, chunk string, through int64) Observed {
		return Observed{Owner: "owner", Live: true, Admissible: true, Record: &record.Record{ID: id, Header: record.Header{Type: record.KindSession, LID: record.SessionLID(sk, machine, 0), Author: record.Author{MachineID: machine}, Subj: record.Subject{SessionKey: sk}}, Body: &record.SessionBody{Chunks: []string{chunk}, SettledThrough: through}}}
	}
	m1, m2 := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	all := []Observed{chunk("clean", a, false), chunk("web", b, true), snapshot("s1", m1, "clean", 0), snapshot("s2", m2, "web", 0)}
	s, err := SessionView(all, nil, nil, sk)
	if err != nil || len(s.Events) != 1 || s.Events[0].Revision != a.Revision {
		t.Fatal("display representative", s, err)
	}
	trust := Trust(TrustInput{Kind: record.KindConclusion, Verified: true, AncestryResolved: true, Session: s, Boundary: 0, BindingConfidence: "transcript-echo"})
	if trust.Coverage != "complete" || len(trust.Observed) != 1 || trust.Observed[0] != "web" {
		t.Fatal("clean display discarded equal copy taint", trust)
	}
	e1 := rev(t, "ev1:"+record.H("e1"), 1, "one")
	all = []Observed{chunk("zero", a, false), chunk("one", e1, false), snapshot("s1", m1, "zero", 1), snapshot("s2", m2, "one", 1)}
	s, err = SessionView(all, nil, nil, sk)
	if err != nil || s.CoverageAt(1) {
		t.Fatal("complementary partial captures invented complete prefix", s, err)
	}
	bodyless := chunk("erased", a, false)
	bodyless.Record = bodyless.Record.WithoutBody()
	s, err = SessionView([]Observed{bodyless, snapshot("s1", m1, "erased", 0)}, nil, nil, sk)
	if err != nil || len(s.Facts.Presence) != 0 || len(s.Facts.Witnesses) != 0 || s.CoverageAt(0) {
		t.Fatal("bodyless envelope created protected facts", s, err)
	}
}

func TestBodylessInvalidSourceOverridesRetainedHistory(t *testing.T) {
	sk := "sk1:" + record.H("bodyless-history")
	id := "ev1:" + record.H("bodyless-event")
	a := rev(t, id, 0, "old")
	b := rev(t, id, 0, "corrected", a.Revision)
	sourceA := &record.Record{ID: version(a).RecordID, Header: record.Header{Type: record.KindChunk, Subj: record.Subject{SessionKey: sk}}, Body: &record.ChunkBody{Events: []record.Event{a}}}
	sourceB := &record.Record{ID: version(b).RecordID, Header: record.Header{Type: record.KindChunk, Subj: record.Subject{SessionKey: sk}}, Body: &record.ChunkBody{Events: []record.Event{b}}}
	p := presence(a)
	p.SessionKey = sk
	history := EventFacts{V: record.Version, Presence: []RevisionPresence{p}}
	snapshot := &record.Record{ID: record.H("snapshot"), Header: record.Header{Type: record.KindSession, LID: record.SessionLID(sk, "11111111-1111-4111-8111-111111111111", 0), Author: record.Author{MachineID: "11111111-1111-4111-8111-111111111111"}, Subj: record.Subject{SessionKey: sk}}, Body: &record.SessionBody{Chunks: []string{sourceB.ID}, SettledThrough: 0}}
	all := []Observed{{Record: sourceA.WithoutBody(), Owner: "owner", Live: false, Admissible: false}, {Record: sourceB, Owner: "owner", Live: true, Admissible: true}, {Record: snapshot, Owner: "owner", Live: true, Admissible: true}}
	s, err := SessionView(all, nil, nil, sk, history)
	if err != nil || s.CoverageAt(0) {
		t.Fatal("bodyless invalid predecessor reauthorized retained presence", s, err)
	}
	trust := Trust(TrustInput{Kind: record.KindConclusion, Verified: true, AncestryResolved: true, Session: s, Boundary: 0, BindingConfidence: "transcript-echo"})
	if trust.Coverage == "complete" {
		t.Fatal("bodyless invalid source created clean complete trust")
	}
	all[0].Admissible = true
	s, err = SessionView(all, nil, nil, sk, history)
	if err != nil || !s.CoverageAt(0) {
		t.Fatal("known erased but admissible predecessor did not remain usable as causal fact", s, err)
	}
}
