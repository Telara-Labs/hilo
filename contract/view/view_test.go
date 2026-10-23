package view

import (
	"github.com/Telara-Labs/telara-memory/contract/heads"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"testing"
)

func rev(t *testing.T, id string, seq int64, text string, parents ...string) record.Event {
	t.Helper()
	e, err := record.ReviseEvent(record.Event{ID: id, Seq: seq, Kind: "assistant_final", Text: &record.Text{Body: text}}, parents, []byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func TestCausalEventRepackingAndConflicts(t *testing.T) {
	id := "ev1:" + record.H("e")
	a := rev(t, id, 0, "original")
	b := rev(t, id, 0, "corrected", a.Revision)
	copies := []EventVersion{version(a), version(b), version(a)}
	choices, err := EventHeads(copies, nil)
	if err != nil || len(choices[id].Heads) != 1 || choices[id].Heads[0].Text.Body != "corrected" {
		t.Fatal("repacking revived original", choices, err)
	}
	c := rev(t, id, 0, "independent", a.Revision)
	choices, _ = EventHeads(append(copies, version(c)), nil)
	if len(choices[id].Heads) != 2 {
		t.Fatal("concurrent correction hidden")
	}
	choices, _ = EventHeads([]EventVersion{version(a)}, nil, EventFacts{V: record.Version, Presence: []RevisionPresence{presence(b)}})
	if len(choices[id].Heads) != 0 {
		t.Fatal("persisted revision supersession forgotten")
	}
	choices, _ = EventHeads([]EventVersion{version(b)}, nil)
	if !choices[id].Pending {
		t.Fatal("missing predecessor called resolved")
	}
}
func TestCoverageAndTaintBySequence(t *testing.T) {
	s := &Session{HasBoundary: true, Through: 2, seq: map[int64]string{0: "a", 2: "c"}, badSeq: map[int64]bool{}}
	in := TrustInput{Kind: record.KindConclusion, Verified: true, AncestryResolved: true, BindingConfidence: "transcript-echo", Session: s, Boundary: 2, Header: record.Trust{Coverage: "complete"}, Events: []EventTaint{{Seq: 1, Tags: []string{"web"}}}}
	got := Trust(in)
	if got.Coverage != "incomplete" || !got.Uncertain || len(got.Observed) != 1 {
		t.Fatal("missing earlier chunk certified clean", got)
	}
	s.seq[1] = "b"
	got = Trust(in)
	if got.Coverage != "complete" || got.Uncertain || got.Observed[0] != "web" {
		t.Fatal("late web event was lost", got)
	}
	in.Kind = record.KindKeyOp
	if Trust(in).Coverage == "complete" {
		t.Fatal("undefined kind coverage")
	}
	in.Kind = record.KindDigest
	in.Provenance = record.ProvDerived
	in.CopiedInputs = 0
	if Trust(in).Coverage == "complete" {
		t.Fatal("empty derivation certified clean")
	}
	in.CopiedInputs = 1
	in.Inputs = []EffectiveTrust{got}
	if Trust(in).Coverage != "complete" {
		t.Fatal("complete copied input refused")
	}
	in.OriginRequired = true
	if Trust(in).Coverage == "complete" {
		t.Fatal("missing export origin certified clean")
	}
}
func TestReadBackAndOwnerTaskBoundary(t *testing.T) {
	c := ReadContext{Channel: "H", Kind: record.KindConclusion, Verified: true, OwnGenesis: true, SameRepo: true, GrantAllowed: true, Trust: EffectiveTrust{Coverage: "complete"}}
	if Eligible(c) {
		t.Fatal("H enabled by default")
	}
	c.HookEnabled = true
	if !Eligible(c) {
		t.Fatal("clean opt-in H refused")
	}
	c.Trust.Observed = []string{"web"}
	if Eligible(c) {
		t.Fatal("web H allowed")
	}
	c.Channel = "S"
	c.Held = true
	if Eligible(c) {
		t.Fatal("search displayed held content")
	}
	r := &record.Record{ID: "a", Header: record.Header{Type: record.KindTask, LID: "same", Subj: record.Subject{TaskID: "T"}}, Body: &record.TaskBody{Status: "open"}}
	done := &record.Record{ID: "b", Header: record.Header{Type: record.KindConclusion, LID: "done", Prov: record.ProvGateway, Subj: record.Subject{TaskID: "T"}}}
	all := []Observed{{Record: r, Owner: "genesis:a", Live: true, Admissible: true}, {Record: done, Owner: "tenant:b", Live: true, Admissible: true}}
	if TaskStatus(all, nil, "genesis:a", "T") != "open" {
		t.Fatal("foreign task completed local task")
	}
	if len(heads.HeadsForOwner([]heads.Version{{ID: "x", Owner: "a", LID: "t", Type: record.KindTask, Live: true}}, []heads.Pair{{From: "z", To: "x", Owner: "b", LID: "t", Type: record.KindTask}}, "t", record.KindTask, "a")) != 1 {
		t.Fatal("cross owner supersession")
	}
}
func TestBindingTopRankTieAndCorrection(t *testing.T) {
	call := "m1.aaaaaaaaaa"
	lid := record.BindingLID(call)
	makeB := func(id, session, confidence string) Observed {
		return Observed{Owner: "owner", Live: true, Admissible: true, Record: &record.Record{ID: id, Header: record.Header{Type: record.KindBinding, LID: lid}, Body: &record.BindingBody{CallRef: call, Status: "bound", Confidence: confidence, Target: &record.BindTarget{SessionKey: session}}}}
	}
	all := []Observed{makeB("a", "A", "transcript-echo"), makeB("b", "B", "transcript-echo"), makeB("c", "C", "inferred")}
	if ResolveBinding(all, nil, call, "owner").Status != "ambiguous" {
		t.Fatal("equal top rank bound")
	}
	all = append(all, makeB("d", "D", "stated"))
	if ResolveBinding(all, nil, call, "owner").Target.SessionKey != "D" || MayCorrectBinding("stated", "inferred") {
		t.Fatal("rank rule")
	}
}

func TestSessionMultiMachineCorrectionSurvivesRepack(t *testing.T) {
	sk := "sk1:" + record.H("session")
	m1, m2 := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	e0 := rev(t, "ev1:"+record.H("e0"), 0, "zero")
	e1 := rev(t, "ev1:"+record.H("e1"), 1, "stale one")
	e2 := rev(t, "ev1:"+record.H("e2"), 2, "two")
	corrected := rev(t, e1.ID, 1, "corrected one", e1.Revision)
	changed2 := rev(t, e2.ID, 2, "changed two", e2.Revision)
	chunk := func(id string, events ...record.Event) Observed {
		return Observed{Owner: "owner", Live: true, Admissible: true, Record: &record.Record{ID: id, Header: record.Header{Type: record.KindChunk, Subj: record.Subject{SessionKey: sk}}, Body: &record.ChunkBody{Events: events}}}
	}
	snapshot := func(id, machine, chunk string, through int64) Observed {
		return Observed{Owner: "owner", Live: true, Admissible: true, Record: &record.Record{ID: id, Header: record.Header{Type: record.KindSession, LID: record.SessionLID(sk, machine, 0), Author: record.Author{MachineID: machine}, Subj: record.Subject{SessionKey: sk}}, Body: &record.SessionBody{Chunks: []string{chunk}, SettledThrough: through}}}
	}
	all := []Observed{chunk("old", e0, e1, e2), chunk("repacked", e0, e1, changed2), chunk("short", e0, corrected), snapshot("s1", m1, "repacked", 2), snapshot("s2", m2, "short", 1)}
	s, err := SessionView(all, nil, nil, sk)
	if err != nil || !s.CoverageAt(2) || len(s.Events) != 3 {
		t.Fatalf("merged view %+v %v", s, err)
	}
	if s.Events[1].Text.Body != "corrected one" || s.Events[2].Text.Body != "changed two" {
		t.Fatal("repacking suppressed independent correction")
	}
	concurrent := rev(t, e1.ID, 1, "other correction", e1.Revision)
	all = append(all, chunk("conflict", e0, concurrent), snapshot("s3", "33333333-3333-4333-8333-333333333333", "conflict", 1))
	s, err = SessionView(all, nil, nil, sk)
	if err != nil || s.CoverageAt(2) || len(s.Conflicts[e1.ID]) != 2 {
		t.Fatal("concurrent correction not reflected in coverage", s, err)
	}
}

func TestLaterMissingPageKeepsEarlierSettledPrefix(t *testing.T) {
	sk := "sk1:" + record.H("s")
	machine := "11111111-1111-4111-8111-111111111111"
	e := rev(t, "ev1:"+record.H("e"), 0, "zero")
	chunk := Observed{Owner: "owner", Live: true, Admissible: true, Record: &record.Record{ID: "chunk", Header: record.Header{Type: record.KindChunk, Subj: record.Subject{SessionKey: sk}}, Body: &record.ChunkBody{Events: []record.Event{e}}}}
	snapshot := func(page int64, ch string) Observed {
		return Observed{Owner: "owner", Live: true, Admissible: true, Record: &record.Record{ID: record.H("page", string(rune('0'+page))), Header: record.Header{Type: record.KindSession, LID: record.SessionLID(sk, machine, page), Author: record.Author{MachineID: machine}, Subj: record.Subject{SessionKey: sk}}, Body: &record.SessionBody{Page: page, Chunks: []string{ch}, SettledThrough: page}}}
	}
	s, err := SessionView([]Observed{chunk, snapshot(0, "chunk"), snapshot(1, "missing-later")}, nil, nil, sk)
	if err != nil || !s.CoverageAt(0) || s.CoverageAt(1) {
		t.Fatal("later incomplete page removed settled prefix", s, err)
	}
}

func version(e record.Event) EventVersion {
	return EventVersion{Event: e, Live: true, Admissible: true, Owner: "owner", SessionKey: "session", RecordID: record.H("source", e.Revision)}
}
func presence(e record.Event) RevisionPresence {
	v := version(e)
	return RevisionPresence{EventID: e.ID, Revision: e.Revision, Owner: v.Owner, SessionKey: v.SessionKey, RecordID: v.RecordID, Replaces: append([]string(nil), e.Replaces...), Admissible: true}
}
