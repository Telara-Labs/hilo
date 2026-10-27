package view

import (
	"github.com/Telara-Labs/hilo/contract/record"
	"testing"
)

type publicTextRedactor struct{}

func (publicTextRedactor) Redact(s string) string           { return s }
func (publicTextRedactor) Argument(n, s string) string      { return s }
func (publicTextRedactor) Profiles() []string               { return nil }
func (publicTextRedactor) RedactProfile(p, s string) string { return s }
func TestV3EqualityRequiresCompleteOwnKeyText(t *testing.T) {
	id := "ev1:" + record.H("event")
	session := "sk1:" + record.H("session")
	owner := "11111111111111111111111111111111"
	makeEvent := func(max int) record.Event {
		e, err := record.ReviseTextEvent(record.Event{ID: id, Kind: "assistant_text", Prov: "transcript"}, nil, "complete redacted text", publicTextRedactor{}, max)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	a, b := makeEvent(600), makeEvent(600)
	copies := []EventVersion{{Event: a, Live: true, Admissible: true, RecordID: record.H("a"), Owner: owner, SessionKey: session}, {Event: b, Live: true, Admissible: true, RecordID: record.H("b"), Owner: owner, SessionKey: session}}
	choices, err := EventHeads(copies, nil)
	if err != nil || len(choices[id].Facts.Witnesses) != 1 || choices[id].Conflict {
		t.Fatal("own-key full equality", err)
	}
	copies[0].Event = makeEvent(4)
	copies[1].Event = makeEvent(4)
	choices, err = EventHeads(copies, nil)
	if err != nil || len(choices[id].Facts.Witnesses) != 0 || !choices[id].Conflict {
		t.Fatal("equal excerpts established hidden full-text equality", err)
	}
	// Retained authoritative source invalidation wins over a cached eligible body.
	copies[0].Event = a
	copies[1].Event = b
	history := EventFacts{V: 3, CurrentSources: map[string]bool{copies[0].RecordID: false, copies[1].RecordID: true}}
	choices, err = EventHeads(copies, nil, history)
	if err != nil || len(choices[id].Heads) != 1 || len(choices[id].Facts.Witnesses) != 0 {
		t.Fatal("invalidated source supplied equality operand", err)
	}
}

func TestV3SelfReviewTruncatedResultCannotEstablishEquality(t *testing.T) {
	id := "ev1:" + record.H("result-event")
	session := "sk1:" + record.H("session")
	owner := "11111111111111111111111111111111"
	copies := []EventVersion{}
	for _, name := range []string{"a", "b"} {
		e, err := record.ReviseEvent(record.Event{ID: id, Kind: "tool_result", Prov: "transcript", Result: &record.ToolResult{Excerpt: "same excerpt", Bytes: 1000, Outcome: "ok"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		copies = append(copies, EventVersion{Event: e, Live: true, Admissible: true, Owner: owner, SessionKey: session, RecordID: record.H(name)})
	}
	choices, err := EventHeads(copies, nil)
	if err != nil || len(choices[id].Facts.Witnesses) != 0 || !choices[id].Conflict {
		t.Fatal("truncated result excerpts established full payload equality", err)
	}
}

func TestV3TenantPolicyPrecedesEveryReadChannel(t *testing.T) {
	for _, channel := range []string{"S", "P", "E", "H"} {
		c := ReadContext{Channel: channel, Kind: record.KindConclusion, PolicyRequired: true, PolicyAllowed: false, GrantAllowed: true, Verified: true, SameRepo: true, OwnGenesis: true, HookEnabled: true, Trust: EffectiveTrust{Coverage: "complete"}}
		if Eligible(c) {
			t.Fatal("tenant policy bypass", channel)
		}
		c.PolicyAllowed = true
		if !Eligible(c) {
			t.Fatal("permitted channel denied", channel)
		}
	}
}
