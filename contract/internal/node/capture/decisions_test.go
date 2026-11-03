package capture

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/view"
)

// These are pure producer decision checks. Authentic store derivation of these
// facts is exercised separately by actual SQLite integration, not mocked here.
func TestProducerDecisionFrontierAndUnavailableHolds(t *testing.T) {
	id := "ev1:" + strings.Repeat("a", 64)
	source := strings.Repeat("b", 64)
	plain := record.Event{ID: id, Kind: "assistant_text", Prov: "transcript", Ruleset: 3, Text: &record.Text{Body: "synthetic X", Bytes: 11}}
	old, err := record.ReviseEvent(plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := map[string]baselineEvent{id: {event: old, source: source}}
	h := store.CaptureEventHistory{ID: id, KnownPresence: true, CompleteFrontier: true, Copies: []view.EventVersion{{Admissible: true, Live: true, RecordID: source, Event: old}}, Facts: view.EventFacts{V: record.Version, CurrentSources: map[string]bool{source: true}, Presence: []view.RevisionPresence{{EventID: id, Revision: old.Revision, RecordID: source, Admissible: true}}}, MaximalRevisionIDs: []string{strings.Repeat("c", 64)}}
	ds, err := decisions([]record.Event{plain}, base, map[string]store.CaptureEventHistory{id: h})
	if err != nil || ds[0].mint || !reflect.DeepEqual(ds[0].event, old) {
		t.Fatal("unchanged baseline replaced by newer head instead of exact reuse", err)
	}
	changed := plain
	changed.Text = &record.Text{Body: "synthetic Y", Bytes: 11}
	h.MaximalRevisionIDs = []string{strings.Repeat("d", 64), strings.Repeat("c", 64)}
	ds, err = decisions([]record.Event{changed}, base, map[string]store.CaptureEventHistory{id: h})
	if err != nil || !ds[0].mint || !equalStrings(ds[0].parents, []string{strings.Repeat("c", 64), strings.Repeat("d", 64)}) {
		t.Fatal("changed payload did not retain full authorized frontier", err)
	}
	if _, err = decisions([]record.Event{plain}, nil, map[string]store.CaptureEventHistory{id: h}); Code(err) != "ambiguous_source_baseline" {
		t.Fatal("new source inferred prior frontier", err)
	}
	for i := 0; i < 9; i++ {
		h.MaximalRevisionIDs = append(h.MaximalRevisionIDs, record.H("synthetic-head", string(rune('a'+i))))
	}
	if _, err = decisions([]record.Event{changed}, base, map[string]store.CaptureEventHistory{id: h}); Code(err) != "history_incomplete" {
		t.Fatal("oversized frontier was truncated", err)
	}
	h.Copies = nil
	if _, err = decisions([]record.Event{plain}, base, map[string]store.CaptureEventHistory{id: h}); Code(err) != "baseline_unavailable" {
		t.Fatal("bodyless baseline resealed", err)
	}
	h.Pending = true
	if _, err = decisions([]record.Event{plain}, base, map[string]store.CaptureEventHistory{id: h}); Code(err) != "history_incomplete" {
		t.Fatal("pending causal state accepted", err)
	}
}

func TestCanonicalPartitionPreflightsExactBodyLimits(t *testing.T) {
	makeEvent := func(i int, n int) eventDecision {
		return eventDecision{mint: true, event: record.Event{ID: "ev1:" + record.H("synthetic-event", string(rune(i))), Seq: int64(i), Kind: "assistant_text", Prov: "transcript", Text: &record.Text{Body: strings.Repeat("x", n)}}}
	}
	if _, err := partition([]eventDecision{makeEvent(0, record.MaxBodyBytes)}); Code(err) != "event_size" {
		t.Fatal("oversized event reached mint", err)
	}
	var input []eventDecision
	for i := 0; i < 300; i++ {
		input = append(input, makeEvent(i, 100))
	}
	groups, err := partition(input)
	if err != nil || len(groups) != 2 || len(groups[0]) != 256 || len(groups[1]) != 44 {
		t.Fatal("chunk event partition incorrect", err)
	}
}
