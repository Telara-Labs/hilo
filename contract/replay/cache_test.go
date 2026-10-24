package replay

import (
	"encoding/json"
	"errors"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"testing"
)

func settledCall(t *testing.T) (string, Outcome) {
	t.Helper()
	tokens := record.NewOperationTokens()
	pool, err := tokens.Issue("credential")
	if err != nil {
		t.Fatal(err)
	}
	op, err := tokens.Resolve("credential", pool[0])
	if err != nil {
		t.Fatal(err)
	}
	h := record.Header{Type: record.KindCall, LID: record.CallLID("m1.abcdefghij"), Author: record.Author{MachineID: "6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b", KeyID: "11111111111111111111111111111111"}, At: 1, Prov: record.ProvMCPExplicit, Op: op, Red: record.Redact{Profile: record.ProfileLocal}}
	root := record.H("mutation")
	h.Links.DerivedFrom = []string{root}
	r, err := record.BuildCall(h, record.CallBody{CallRef: "m1.abcdefghij", ScopeID: "sc1:" + h.Author.MachineID + ":00112233445566778899aabbccddeeff", Tool: "telara_task_checkpoint", CommitmentDeps: []string{root}}, json.RawMessage(`{"text":"private"}`), json.RawMessage(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	return op, Outcome{Tool: "telara_task_checkpoint", Call: r, RecordIDs: []string{root}, Dependencies: []string{r.ID, root}, Text: "old clean", RenderVersion: "v1"}
}
func TestStableOperationAndDisclosureReplay(t *testing.T) {
	op, out := settledCall(t)
	cache := New()
	args := json.RawMessage(`{"text":"private"}`)
	if err := cache.Commit(op, out); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cache.Lookup(op, "telara_task_pause", args); !errors.Is(err, ErrConflict) {
		t.Fatal("changed tool accepted")
	}
	if _, _, err := cache.Lookup(op, out.Tool, json.RawMessage(`{"text":"different"}`)); !errors.Is(err, ErrConflict) {
		t.Fatal("changed args accepted")
	}
	text, ok, err := cache.Replay(op, out.Tool, args, true, "v2", func(Outcome) (string, error) { return "web-tainted now", nil })
	if err != nil || !ok || text != "web-tainted now" {
		t.Fatal(text, err)
	}
	text, _, err = cache.Replay(op, "different-tool", json.RawMessage(`{"guess":true}`), false, "v2", nil)
	if err != nil || text != Unavailable {
		t.Fatal("narrowed grant compared content", err)
	}
	cache.Invalidate(out.RecordIDs[0])
	for _, candidate := range []json.RawMessage{args, json.RawMessage(`{"text":"different"}`), nil, json.RawMessage(`INVALID`)} {
		for _, tool := range []string{out.Tool, "arbitrary changed tool"} {
			text, ok, err = cache.Replay(op, tool, candidate, true, "v3", func(Outcome) (string, error) { t.Fatal("keyless rerender"); return "", nil })
			if err != nil || !ok || text != Unavailable {
				t.Fatal("post-erasure candidate oracle", text, err)
			}
		}
	}
	if cache.rows[op].Call != nil || cache.rows[op].ArgsHash != "" || cache.rows[op].Text != "" {
		t.Fatal("comparator copy retained")
	}
	if cache.Commit(op, out) == nil {
		t.Fatal("erased operation executed twice")
	}
}
func TestComparatorDependencyUnion(t *testing.T) {
	for _, mutate := range []func(*Outcome){func(o *Outcome) { o.Dependencies = nil }, func(o *Outcome) { o.Dependencies = o.RecordIDs }, func(o *Outcome) { o.RecordIDs = append(o.RecordIDs, record.H("omitted")) }, func(o *Outcome) { o.Call = o.Call.WithoutBody() }, func(o *Outcome) { o.ArgsHash = record.H("candidate") }} {
		op, o := settledCall(t)
		mutate(&o)
		if New().Commit(op, o) == nil {
			t.Fatal("orphan comparator accepted")
		}
	}
}
func TestDeliveryConfirmationGeneration(t *testing.T) {
	d := NewDelivery()
	g := d.Expose("r")
	if d.Confirmed("r") || !d.Exposed("r") || !d.Confirm("r", g) {
		t.Fatal("delivery")
	}
	d.Compact()
	g2 := d.Expose("r")
	if g2 == g || d.Confirm("r", g) || d.Confirmed("r") || !d.Confirm("r", g2) {
		t.Fatal("generation")
	}
}

func TestV3SelfReviewCanonicalOperationLinkage(t *testing.T) {
	_, out := settledCall(t)
	forged := record.H("forged-advisory-op")
	out.Call.Header.Op = forged
	if New().Commit(forged, out) == nil {
		t.Fatal("advisory decoded header replaced signed operation identity")
	}
}
