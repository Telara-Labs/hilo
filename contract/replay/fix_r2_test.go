package replay

import (
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/invalidate"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

func TestV3ReplayRejectsUnsignedInputRoots(t *testing.T) {
	for _, field := range []string{"render", "mutation", "both", "unavailable-commitments"} {
		t.Run(field, func(t *testing.T) {
			op, out := settledCall(t)
			q := record.H("known-render-input")
			if field == "unavailable-commitments" {
				h, b := out.Call.Header, *out.Call.Body.(*record.CallBody)
				b.Salt, b.ArgsHash, b.ResultHash = "", "", ""
				var err error
				out.Call, err = record.BuildCall(h, b, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				out.Dependencies[0] = out.Call.ID
			}
			if field != "mutation" {
				out.Dependencies = append(out.Dependencies, q)
			}
			if field == "mutation" || field == "both" {
				out.RecordIDs = append(out.RecordIDs, q)
			}
			cache := New()
			if err := cache.Commit(op, out); err == nil || err.Error() != "commitment_dependencies" {
				t.Fatalf("known input omitted from signed set was not rejected: %v", err)
			}
			if _, ok, err := cache.Lookup(op, out.Tool, nil); ok || err != nil {
				t.Fatal("rejected outcome retained comparator state", err)
			}
		})
	}
}

func TestV3ReplayDependencySetBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Outcome)
	}{
		{"duplicate", func(o *Outcome) { o.Dependencies = append(o.Dependencies, o.Dependencies[0]) }},
		{"malformed", func(o *Outcome) { o.Dependencies = append(o.Dependencies, "private prose") }},
		{"missing-call", func(o *Outcome) { o.Dependencies = o.Dependencies[1:] }},
		{"missing-signed-root", func(o *Outcome) { o.Dependencies = o.Dependencies[:1] }},
		{"self-as-input", func(o *Outcome) { o.RecordIDs = append(o.RecordIDs, o.Call.ID) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op, out := settledCall(t)
			tc.mutate(&out)
			if err := New().Commit(op, out); err == nil {
				t.Fatal("invalid local dependency set accepted")
			}
		})
	}
	// The call itself is the only permitted local edge outside the signed set.
	op, out := settledCall(t)
	h, b := out.Call.Header, *out.Call.Body.(*record.CallBody)
	h.Links.DerivedFrom = nil
	b.Salt, b.ArgsHash, b.ResultHash = "", "", ""
	b.CommitmentDeps = []string{}
	var err error
	out.Call, err = record.BuildCall(h, b, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	out.RecordIDs = nil
	out.Dependencies = []string{out.Call.ID}
	if err := New().Commit(op, out); err != nil {
		t.Fatal("explicit signed empty set with call-lifetime edge rejected", err)
	}
	// A decoded sender-side dependency claim cannot repair the signed bytes.
	q := record.H("unsigned-decoded-root")
	out.Call.Body.(*record.CallBody).CommitmentDeps = []string{q}
	out.Call.Header.Links.DerivedFrom = []string{q}
	out.Dependencies = append(out.Dependencies, q)
	if err := New().Commit(op, out); err == nil {
		t.Fatal("decoded side fields repaired an omitted signed root")
	}
}

// This is a pure wire/closure regression. Actual encrypted transfer, persistence
// and physical key cleanup are separate adapter conformance requirements.
func TestV3ReplayTransferredRenderRootErasure(t *testing.T) {
	op, out := settledCall(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	h := out.Call.Header
	h.Author.KeyID = sig.KeyID(pub)
	h.Subj.TaskID = "3f2a91c0-1111-4222-8333-444455556666"
	h.Links = record.Links{}
	h.Type = record.KindCheckpoint
	h.LID = record.CheckpointLID(h.Author.KeyID, h.Subj.TaskID, h.Author.MachineID, op)
	p, err := record.Build(h, &record.CheckpointBody{Milestone: "mutation"})
	if err != nil {
		t.Fatal(err)
	}
	h.Type = record.KindTask
	h.LID = record.TaskLID(h.Author.KeyID, h.Subj.TaskID)
	q, err := record.Build(h, &record.TaskBody{Status: "active", Goal: "render-only private input"})
	if err != nil {
		t.Fatal(err)
	}
	h = out.Call.Header
	h.Author.KeyID = sig.KeyID(pub)
	deps := []string{p.ID, q.ID}
	sort.Strings(deps)
	h.Links.DerivedFrom = deps
	b := *out.Call.Body.(*record.CallBody)
	b.Salt, b.ArgsHash, b.ResultHash = "", "", ""
	b.CommitmentDeps = deps
	args := json.RawMessage(`{"text":"private"}`)
	out.Call, err = record.BuildCall(h, b, args, json.RawMessage(`{"text":"render-only private input"}`))
	if err != nil {
		t.Fatal(err)
	}
	out.RecordIDs = []string{p.ID} // Q contributes only through rendered input.
	out.Dependencies = []string{out.Call.ID, q.ID, p.ID}
	if err := New().Commit(op, out); err != nil {
		t.Fatal("complete signed union rejected", err)
	}
	// Transfer canonical records and signatures only, discarding local cache deps.
	wire := map[string]*record.Record{}
	bundle := map[string]transport.BundleRecord{}
	for _, source := range []*record.Record{p, q, out.Call} {
		s, err := sig.SignRecord(priv, source.ID)
		if err != nil {
			t.Fatal(err)
		}
		r, err := record.Parse(source.HeaderJCS, source.BodyJCS, source.ID)
		msg, msgErr := sig.RecordMessage(source.ID)
		if err != nil || msgErr != nil || sig.Verify(pub, sig.CtxRecord, msg, s) != nil {
			t.Fatal("transferred canonical seal/signature invalid", err, msgErr)
		}
		wire[r.ID] = r
		bundle[r.ID] = transport.BundleRecord{ID: r.ID, Record: r, CompleteSigned: true, SelectorIdentity: true, Selected: true, Live: true, Authorization: transport.BundleAuthorization{ProvenanceKnown: true}}
	}
	if !transport.BundleEligible(out.Call.ID, bundle) {
		t.Fatal("complete signed transfer denied")
	}
	delete(bundle, q.ID)
	if transport.BundleEligible(out.Call.ID, bundle) {
		t.Fatal("transfer omitted render-only signed root")
	}
	for _, order := range []string{"PCQE", "CPQE", "ECPQ", "CEQP", "PEQC", "QPEC"} {
		t.Run(order, func(t *testing.T) {
			m := invalidate.NewModel()
			cache := New()
			c := wire[out.Call.ID]
			// Rebuild using only signed bytes, as on import/restart.
			restored := Outcome{Tool: b.Tool, Call: c, RecordIDs: []string{p.ID}, Dependencies: append([]string{c.ID}, c.Header.Links.DerivedFrom...), Text: "private rendered text", RenderVersion: "v1"}
			if err := cache.Commit(op, restored); err != nil {
				t.Fatal(err)
			}
			for _, step := range order {
				if step == 'E' {
					if err := m.Apply(invalidate.Control{ID: record.H("erase-render-root"), Owner: h.Author.KeyID, Kind: record.KindErasure, Erasure: &record.ErasureBody{EventCoverage: "complete", Reason: "user_request", Selectors: record.Selectors{IDs: []string{q.ID}}}}); err != nil {
						t.Fatal(err)
					}
					continue
				}
				r := wire[map[rune]string{'P': p.ID, 'Q': q.ID, 'C': c.ID}[step]]
				m.Admit(invalidate.Item{ID: r.ID, Kind: r.Header.Type, Owner: r.Header.Author.KeyID, Prov: r.Header.Prov, Deps: r.Header.Links.DerivedFrom, BodyAvailable: true})
			}
			if m.Evaluate().StatusOf(c.ID) != invalidate.Invalidated {
				t.Fatal("transferred signed render root did not invalidate call")
			}
			// Q alone must scrub the local copy, despite not being a RecordID.
			cache.Invalidate(q.ID)
			for _, candidate := range []json.RawMessage{args, json.RawMessage(`{"guess":"different"}`), json.RawMessage(`INVALID`)} {
				text, found, err := cache.Replay(op, "changed-tool", candidate, true, "v2", func(Outcome) (string, error) { t.Fatal("erased key rerendered"); return "", nil })
				if text != Unavailable || !found || err != nil {
					t.Fatal("erasure retained a content oracle", text, found, err)
				}
			}
			if row := cache.rows[op]; row.Call != nil || row.ArgsHash != "" || row.Text != "" {
				t.Fatal("erasure retained managed comparator/render copy")
			}
		})
	}
}
