package store

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/view"
)

// A record whose effective label is missing or unknown refuses release. It
// is never rendered with empty coverage or trust labels.
func TestReleaseLabelFailureRefusesInsteadOfUnlabeled(t *testing.T) {
	w := newWorld(t)
	in := w.task(7100, "labelfailurecontent")
	rec, _, err := parse(in)
	if err != nil {
		t.Fatal(err)
	}
	x := &stored{rec: rec}
	for name, trust := range map[string]*view.EffectiveTrust{
		"not_computed":     nil,
		"empty_coverage":   {},
		"unknown_coverage": {Coverage: "partial"},
	} {
		d := &databaseState{trust: map[string]view.EffectiveTrust{}}
		if trust != nil {
			d.trust[rec.ID] = *trust
		}
		labels, err := releaseLabels(d, x)
		if Code(err) != "label_unavailable" || labels.Coverage != "" || labels.Trust != "" || labels.Kind != "" {
			t.Fatalf("%s: label failure degraded to %+v, %v", name, labels, err)
		}
	}
	d := &databaseState{trust: map[string]view.EffectiveTrust{rec.ID: {Coverage: "incomplete", Uncertain: true, Observed: []string{"web"}}}}
	labels, err := releaseLabels(d, x)
	if err != nil || labels.Coverage != "incomplete" || labels.Trust != "taint-unknown,web" || labels.Kind != "task" || labels.Signature != "verified" {
		t.Fatalf("computed label not carried %+v %v", labels, err)
	}
}

// labelSessionChunk builds one transcript chunk in its own native session.
func labelSessionChunk(t *testing.T, k *kernelWorld, n int) SignedRecord {
	t.Helper()
	sk, err := record.SessionKey("claude-code", "local", record.NativeGlobal, fmt.Sprintf("71111111-1111-4111-8111-%012x", n), "")
	if err != nil {
		t.Fatal(err)
	}
	eid, err := record.EventID(sk, "assistant_final", record.Anchor{NativeItemID: "label-boundary"})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := record.ReviseEvent(record.Event{ID: eid, Seq: 0, Kind: "assistant_final", Prov: "transcript", Text: &record.Text{Body: "label input"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return k.signed(record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.ChunkLID(sk, testMachine, eid)}, &record.ChunkBody{Events: []record.Event{ev}})
}

// A label input that cannot be computed on a real store refuses the read
// with a fixed code and no reply, rather than releasing the record without
// its coverage and trust labels. The planted orphan taint fact is one of
// the session facts that label computation reduces.
func TestReleaseLabelComputationErrorRefusesRelease(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	chunk := labelSessionChunk(t, k, 1)
	k.append(chunk)
	task := k.task(7200, "labelfailurecontent", chunk.AdvisoryID)
	k.append(task)
	text := k.release(k.execute("label-before", "local.lookup_record", map[string]any{"record_id": task.AdvisoryID}))
	if !strings.Contains(text, "labelfailurecontent") || !strings.Contains(text, `; coverage incomplete; trust taint\u002dunknown;`) {
		t.Fatal("computable label not rendered", text)
	}
	var sk string
	if err := k.s.conn.QueryRowContext(ctx, "SELECT session FROM presence LIMIT 1").Scan(&sk); err != nil {
		t.Fatal(err)
	}
	if _, err := k.s.conn.ExecContext(ctx, "INSERT INTO presence_taint VALUES(?,?,?,?,?,?)", k.o.PinnedGenesisID, sk, "missing-event", "missing-revision", chunk.AdvisoryID, "web"); err != nil {
		t.Fatal(err)
	}
	r, err := k.e.Execute(ctx, k.h, k.sc, CallIdentity{SuppliedOpID: k.issued("label-after")}, commandFor(t, "local.lookup_record", map[string]any{"record_id": task.AdvisoryID}), ByteBudget{MaxBytes: 4096})
	if err == nil || r.engine != nil {
		out, rerr := k.e.Release(ctx, k.h, r)
		t.Fatalf("record released without computable labels: %q %v", out.Text(), rerr)
	}
	if Code(err) != "corrupt_database" || strings.Contains(err.Error(), "labelfailurecontent") {
		t.Fatalf("label input failure has unexpected refusal %v", err)
	}
}
