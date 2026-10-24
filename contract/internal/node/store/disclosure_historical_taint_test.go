package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"strings"
	"testing"
)

func historicalSessionFixture(t *testing.T, k *kernelWorld, native, tag string) (string, SignedRecord, SignedRecord, record.Event) {
	t.Helper()
	sk, err := record.SessionKey("claude-code", "local", record.NativeGlobal, native, "")
	if err != nil {
		t.Fatal(err)
	}
	eid, err := record.EventID(sk, "assistant_final", record.Anchor{NativeItemID: "review-boundary"})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := record.ReviseEvent(record.Event{ID: eid, Seq: 0, Kind: "assistant_final", Prov: "transcript", Text: &record.Text{Body: "review boundary"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	trust := record.Trust{}
	if tag != "" {
		trust.Taint = []string{tag}
	}
	chunk := k.signed(record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.ChunkLID(sk, testMachine, eid), Trust: trust}, &record.ChunkBody{Events: []record.Event{ev}})
	k.append(chunk)
	page := k.signed(record.Header{Type: record.KindSession, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.SessionLID(sk, testMachine, 0)}, &record.SessionBody{NativeID: native, NativeIDKind: record.NativeGlobal, MachineOS: "darwin", Chunks: []string{chunk.AdvisoryID}, SettledThrough: 0})
	k.append(page)
	return sk, chunk, page, ev
}
func TestDisclosureHistoricalEventTaintBeforeBindingSurvivesCorrection(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	rootKey := k.key
	historicalKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, 32))
	enroll := k.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(historicalKey.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: k.o.PinnedGenesisID, Parents: []string{k.genesis.AdvisoryID}}, rootKey, rootKey, historicalKey)
	k.append(enroll)
	k.key = historicalKey
	a, oldChunk, oldPage, oldEvent := historicalSessionFixture(t, k, "77777777-7777-4777-8777-777777777777", "web")
	k.key = rootKey
	cleanEvent, err := record.ReviseEvent(record.Event{ID: oldEvent.ID, Seq: 0, Kind: oldEvent.Kind, Prov: oldEvent.Prov, Text: &record.Text{Body: "clean corrected boundary"}}, []string{oldEvent.Revision})
	if err != nil {
		t.Fatal(err)
	}
	chunk := k.signed(record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: a}, LID: record.ChunkLID(a, testMachine, oldEvent.ID)}, &record.ChunkBody{Events: []record.Event{cleanEvent}})
	k.append(chunk)
	page := k.signed(record.Header{Type: record.KindSession, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: a}, LID: record.SessionLID(a, testMachine, 0), Links: record.Links{Prev: oldPage.AdvisoryID, Supersedes: []string{oldPage.AdvisoryID}}}, &record.SessionBody{NativeID: "77777777-7777-4777-8777-777777777777", NativeIDKind: record.NativeGlobal, MachineOS: "darwin", Chunks: []string{chunk.AdvisoryID}, SettledThrough: 0})
	k.append(page)
	b, _, _, eventB := historicalSessionFixture(t, k, "66666666-6666-4666-8666-666666666666", "")
	task := k.execute("review-create", "local.create_task", map[string]any{"goal": "explicit task"})
	tid := k.taskID(task)
	conclusion := k.execute("review-complete", "local.complete_task", map[string]any{"task_id": tid, "final_summary": "review conclusion", "token_estimate": 0})
	var cid, ref string
	k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=?", conclusion.op).Scan(&cid)
	k.s.conn.QueryRowContext(ctx, "SELECT call_ref FROM operation WHERE op=?", conclusion.op).Scan(&ref)
	bind := func(sk, eid string, prior ...string) SignedRecord {
		return k.signed(record.Header{Type: record.KindBinding, Prov: record.ProvDerived, LID: record.BindingLID(ref), Links: record.Links{Supersedes: prior}}, &record.BindingBody{CallRef: ref, Status: "bound", Confidence: "transcript-echo", Target: &record.BindTarget{SessionKey: sk}, Evidence: &record.BindEvidence{SightingEventIDs: []string{eid}}})
	}
	first := bind(a, oldEvent.ID)
	k.append(first)
	var hadWeb bool
	if err = k.s.write(ctx, func() error {
		d, e := k.s.load(ctx)
		if e != nil {
			return e
		}
		if e = d.computeTrust([]string{cid}); e != nil {
			return e
		}
		for _, tag := range d.trust[cid].Observed {
			if tag == "web" {
				hadWeb = true
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !hadWeb {
		t.Fatal("fixture did not expose historical web label before correction")
	}
	check := func() {
		t.Helper()
		var tags, witness int
		k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_observed_taint WHERE id=? AND tag='web'", cid).Scan(&tags)
		k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_taint_evidence WHERE id=? AND tag='web' AND evidence=? AND source=? AND boundary=?", cid, first.AdvisoryID, oldChunk.AdvisoryID, oldEvent.ID).Scan(&witness)
		if tags != 1 || witness != 1 {
			t.Fatalf("historical tag/witness lost: tags=%d witnesses=%d", tags, witness)
		}
		var unknown int
		k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_observed_taint WHERE id=? AND tag='taint-unknown'", cid).Scan(&unknown)
		if unknown != 0 {
			t.Fatal("uncertainty became a permanent observation")
		}
	}
	check()
	if text := k.release(conclusion); !strings.Contains(text, "web") {
		t.Fatal("historical web label was not disclosed")
	}
	revoke := k.op(record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: sig.KeyRefOf(historicalKey.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: k.o.PinnedGenesisID, Parents: []string{enroll.AdvisoryID}, Reason: "compromised"}, rootKey, rootKey)
	k.append(revoke)
	check()
	k.append(bind(b, eventB.ID, first.AdvisoryID))
	check()
	if err = k.s.Reindex(ctx); err != nil {
		t.Fatal(err)
	}
	check()
	erase := k.control(28101, record.KindErasure, oldChunk.AdvisoryID)
	k.append(erase)
	check()
	if result, e := k.s.Scrub(ctx, erase.AdvisoryID); e != nil || result.State != "complete" {
		t.Fatal("historical body scrub", result, e)
	}
	check()
	reopenDisclosureKernel(t, k)
	check()
}

func TestDisclosureHistoricalTaintRespectsBoundaryAndInitialInvalidSignature(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	sk, base, prior, first := historicalSessionFixture(t, k, "44444444-4444-4444-8444-444444444444", "")
	eid, err := record.EventID(sk, "assistant_final", record.Anchor{NativeItemID: "future-boundary"})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := record.ReviseEvent(record.Event{ID: eid, Seq: 1, Kind: "assistant_final", Prov: "transcript", Text: &record.Text{Body: "future tainted event"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	future := k.signed(record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.ChunkLID(sk, testMachine, eid), Trust: record.Trust{Taint: []string{"taint-unknown", "web"}}}, &record.ChunkBody{Events: []record.Event{ev}})
	k.append(future)
	page := k.signed(record.Header{Type: record.KindSession, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.SessionLID(sk, testMachine, 0), Links: record.Links{Prev: prior.AdvisoryID, Supersedes: []string{prior.AdvisoryID}}}, &record.SessionBody{NativeID: "44444444-4444-4444-8444-444444444444", NativeIDKind: record.NativeGlobal, MachineOS: "darwin", Chunks: []string{base.AdvisoryID, future.AdvisoryID}, SettledThrough: 1})
	k.append(page)
	task := k.execute("boundary-create", "local.create_task", map[string]any{"goal": "explicit boundary task"})
	tid := k.taskID(task)
	outcome := k.execute("boundary-complete", "local.complete_task", map[string]any{"task_id": tid, "final_summary": "boundary conclusion", "token_estimate": 0})
	var id, ref string
	k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=?", outcome.op).Scan(&id)
	k.s.conn.QueryRowContext(ctx, "SELECT call_ref FROM operation WHERE op=?", outcome.op).Scan(&ref)
	bind := func(event string, prev ...string) SignedRecord {
		return k.signed(record.Header{Type: record.KindBinding, Prov: record.ProvDerived, LID: record.BindingLID(ref), Links: record.Links{Supersedes: prev}}, &record.BindingBody{CallRef: ref, Status: "bound", Confidence: "transcript-echo", Target: &record.BindTarget{SessionKey: sk}, Evidence: &record.BindEvidence{SightingEventIDs: []string{event}}})
	}
	firstBinding := bind(first.ID)
	k.append(firstBinding)
	var n int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_observed_taint WHERE id=?", id).Scan(&n)
	if n != 0 {
		t.Fatal("future observation crossed evidenced boundary", n)
	}
	// A new unverified source cannot supply observation provenance or modify any
	// already committed body, outcome, grant, progress, projection or generation.
	badEventID, err := record.EventID(sk, "assistant_final", record.Anchor{NativeItemID: "unverified-observation"})
	if err != nil {
		t.Fatal(err)
	}
	badEvent, err := record.ReviseEvent(record.Event{ID: badEventID, Seq: 0, Kind: "assistant_final", Prov: "transcript", Text: &record.Text{Body: "unverified taint canary"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := k.signed(record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.ChunkLID(sk, testMachine, badEventID), Trust: record.Trust{Taint: []string{"foreign-path"}}}, &record.ChunkBody{Events: []record.Event{badEvent}})
	value := []byte(bad.Sigs[0].Value)
	if value[0] == 'A' {
		value[0] = 'B'
	} else {
		value[0] = 'A'
	}
	bad.Sigs[0].Value = string(value)
	before := disclosureGuardState(t, k)
	if _, err = k.s.Append(ctx, bad); err == nil {
		t.Fatal("initial invalid signature accepted")
	}
	requireSameDisclosureGuardState(t, k, before)
	k.append(bind(ev.ID, firstBinding.AdvisoryID))
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_observed_taint WHERE id=? AND tag='web'", id).Scan(&n)
	if n != 1 {
		t.Fatal("newly evidenced valid boundary was not observed", n)
	}
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_observed_taint WHERE id=? AND tag IN('taint-unknown','foreign-path')", id).Scan(&n)
	if n != 0 {
		t.Fatal("uncertainty or invalid signature became permanent", n)
	}
}
