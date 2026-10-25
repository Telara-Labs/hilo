package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// derivationFamilies is the exhaustive 07 §2.5.1 classification of
// hash-bearing content paths, one entry per table row in table order. A new
// retained digest needs a new row there, a new entry here and its own
// erasure case below.
var derivationFamilies = []string{
	"record-identity",     // BodyRef.digest, record id, signatures, receipt/grant/dependency/origin/supersession/tomb ids
	"event-revision",      // Event.Revision/Replaces, presence/equality witnesses, revision indexes
	"call-commitment",     // CallBody.args_hash/result_hash and every retained copy
	"operation-identity",  // Header.op, checkpoint/pause LIDs, supplied/fallback op ids, transition receipts
	"text-digest",         // Text.digest and every other full-text fingerprint
	"delivery-indexes",    // delivered-set/dedup keys, ACK/echo render ids, exposure and binding indexes
	"bundle-artifacts",    // bundle items_digest, manifest signatures, exported content ids
	"identity-metadata",   // H-based LIDs, session/source/repo ids, key ids, ruleset identities
	"event-id",            // event_id = "ev1:" + H("ev1", session_key, event_kind, anchor)
	"content-projections", // passages, FTS tokens, vector projections
}

// explicitConclusion is an owner-authored conclusion on task.
func (w *world) explicitConclusion(task, op, text string, deps ...string) SignedRecord {
	return w.signed(record.Header{Type: record.KindConclusion, LID: record.ExplicitConclusionLID(w.o.PinnedGenesisID, task), Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: record.H("op", op), Links: record.Links{DerivedFrom: deps}}, &record.ConclusionBody{Source: "explicit", Text: text})
}

func bodyDigest(t *testing.T, r SignedRecord) (string, string) {
	t.Helper()
	p, err := record.Parse(r.HeaderJCS, r.BodyJCS, r.AdvisoryID)
	if err != nil {
		t.Fatal(err)
	}
	return p.Header.LID, p.Header.Body.Digest
}

func eraseAndScrub(t *testing.T, s *Store, signer ControlSigner, ids ...string) {
	t.Helper()
	receipt, err := s.EraseExact(context.Background(), EraseRequest{IDs: ids}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := s.Scrub(context.Background(), receipt.Control); err != nil || res.State != "complete" {
		t.Fatal("scrub", res, err)
	}
}

// Erase an explicit conclusion by exact id; its task and LID survive. Neither a
// matching nor a different fresh same-LID record can reproduce the retained
// body digest, even signed by the same device key, because the destroyed salt
// was the only key to it.
func familyRecordIdentity(t *testing.T) {
	w := newWorld(t)
	task := w.task(1, "x5 surviving task")
	w.append(task)
	taskID := "22222222-2222-4222-8222-000000000001"
	const text = "x5_explicit_conclusion_canary_11aa"
	c := w.explicitConclusion(taskID, "x5-c", text, task.AdvisoryID)
	w.append(c)
	lid, digest := bodyDigest(t, c)
	salts := secretsOf(t, c.BodyJCS)
	eraseAndScrub(t, w.s, worldSigner{w.key}, c.AdvisoryID)
	snap := w.snapshot()
	if e := find(snap, task.AdvisoryID); e.State != "live" || e.TaskStatus != "active" {
		t.Fatal("exact conclusion erasure touched its task", e.State)
	}
	e := find(snap, c.AdvisoryID)
	if e.State != "invalidated" || len(e.BodyJCS) != 0 || len(e.HeaderJCS) == 0 {
		t.Fatal("erased conclusion header/body", e.State)
	}
	for _, candidate := range []string{text, "a different conclusion text"} {
		fresh := w.explicitConclusion(taskID, "x5-c", candidate, task.AdvisoryID)
		freshLID, freshDigest := bodyDigest(t, fresh)
		if freshLID != lid || freshDigest == digest || fresh.AdvisoryID == c.AdvisoryID {
			t.Fatal("fresh same-LID record verified the erased digest")
		}
	}
	assertAbsent(t, w.o.Dir, append(salts, text)...)
}

// The per-event salt is body-only and destroyed with every occurrence. A
// fresh revision of the same event and text cannot equal the retained one,
// and no witness ever links them.
func familyEventRevision(t *testing.T) {
	w := newWorld(t)
	const text = "x5_event_revision_canary_22bb"
	e := w.event(text)
	k := w.chunk(e)
	w.append(k)
	eraseAndScrub(t, w.s, worldSigner{w.key}, k.AdvisoryID)
	fresh := w.event(text)
	if fresh.ID != e.ID || fresh.Revision == e.Revision {
		t.Fatal("fresh revision reproduced the erased one")
	}
	again := w.chunk(fresh)
	w.append(again)
	if x := find(w.snapshot(), again.AdvisoryID); x.State != "invalidated" || len(x.BodyJCS) != 0 {
		t.Fatal("recaptured revision escaped", x.State)
	}
	if n := countRows(t, w.s, "SELECT count(*) FROM witness WHERE a=? OR b=?", fresh.Revision, fresh.Revision); n != 0 {
		t.Fatal("equality witness formed against an erased revision", n)
	}
	assertAbsent(t, w.o.Dir, e.Salt, fresh.Salt, text)
}

// Operation identities hold no content: the op, the checkpoint LID and the
// retained operation row survive exact erasure of the checkpoint, yet hold no
// text or plain text hash, and a new operation with the same text gets a new
// op, LID and digest.
func familyOperationIdentity(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	task := k.taskID(k.execute("x5-task", "local.create_task", map[string]any{"goal": "x5 op task"}))
	const text = "x5_operation_identity_canary_33cc"
	// Never released: an erased root that was shown holds every later output
	// of this machine, which would mask the fresh-operation comparison.
	r := k.execute("x5-op", "local.checkpoint_task", map[string]any{"task_id": task, "milestone": text})
	var root string
	if err := k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=? AND role='mutation'", r.op).Scan(&root); err != nil {
		t.Fatal(err)
	}
	entry := find(k.snapshot(), root)
	parsed, err := record.Parse(entry.HeaderJCS, entry.BodyJCS, root)
	if err != nil {
		t.Fatal(err)
	}
	salts := secretsOf(t, entry.BodyJCS)
	eraseAndScrub(t, k.s, worldSigner{k.key}, root)
	sum := sha256.Sum256([]byte(text))
	plain := hex.EncodeToString(sum[:])
	retained := find(k.snapshot(), root)
	if retained.State != "invalidated" || !strings.Contains(string(retained.HeaderJCS), parsed.Header.Op) || !strings.Contains(string(retained.HeaderJCS), parsed.Header.LID) {
		t.Fatal("operation identity not retained")
	}
	if strings.Contains(parsed.Header.Op, plain) || strings.Contains(string(retained.HeaderJCS), text) {
		t.Fatal("operation identity carries content")
	}
	var row string
	if err := k.s.conn.QueryRowContext(ctx, "SELECT op||tool||args_hash||call_ref||result FROM operation WHERE op=?", r.op).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row, text) || strings.Contains(row, plain) {
		t.Fatal("operation row retains content")
	}
	// A fresh operation with the same text, signed by the same device key.
	// (The engine itself holds every later same-machine output once an
	// executed root is erased, so the record is authored directly.)
	op := record.H("x5-fresh-op")
	fresh := k.signed(record.Header{Type: record.KindCheckpoint, LID: record.CheckpointLID(k.o.PinnedGenesisID, task, testMachine, op), Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: op}, &record.CheckpointBody{Milestone: text})
	fp, err := record.Parse(fresh.HeaderJCS, fresh.BodyJCS, fresh.AdvisoryID)
	if err != nil {
		t.Fatal(err)
	}
	if fp.Header.Op == parsed.Header.Op || fp.Header.LID == parsed.Header.LID || fp.Header.Body.Digest == parsed.Header.Body.Digest {
		t.Fatal("new operation reproduced erased identity or digest")
	}
	if n := countRows(t, k.s, "SELECT count(*) FROM task_state WHERE task=? AND status='active'", task); n != 1 {
		t.Fatal("exact checkpoint erasure touched its task", n)
	}
	assertAbsent(t, k.o.Dir, salts...)
}

// Text.digest is keyed by the event secret. Erasing the source purges the
// digest everywhere, including a copy in another salted body that names the
// source in its signed links, and a fresh event cannot reproduce it.
func familyTextDigest(t *testing.T) {
	w := newWorld(t)
	const text = "x5 text digest canary 44dd"
	e, err := record.ReviseTextEvent(record.Event{ID: w.event("x").ID, Seq: 1, Kind: "assistant_final", Prov: "transcript"}, nil, text, plainRedactor{}, 600)
	if err != nil {
		t.Fatal(err)
	}
	k := w.chunk(e)
	w.append(k)
	w.append(w.task(1, "x5 copy task"))
	copied := w.explicitConclusion("22222222-2222-4222-8222-000000000001", "x5-copy", "copied digest "+e.Text.Digest, k.AdvisoryID)
	w.append(copied)
	salts := append(secretsOf(t, k.BodyJCS), secretsOf(t, copied.BodyJCS)...)
	eraseAndScrub(t, w.s, worldSigner{w.key}, k.AdvisoryID)
	if x := find(w.snapshot(), copied.AdvisoryID); x.State != "invalidated" || len(x.BodyJCS) != 0 {
		t.Fatal("copied digest outlived its source", x.State)
	}
	fresh, err := record.ReviseTextEvent(record.Event{ID: e.ID, Seq: 1, Kind: "assistant_final", Prov: "transcript"}, nil, text, plainRedactor{}, 600)
	if err != nil || fresh.Text.Digest == e.Text.Digest {
		t.Fatal("fresh event reproduced the erased digest", err)
	}
	assertAbsent(t, w.o.Dir, append(salts, e.Text.Digest, text)...)
}

// Delivery, dedup, render and exposure indexes keep only opaque ids, nonces
// and generations; erasure removes render bodies and no index row holds the
// erased text or any of its secrets.
func familyDeliveryIndexes(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	const text = "x5_delivery_index_canary_55ee"
	c := k.task(1, text)
	k.append(c)
	lookup := k.execute("x5-lookup", "local.lookup_record", map[string]any{"record_id": c.AdvisoryID})
	if got := k.release(lookup); !strings.Contains(got, rendered(text)) {
		t.Fatal("fixture not delivered", got)
	}
	k.acknowledgeLatest(lookup.op)
	salts := secretsOf(t, c.BodyJCS)
	eraseAndScrub(t, k.s, worldSigner{k.key}, c.AdvisoryID)
	if n := countRows(t, k.s, "SELECT count(*) FROM render_body"); n != 0 {
		t.Fatal("render body survived", n)
	}
	for _, table := range []string{"delivery_confirmation", "render_item", "render_dep", "render_attempt", "exposure", "exposure_affect", "outcome_member", "outcome_dependency"} {
		rows, err := k.s.conn.QueryContext(ctx, "SELECT * FROM "+table)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			line := fmt.Sprint(values...)
			for _, f := range append(salts, text) {
				if strings.Contains(line, f) {
					rows.Close()
					t.Fatal("index retains erased content", table)
				}
			}
		}
		rows.Close()
	}
	if n := countRows(t, k.s, "SELECT count(*) FROM exposure WHERE root=?", c.AdvisoryID); n == 0 {
		t.Fatal("content-free exposure fact dropped by erasure")
	}
	assertAbsent(t, k.o.Dir, append(salts, text)...)
}

// LIDs, session/source ids and key ids are computed from identity inputs
// only: the retained header of an erased record recomputes from them and holds
// no content, and different content under the same identity shares the LID.
func familyIdentityMetadata(t *testing.T) {
	w := newWorld(t)
	const text = "x5_identity_metadata_canary_66ff"
	e := w.event(text)
	k := w.chunk(e)
	w.append(k)
	s := w.session([]string{k.AdvisoryID})
	w.append(s)
	eraseAndScrub(t, w.s, worldSigner{w.key}, k.AdvisoryID, s.AdvisoryID)
	sk := w.sessionKey()
	for id, want := range map[string]string{k.AdvisoryID: record.ChunkLID(sk, testMachine, e.ID), s.AdvisoryID: record.SessionLID(sk, testMachine, 0)} {
		x := find(w.snapshot(), id)
		h, err := record.Parse(x.HeaderJCS, nil, id)
		if err != nil {
			t.Fatal(err)
		}
		if x.State != "invalidated" || h.Header.LID != want || strings.Contains(string(x.HeaderJCS), text) {
			t.Fatal("retained identity is not content independent")
		}
	}
	other := w.chunk(w.event("entirely different content"))
	if lid, _ := bodyDigest(t, other); lid != record.ChunkLID(sk, testMachine, e.ID) {
		t.Fatal("LID depends on content")
	}
	assertAbsent(t, w.o.Dir, text)
}

// event_id is a content-independent identity. It survives as the ban key;
// any recapture of the same native item is suppressed before sealing whatever
// its text, and the ban rows hold no content.
func familyEventID(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	const text = "x5_event_id_canary_7700"
	e := w.event(text)
	if other := w.event("different text"); other.ID != e.ID {
		t.Fatal("event id depends on content")
	}
	k := w.chunk(e)
	w.append(k)
	eraseAndScrub(t, w.s, worldSigner{w.key}, k.AdvisoryID)
	if n := countRows(t, w.s, "SELECT count(*) FROM event_ban WHERE event_id=?", e.ID); n == 0 {
		t.Fatal("event id ban not retained")
	}
	if n := countRows(t, w.s, "SELECT count(*) FROM event_ban WHERE instr(owner||session||event_id||cause, ?)>0", text); n != 0 {
		t.Fatal("ban row holds content")
	}
	supp, err := w.s.Suppressed(ctx, SourceOccurrence{Owner: w.o.PinnedGenesisID, SessionKey: w.sessionKey(), EventIDs: []string{e.ID}})
	if err != nil || !supp.Suppressed {
		t.Fatal("recapture of the erased event id not suppressed", supp, err)
	}
	assertAbsent(t, w.o.Dir, text)
}

// Passages, FTS tokens and vectors are erasable projections: they purge with
// their record, a stale worker cannot republish, and no token survives scrub.
func familyContentProjections(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	const text = "x5_projection_canary_8811"
	c := seedFreshCheckpoint(w, text)
	var generation int64
	if err := w.s.conn.QueryRowContext(ctx, "SELECT generation FROM projection_job WHERE id=?", c.AdvisoryID).Scan(&generation); err != nil {
		t.Fatal("projection job", err)
	}
	if err := w.s.PublishProjection(ctx, JobToken{c.AdvisoryID, generation}, Projection{Model: "x5", Vector: []byte(strings.Repeat("v", 256))}); err != nil {
		t.Fatal(err)
	}
	if countRows(t, w.s, "SELECT count(*) FROM vector WHERE id=?", c.AdvisoryID) != 1 || countRows(t, w.s, "SELECT count(*) FROM search WHERE search MATCH ?", text) == 0 {
		t.Fatal("projection fixture")
	}
	salts := secretsOf(t, c.BodyJCS)
	eraseAndScrub(t, w.s, worldSigner{w.key}, c.AdvisoryID)
	for _, q := range []string{"SELECT count(*) FROM passage WHERE id=?", "SELECT count(*) FROM vector WHERE id=?", "SELECT count(*) FROM projection_job WHERE id=?"} {
		if n := countRows(t, w.s, q, c.AdvisoryID); n != 0 {
			t.Fatal("projection survived", q)
		}
	}
	if n := countRows(t, w.s, "SELECT count(*) FROM search WHERE search MATCH ?", text); n != 0 {
		t.Fatal("fts token survived", n)
	}
	if Code(w.s.PublishProjection(ctx, JobToken{c.AdvisoryID, generation}, Projection{Model: "x5", Vector: []byte(strings.Repeat("v", 256))})) != "stale_projection" {
		t.Fatal("stale worker republished an erased projection")
	}
	assertAbsent(t, w.o.Dir, append(salts, text, strings.Repeat("v", 256))...)
}

// Every 07 §2.5.1 derivation family has an erasure case that runs against the
// actual SQLite store. A family without a case, or a case for an unlisted
// family, fails before anything runs.
func TestX5EveryDerivationFamilyHasAnErasureCase(t *testing.T) {
	cases := map[string]func(*testing.T){
		"record-identity":     familyRecordIdentity,
		"event-revision":      familyEventRevision,
		"call-commitment":     TestV3ErasureDestroysOriginalComparatorAndFreshSameLIDCannotMatch,
		"operation-identity":  familyOperationIdentity,
		"text-digest":         familyTextDigest,
		"delivery-indexes":    familyDeliveryIndexes,
		"bundle-artifacts":    TestBundleImportOtherDeviceThenExactRootErasure,
		"identity-metadata":   familyIdentityMetadata,
		"event-id":            familyEventID,
		"content-projections": familyContentProjections,
	}
	if len(derivationFamilies) != 10 {
		t.Fatal("07 §2.5.1 lists ten derivation families", len(derivationFamilies))
	}
	listed := map[string]bool{}
	for _, f := range derivationFamilies {
		if listed[f] {
			t.Fatal("duplicate family", f)
		}
		listed[f] = true
		if cases[f] == nil {
			t.Fatalf("derivation family %q has no erasure case", f)
		}
	}
	for name := range cases {
		if !listed[name] {
			t.Fatalf("erasure case %q names no listed family", name)
		}
	}
	for _, f := range derivationFamilies {
		t.Run(f, cases[f])
	}
}
