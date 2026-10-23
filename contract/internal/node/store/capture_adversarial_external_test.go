package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// These fixtures exercise the public producer seam against the actual database.
// They do not share private admission helpers with the implementation.
type captureFixture struct {
	s           *store.Store
	opts        store.Options
	key         ed25519.PrivateKey
	req         store.CaptureRequest
	plan        store.CommitPlan
	chunk, page store.SignedRecord
}

func newCaptureFixture(t *testing.T, text string) *captureFixture {
	t.Helper()
	ctx := context.Background()
	seed := sha256.Sum256([]byte("synthetic-producer-external-fixture"))
	key := ed25519.NewKeyFromSeed(seed[:])
	pub := key.Public().(ed25519.PublicKey)
	const machine = "19111111-1111-4111-8111-111111111111"
	const native = "29222222-2222-4222-8222-222222222222"
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	opts := store.Options{Dir: filepath.Join(base, "node"), PinnedGenesisID: sig.KeyID(pub), LocalMachineID: machine}
	s, err := store.Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	f := &captureFixture{s: s, opts: opts, key: key}
	t.Cleanup(func() { _ = f.s.Close() })
	genesis, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Genesis: opts.PinnedGenesisID, Subject: sig.KeyRefOf(pub, record.RoleDevice, machine)}, pub, machine, 1761150000000, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Append(ctx, extensionInput(t, genesis.Rec, key)); err != nil {
		t.Fatal(err)
	}
	session, err := record.SessionKey("claude-code", "local", record.NativeGlobal, native, machine)
	if err != nil {
		t.Fatal(err)
	}
	source, err := record.SourceKey("claude-code", machine, ".claude/projects/fixture/"+native+".jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var golden record.Ruleset
	if err = json.Unmarshal(contract.RedactionGoldenV1(), &golden); err != nil {
		t.Fatal(err)
	}
	eventID, err := record.EventID(session, "user_prompt", record.Anchor{NativeItemID: "external-message", Part: 4096})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := record.ReviseEvent(record.Event{ID: eventID, Seq: 0, Kind: "user_prompt", Prov: "transcript", Ruleset: golden.Epoch, Text: &record.Text{Body: text, Bytes: len(text)}}, nil, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	reader := record.SourceRef{Reader: "claude-code", ReaderVersion: "native-jsonl-runtime.1"}
	f.req = store.CaptureRequest{Occurrence: store.SourceOccurrence{Owner: opts.PinnedGenesisID, Source: source, SessionKey: session}, AuthorKeyID: opts.PinnedGenesisID, Reader: reader, RulesetFingerprint: golden.Fingerprint(), EventIDs: []string{eventID}, Range: store.CaptureRange{First: 0, LastExclusive: 1}}
	build := func(kind record.Kind, lid string, body any, links record.Links) store.SignedRecord {
		r, err := record.Build(record.Header{Type: kind, LID: lid, At: 1761150000001, Author: record.Author{KeyID: opts.PinnedGenesisID, MachineID: machine}, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: session, Source: source, Client: &record.ClientRef{ID: "claude-code", Surface: "cli"}}, Red: record.Redact{Profile: record.ProfileLocal, Epoch: golden.Epoch, Fingerprint: golden.Fingerprint()}, Links: links}, body, bytes.Repeat([]byte{8}, 32))
		if err != nil {
			t.Fatal(err)
		}
		return extensionInput(t, r, key)
	}
	f.chunk = build(record.KindChunk, record.ChunkLID(session, machine, eventID), &record.ChunkBody{Events: []record.Event{ev}}, record.Links{})
	f.page = build(record.KindSession, record.SessionLID(session, machine, 0), &record.SessionBody{NativeID: native, NativeIDKind: record.NativeGlobal, Page: 0, Chunks: []string{f.chunk.AdvisoryID}, SettledThrough: 0, Reader: &reader}, record.Links{})
	f.plan = store.CommitPlan{NewRecords: []store.SignedRecord{f.chunk, f.page}, Next: store.CaptureNext{SettledThrough: 0, LastSourceRecordIDs: []string{f.chunk.AdvisoryID}, SessionPageIDs: []store.PageRef{{Page: 0, ID: f.page.AdvisoryID}}, Reader: reader, RulesetFingerprint: golden.Fingerprint(), Range: f.req.Range}}
	return f
}

func TestCaptureWholeBatchRefusalLeavesNoCandidateBytes(t *testing.T) {
	const canary = "UNCOMMITTED_CAPTURE_BODY_eb8607de8f57429e"
	f := newCaptureFixture(t, canary)
	ctx := context.Background()
	bad := f.plan
	bad.NewRecords = append([]store.SignedRecord(nil), bad.NewRecords...)
	bad.NewRecords[1].Sigs = append([]record.Signature(nil), bad.NewRecords[1].Sigs...)
	prefix := "A"
	if bad.NewRecords[1].Sigs[0].Value[0] == 'A' {
		prefix = "B"
	}
	bad.NewRecords[1].Sigs[0].Value = prefix + bad.NewRecords[1].Sigs[0].Value[1:]
	if _, err := f.s.Capture(ctx, f.req, func(*store.CaptureTxn) (store.CommitPlan, error) { return bad, nil }); err == nil {
		t.Fatal("invalid second record committed first record")
	}
	inspection, err := f.s.InspectCapture(ctx, f.req.Occurrence)
	if err != nil || inspection.Progress.Version != 0 {
		t.Fatal("refused batch advanced progress", inspection, err)
	}
	snap, err := f.s.Snapshot(ctx, store.ReadRequest{})
	if err != nil || len(snap.Entries) != 1 {
		t.Fatal("refused batch persisted a record", len(snap.Entries), err)
	}
	assertNoManagedCanary(t, f.opts.Dir, canary)
	if err = f.s.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoManagedCanary(t, f.opts.Dir, canary)
}

func TestCaptureProducerErrorAndExpiredViewDoNotWrite(t *testing.T) {
	f := newCaptureFixture(t, "private candidate")
	ctx := context.Background()
	var expired *store.CaptureTxn
	_, err := f.s.Capture(ctx, f.req, func(tx *store.CaptureTxn) (store.CommitPlan, error) {
		expired = tx
		return f.plan, errors.New("private producer error")
	})
	if err == nil {
		t.Fatal("producer failure committed")
	}
	if expired == nil {
		t.Fatal("valid request never reached producer", err)
	}
	if _, err = expired.Context(); store.Code(err) != "capture_txn_expired" {
		t.Fatal("escaped transaction remained usable", err)
	}
	if _, err = expired.Progress(); store.Code(err) != "capture_txn_expired" {
		t.Fatal("escaped progress remained usable", err)
	}
	if _, err = expired.Events(f.req.EventIDs); store.Code(err) != "capture_txn_expired" {
		t.Fatal("escaped event view remained usable", err)
	}
	inspection, err := f.s.InspectCapture(ctx, f.req.Occurrence)
	if err != nil || inspection.Progress.Version != 0 {
		t.Fatal("producer error advanced progress", inspection, err)
	}
}

func TestCaptureLostAckReceiptSurvivesErasureWithoutProducer(t *testing.T) {
	f := newCaptureFixture(t, "ERASABLE_CAPTURE_213470ec7c9241b3")
	ctx := context.Background()
	first, err := f.s.Capture(ctx, f.req, func(*store.CaptureTxn) (store.CommitPlan, error) { return f.plan, nil })
	if err != nil || first.Status != "committed" || first.ResultingProgress.Version != 1 {
		t.Fatal("capture did not commit", first, err)
	}
	lid, err := record.ControlLID(record.KindErasure, f.opts.PinnedGenesisID, "b1111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	r, err := record.Build(record.Header{Type: record.KindErasure, LID: lid, At: 1761150000002, Prov: record.ProvUser, Author: record.Author{KeyID: f.opts.PinnedGenesisID, MachineID: f.opts.LocalMachineID}, Red: record.Redact{Profile: record.ProfileLocal}}, &record.ErasureBody{Selectors: record.Selectors{IDs: []string{f.chunk.AdvisoryID}}, Reason: "user_request"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.ApplyControl(ctx, extensionInput(t, r, f.key)); err != nil {
		t.Fatal(err)
	}
	scrubbed, err := f.s.Scrub(ctx, r.ID)
	if err != nil || scrubbed.State != "complete" {
		t.Fatal("capture erasure did not physically settle", scrubbed, err)
	}
	if err = f.s.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoManagedCanary(t, f.opts.Dir, "ERASABLE_CAPTURE_213470ec7c9241b3")
	var erasedBody record.ChunkBody
	if err = json.Unmarshal(f.chunk.BodyJCS, &erasedBody); err != nil {
		t.Fatal(err)
	}
	assertNoManagedCanary(t, f.opts.Dir, erasedBody.Events[0].Salt)
	f.s, err = store.Open(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	// A competing prepared batch describes different observations at the same
	// old version. It must learn what actually committed before suppression/CAS.
	retry := f.req
	retry.Range = store.CaptureRange{First: 0, LastExclusive: 2}
	called := false
	got, err := f.s.Capture(ctx, retry, func(*store.CaptureTxn) (store.CommitPlan, error) {
		called = true
		return store.CommitPlan{}, errors.New("must not mint")
	})
	if err != nil || called || got.Status != "prior_transition_committed" {
		t.Fatal("lost ACK invoked producer or hid committed receipt", got.Status, called, err)
	}
	if got.TransitionID != first.TransitionID || !reflect.DeepEqual(got.ActualRecordRefs, first.ActualRecordRefs) || got.ResultingProgress.Range != first.ResultingProgress.Range || got.ResultingProgress.Version != 1 {
		t.Fatal("retry substituted its own candidate facts", got, first)
	}
	if got.CurrentAvailability[f.chunk.AdvisoryID] == "available" {
		t.Fatal("erased body reported available")
	}
	snap, err := f.s.Snapshot(ctx, store.ReadRequest{IDs: []string{f.chunk.AdvisoryID, f.page.AdvisoryID}})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range snap.Entries {
		if len(entry.BodyJCS) != 0 {
			t.Fatal("receipt replay resurrected erased body")
		}
	}
	assertNoManagedCanary(t, f.opts.Dir, erasedBody.Events[0].Salt)
}

func TestCaptureViewsAreDetachedAndNoChangeKeepsVersion(t *testing.T) {
	f := newCaptureFixture(t, "detached producer history")
	ctx := context.Background()
	first, err := f.s.Capture(ctx, f.req, func(*store.CaptureTxn) (store.CommitPlan, error) { return f.plan, nil })
	if err != nil {
		t.Fatal(err)
	}
	q := f.req
	q.ExpectedVersion = first.ResultingProgress.Version
	var escaped *store.CaptureTxn
	got, err := f.s.Capture(ctx, q, func(tx *store.CaptureTxn) (store.CommitPlan, error) {
		escaped = tx
		before, err := tx.PriorSource()
		if err != nil || len(before) != 1 {
			t.Fatal("missing prior source", len(before), err)
		}
		want := append([]byte(nil), before[0].BodyJCS...)
		before[0].BodyJCS[0] ^= 0xff
		after, err := tx.PriorSource()
		if err != nil || !bytes.Equal(after[0].BodyJCS, want) {
			t.Fatal("prior source aliases transaction")
		}
		pages, err := tx.SessionPages()
		if err != nil || len(pages) != 1 {
			t.Fatal("missing page history", len(pages), err)
		}
		wantPage := append([]byte(nil), pages[0].BodyJCS...)
		pages[0].BodyJCS[0] ^= 0xff
		pagesAgain, err := tx.SessionPages()
		if err != nil || !bytes.Equal(pagesAgain[0].BodyJCS, wantPage) {
			t.Fatal("page history aliases transaction")
		}
		events, err := tx.Events(q.EventIDs)
		id := q.EventIDs[0]
		if err != nil || !events[id].KnownPresence || !events[id].CompleteFrontier || len(events[id].Copies) != 1 {
			t.Fatal("missing complete event history", events, err)
		}
		copyEvent := events[id]
		copyEvent.Copies[0].Event.Text.Body = "mutated copy"
		copyEvent.Facts.Presence[0].Replaces = []string{record.H("invented-parent")}
		copyEvent.Facts.CurrentSources[f.chunk.AdvisoryID] = false
		eventsAgain, err := tx.Events(q.EventIDs)
		if err != nil || eventsAgain[id].Copies[0].Event.Text.Body != "detached producer history" || len(eventsAgain[id].Facts.Presence[0].Replaces) != 0 || !eventsAgain[id].Facts.CurrentSources[f.chunk.AdvisoryID] {
			t.Fatal("event facts alias transaction", err)
		}
		progress, err := tx.Progress()
		if err != nil {
			t.Fatal(err)
		}
		progress.LastSourceRecords[0].ID = record.H("invented-progress")
		progressAgain, err := tx.Progress()
		if err != nil || progressAgain.LastSourceRecords[0].ID != f.chunk.AdvisoryID {
			t.Fatal("progress aliases transaction", err)
		}
		return store.CommitPlan{ReuseRecordIDs: []string{f.chunk.AdvisoryID, f.page.AdvisoryID}, Next: f.plan.Next}, nil
	})
	if err != nil || got.Status != "no_change" || got.ResultingProgress.Version != 1 {
		t.Fatal("unchanged capture advanced progress", got, err)
	}
	if _, err = escaped.PriorSource(); store.Code(err) != "capture_txn_expired" {
		t.Fatal("successful callback view escaped", err)
	}
	snap, err := f.s.Snapshot(ctx, store.ReadRequest{IDs: []string{f.chunk.AdvisoryID}})
	if err != nil || len(snap.Entries) != 1 || !bytes.Equal(snap.Entries[0].BodyJCS, f.chunk.BodyJCS) {
		t.Fatal("producer view mutation reached database", err)
	}
}

func TestCaptureRechecksNamedAuthorAcrossStoreHandles(t *testing.T) {
	f := newCaptureFixture(t, "unminted after revoke")
	ctx := context.Background()
	initial, err := f.s.Snapshot(ctx, store.ReadRequest{})
	if err != nil || len(initial.Entries) != 1 {
		t.Fatal("missing genesis", err)
	}
	other, err := store.Open(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	seed := sha256.Sum256([]byte("synthetic-secondary-capture-key"))
	secondary := ed25519.NewKeyFromSeed(seed[:])
	pub := secondary.Public().(ed25519.PublicKey)
	add, err := sig.BuildKeyOp(record.KeyOpBody{
		Op: record.OpDeviceAdd, Genesis: f.opts.PinnedGenesisID,
		Subject: sig.KeyRefOf(pub, record.RoleDevice, f.opts.LocalMachineID),
		Parents: []string{initial.Entries[0].ID},
	}, f.key.Public().(ed25519.PublicKey), f.opts.LocalMachineID, 1761150000003, f.key, secondary)
	if err != nil {
		t.Fatal(err)
	}
	toWire := func(op *sig.KeyOp) store.SignedRecord {
		return store.SignedRecord{HeaderJCS: op.Rec.HeaderJCS, BodyJCS: op.Rec.BodyJCS, Sigs: op.Sigs, AdvisoryID: op.Rec.ID}
	}
	if _, err = other.Append(ctx, toWire(add)); err != nil {
		t.Fatal(err)
	}
	// The original handle observes an active named key. Another handle revokes
	// it before production; authoring must consult authority inside the writer.
	q := f.req
	q.AuthorKeyID = sig.KeyID(pub)
	revoke, err := sig.BuildKeyOp(record.KeyOpBody{
		Op: record.OpDeviceRevoke, Genesis: f.opts.PinnedGenesisID,
		Subject: sig.KeyRefOf(pub, record.RoleDevice, f.opts.LocalMachineID),
		Parents: []string{add.Rec.ID}, Reason: "compromised",
	}, f.key.Public().(ed25519.PublicKey), f.opts.LocalMachineID, 1761150000004, f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.Append(ctx, toWire(revoke)); err != nil {
		t.Fatal(err)
	}
	called := false
	_, err = f.s.Capture(ctx, q, func(*store.CaptureTxn) (store.CommitPlan, error) {
		called = true
		return f.plan, nil
	})
	if err == nil || called {
		t.Fatal("revoked named key reached producer", called, err)
	}
	inspection, err := f.s.InspectCapture(ctx, q.Occurrence)
	if err != nil || inspection.Progress.Version != 0 {
		t.Fatal("revoked author advanced progress", inspection, err)
	}
}

func TestCaptureRefusesAnotherSourceCompetingForSessionPage(t *testing.T) {
	f := newCaptureFixture(t, "original source")
	ctx := context.Background()
	if _, err := f.s.Capture(ctx, f.req, func(*store.CaptureTxn) (store.CommitPlan, error) { return f.plan, nil }); err != nil {
		t.Fatal(err)
	}
	q := f.req
	q.Occurrence.Source = record.H("different-source-path")
	eventID, err := record.EventID(q.Occurrence.SessionKey, "user_prompt", record.Anchor{NativeItemID: "different-message", Part: 4096})
	if err != nil {
		t.Fatal(err)
	}
	q.EventIDs = []string{eventID}
	const canary = "FOREIGN_SOURCE_PAGE_0c0af2851b414341"
	chunk, err := record.Parse(f.chunk.HeaderJCS, f.chunk.BodyJCS, "")
	if err != nil {
		t.Fatal(err)
	}
	body := chunk.Body.(*record.ChunkBody)
	e := body.Events[0]
	e.ID, e.Revision, e.Salt = eventID, "", ""
	e.Text = &record.Text{Body: canary, Bytes: len(canary)}
	e, err = record.ReviseEvent(e, nil, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	body.Events = []record.Event{e}
	h := chunk.Header
	h.Subj.Source = q.Occurrence.Source
	h.LID = record.ChunkLID(q.Occurrence.SessionKey, f.opts.LocalMachineID, eventID)
	newChunk, err := record.Build(h, body, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	page, err := record.Parse(f.page.HeaderJCS, f.page.BodyJCS, "")
	if err != nil {
		t.Fatal(err)
	}
	pageBody := page.Body.(*record.SessionBody)
	pageBody.Chunks = []string{newChunk.ID}
	h = page.Header
	h.Subj.Source = q.Occurrence.Source
	newPage, err := record.Build(h, pageBody, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	plan := f.plan
	plan.NewRecords = []store.SignedRecord{extensionInput(t, newChunk, f.key), extensionInput(t, newPage, f.key)}
	plan.Next.LastSourceRecordIDs = []string{newChunk.ID}
	plan.Next.SessionPageIDs = []store.PageRef{{Page: 0, ID: newPage.ID}}
	if _, err = f.s.Capture(ctx, q, func(*store.CaptureTxn) (store.CommitPlan, error) { return plan, nil }); err == nil {
		t.Fatal("second source created a competing head in the same session/page namespace")
	}
	inspection, err := f.s.InspectCapture(ctx, q.Occurrence)
	if err != nil || inspection.Progress.Version != 0 {
		t.Fatal("foreign source refusal advanced progress", inspection, err)
	}
	assertNoManagedCanary(t, f.opts.Dir, canary)
}
