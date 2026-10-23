package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"os"
	"testing"
)

func TestRetainedTombSurvivesLaterControlClassification(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{22}, 32))
	keyop := w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(other.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: w.o.PinnedGenesisID, Parents: []string{w.genesis.AdvisoryID}}, w.key, w.key, other)
	w.append(w.control(1, record.KindErasure, keyop.AdvisoryID))
	y := w.task(1, "neverrevive", keyop.AdvisoryID)
	w.append(y)
	w.append(keyop)
	w.append(y)
	if x := find(w.snapshot(), y.AdvisoryID); x.State != "invalidated" || len(x.BodyJCS) != 0 {
		t.Fatal("committed descendant tomb stopped applying")
	}
	if x := find(w.snapshot(), keyop.AdvisoryID); len(x.BodyJCS) == 0 || x.SignatureStatus != "verified" {
		t.Fatal("security key operation purged")
	}
	var n int
	if w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect WHERE target=?", keyop.AdvisoryID).Scan(&n) != nil || n != 0 {
		t.Fatal("key operation charged against deletion budget")
	}
	w.s.Close()
	s, e := Open(ctx, w.o)
	if e != nil {
		t.Fatal(e)
	}
	w.s = s
	if x := find(w.snapshot(), y.AdvisoryID); x.State != "invalidated" || len(x.BodyJCS) != 0 {
		t.Fatal("restart lost permanent tomb")
	}
}
func TestTombedHeaderLearnsOccurrenceWithoutBodyPersistence(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	e := w.event("late_erased_event_canary")
	full := w.chunk(e)
	header := full
	header.BodyJCS = nil
	first := w.append(header)
	w.append(w.control(1, record.KindErasure, full.AdvisoryID))
	late := w.append(full)
	if late.Sequence != first.Sequence || len(find(w.snapshot(), full.AdvisoryID).BodyJCS) != 0 {
		t.Fatal("late body persisted")
	}
	normalized := w.snapshot()
	repeat := w.append(full)
	if repeat.Generation != late.Generation || w.snapshot().Generation != normalized.Generation {
		t.Fatal("repeated tomb body changed generation")
	}
	var seen int
	if w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM body_seen WHERE id=?", full.AdvisoryID).Scan(&seen) != nil || seen != 1 {
		t.Fatal("body seen not persisted")
	}
	fresh := w.chunk(w.event("late_erased_event_canary"))
	w.append(fresh)
	if x := find(w.snapshot(), fresh.AdvisoryID); x.State != "invalidated" || len(x.BodyJCS) != 0 {
		t.Fatal("fresh occurrence escaped")
	}
	supp, e2 := w.s.Suppressed(ctx, SourceOccurrence{Owner: w.o.PinnedGenesisID, SessionKey: w.sessionKey()})
	if e2 != nil || !supp.Suppressed {
		t.Fatal("pre-open session did not suppress", e2)
	}
	if _, e2 = w.s.Suppressed(ctx, SourceOccurrence{Owner: w.o.PinnedGenesisID}); Code(e2) != "invalid_request" {
		t.Fatal("empty selector accepted")
	}
	for _, suffix := range []string{"", "-wal"} {
		b, e2 := os.ReadFile(w.s.path + suffix)
		if e2 == nil && bytes.Contains(b, []byte("late_erased_event_canary")) {
			t.Fatal("late erased body reached disk")
		}
	}
}
func TestRecallKnownMixedAndUnknownOrderingHold(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	a := w.task(1, "recalltarget")
	w.append(a)
	recall := w.event("recall marker")
	ar, err := record.Parse(a.HeaderJCS, a.BodyJCS, a.AdvisoryID)
	if err != nil {
		t.Fatal(err)
	}
	recall.Seq = 10
	recall.Recalled = []string{ar.Header.LID + "@" + a.AdvisoryID}
	recall.Revision = ""
	recall.Salt = ""
	earlyEvent := w.event("known earlier unrelated output")
	earlyEvent.Seq = 5
	earlyEvent.ID, _ = record.EventID(w.sessionKey(), "assistant_final", record.Anchor{NativeItemID: "early-known"})
	earlyEvent.Revision = ""
	earlyEvent.Salt = ""
	early := w.chunk(earlyEvent)
	w.append(early)
	rc := w.chunk(recall)
	w.append(rc)
	later := w.event("possibly repeated output")
	later.Seq = 11
	later.Revision = ""
	later.Salt = ""
	late := w.chunk(later)
	w.append(late)
	pre := w.event("earlier in mixed chunk")
	pre.ID, _ = record.EventID(w.sessionKey(), "assistant_final", record.Anchor{NativeItemID: "mixed-earlier"})
	pre.Revision = ""
	pre.Salt = ""
	post := w.event("later in mixed chunk")
	post.Seq = 12
	post.ID, _ = record.EventID(w.sessionKey(), "assistant_final", record.Anchor{NativeItemID: "mixed-later"})
	post.Revision = ""
	post.Salt = ""
	mixed := w.signed(record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: w.sessionKey()}, LID: record.ChunkLID(w.sessionKey(), testMachine, pre.ID)}, &record.ChunkBody{Events: []record.Event{pre, post}})
	w.append(mixed)
	unknown := w.signed(record.Header{Type: record.KindDigest, Prov: record.ProvDerived, Subj: record.Subject{SessionKey: w.sessionKey()}, LID: record.DigestLID(w.sessionKey(), testMachine)}, &record.DigestBody{HasOutcome: true, Outcome: "unknown ordering output"})
	w.append(unknown)
	w.append(w.control(1, record.KindErasure, a.AdvisoryID))
	if x := find(w.snapshot(), early.AdvisoryID); x.State != "live" || len(x.BodyJCS) == 0 {
		t.Fatal("known earlier output incorrectly held", x.State)
	}
	var known, lo, hi int
	if w.s.conn.QueryRowContext(ctx, "SELECT known,first_seq,last_seq FROM item_order WHERE id=?", early.AdvisoryID).Scan(&known, &lo, &hi) != nil || known != 1 || lo != 5 || hi != 5 {
		t.Fatal("known order not persisted", known, lo, hi)
	}
	for _, r := range []SignedRecord{late, mixed, unknown} {
		x := find(w.snapshot(), r.AdvisoryID)
		if x.State != "lineage-hold" || len(x.BodyJCS) != 0 {
			t.Fatal("recalled output served", x.State)
		}
	}
	var n int
	if w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM passage WHERE id IN (?,?)", late.AdvisoryID, unknown.AdvisoryID).Scan(&n) != nil || n != 0 {
		t.Fatal("held text searchable")
	}
	w.s.Close()
	s, e := Open(ctx, w.o)
	if e != nil {
		t.Fatal(e)
	}
	w.s = s
	if x := find(w.snapshot(), early.AdvisoryID); x.State != "live" || len(x.BodyJCS) == 0 {
		t.Fatal("restart forgot earlier order")
	}
	if x := find(w.snapshot(), late.AdvisoryID); x.State != "lineage-hold" {
		t.Fatal("restart lost recall order")
	}
}
func TestHeldKeyOperationRejectsOversizedSignatureBeforePersistence(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, 32))
	r := w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(other.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: w.o.PinnedGenesisID, Parents: []string{record.H("missing-parent")}}, w.key, w.key, other)
	r.Sigs[0].Value = "signature_canary_private_2cc55b"
	parsed, e := record.Parse(r.HeaderJCS, r.BodyJCS, r.AdvisoryID)
	if e != nil {
		t.Fatal(e)
	}
	genesis, e := record.Parse(w.genesis.HeaderJCS, w.genesis.BodyJCS, w.genesis.AdvisoryID)
	if e != nil {
		t.Fatal(e)
	}
	kr := sig.NewKeyring(w.o.PinnedGenesisID)
	if e = kr.Add(&sig.KeyOp{Rec: genesis, Body: genesis.Body.(*record.KeyOpBody), Sigs: w.genesis.Sigs, AdmittedSeq: 1}); e != nil {
		t.Fatal(e)
	}
	if e = kr.Add(&sig.KeyOp{Rec: parsed, Body: parsed.Body.(*record.KeyOpBody), Sigs: r.Sigs, AdmittedSeq: 2}); e != nil || kr.State().Status[r.AdvisoryID] != sig.OpHeldParents {
		t.Fatal("fixture did not exercise deferred authorizer shape", e)
	}
	if _, e = w.s.Append(ctx, r); Code(e) != "invalid_record" || e.Error() != "invalid_record" {
		t.Fatal("signature shape leaked/accepted", e)
	}
	for _, suffix := range []string{"", "-wal"} {
		b, e := os.ReadFile(w.s.path + suffix)
		if e == nil && bytes.Contains(b, []byte("signature_canary_private_2cc55b")) {
			t.Fatal("signature metadata persisted")
		}
	}
}
func TestCurrentDependencyAuthorityLossBecomesPending(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	a := w.key
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{24}, 32))
	c := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{25}, 32))
	genesis := w.o.PinnedGenesisID
	enroll := w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(b.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{w.genesis.AdvisoryID}}, a, a, b)
	w.append(enroll)
	parent := w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(c.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{enroll.AdvisoryID}}, a, a, c)
	revoke := w.op(record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: sig.KeyRefOf(b.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{parent.AdvisoryID}, Reason: "compromised"}, a, a)
	w.append(revoke)
	w.key = b
	source := w.task(1, "authoritysourcecanary")
	w.append(source)
	w.key = a
	copy := w.task(2, "authoritycopiedcanary", source.AdvisoryID)
	old := w.append(copy)
	if len(find(w.snapshot(), copy.AdvisoryID).BodyJCS) == 0 {
		t.Fatal("fixture not live")
	}
	w.append(parent)
	if x := find(w.snapshot(), copy.AdvisoryID); x.State != "ancestry-pending" || len(x.BodyJCS) != 0 {
		t.Fatal("unverified dependency left copied data live", x.State)
	}
	if Code(w.s.PublishProjection(ctx, JobToken{copy.AdvisoryID, old.Generation}, Projection{Model: "m1", Vector: make([]byte, 256)})) != "stale_projection" {
		t.Fatal("old worker bypassed current dependency")
	}
	var n int
	if w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM passage WHERE id=?", copy.AdvisoryID).Scan(&n) != nil || n != 0 {
		t.Fatal("copied unverified content searchable")
	}
	w.s.Close()
	s, e := Open(ctx, w.o)
	if e != nil {
		t.Fatal(e)
	}
	w.s = s
	if x := find(w.snapshot(), copy.AdvisoryID); x.State != "ancestry-pending" || len(x.BodyJCS) != 0 {
		t.Fatal("restart lost dependency ineligibility")
	}
}
func TestRecalledAuthorityLossPropagatesKnownUnknownAndCopied(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	a := w.key
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{27}, 32))
	c := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{28}, 32))
	genesis := w.o.PinnedGenesisID
	enroll := w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(b.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{w.genesis.AdvisoryID}}, a, a, b)
	w.append(enroll)
	parent := w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(c.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{enroll.AdvisoryID}}, a, a, c)
	revoke := w.op(record.KeyOpBody{Op: record.OpDeviceRevoke, Subject: sig.KeyRefOf(b.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Genesis: genesis, Parents: []string{parent.AdvisoryID}, Reason: "compromised"}, a, a)
	w.append(revoke)
	w.key = b
	source := w.task(1, "semantic_authority_source")
	w.append(source)
	w.key = a
	parsed, e := record.Parse(source.HeaderJCS, source.BodyJCS, source.AdvisoryID)
	if e != nil {
		t.Fatal(e)
	}
	earlyEvent := w.event("known earlier semantic output")
	earlyEvent.Seq = 5
	earlyEvent.ID, _ = record.EventID(w.sessionKey(), "assistant_final", record.Anchor{NativeItemID: "semantic-early"})
	earlyEvent.Revision = ""
	earlyEvent.Salt = ""
	early := w.chunk(earlyEvent)
	w.append(early)
	marker := w.event("memory recall marker")
	marker.Seq = 10
	marker.Recalled = []string{parsed.Header.LID + "@" + source.AdvisoryID}
	marker.Revision = ""
	marker.Salt = ""
	w.append(w.chunk(marker))
	laterEvent := w.event("semantic_authority_repeated")
	laterEvent.Seq = 11
	laterEvent.ID, _ = record.EventID(w.sessionKey(), "assistant_final", record.Anchor{NativeItemID: "semantic-late"})
	laterEvent.Revision = ""
	laterEvent.Salt = ""
	later := w.chunk(laterEvent)
	laterResult := w.append(later)
	unknown := w.signed(record.Header{Type: record.KindDigest, Prov: record.ProvDerived, Subj: record.Subject{SessionKey: w.sessionKey()}, LID: record.DigestLID(w.sessionKey(), testMachine)}, &record.DigestBody{HasOutcome: true, Outcome: "unknown ordered semantic output"})
	w.append(unknown)
	copy := w.task(2, "copied semantic result", later.AdvisoryID)
	w.append(copy)
	w.append(parent)
	for _, input := range []SignedRecord{later, unknown, copy} {
		x := find(w.snapshot(), input.AdvisoryID)
		if x.State != "ancestry-pending" || len(x.BodyJCS) != 0 {
			t.Fatal("ineligible recalled ancestry was served", x.State)
		}
		var n int
		if w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM passage WHERE id=?", input.AdvisoryID).Scan(&n) != nil || n != 0 {
			t.Fatal("ineligible recalled result searchable")
		}
	}
	if x := find(w.snapshot(), early.AdvisoryID); x.State != "live" || len(x.BodyJCS) == 0 {
		t.Fatal("unrelated known earlier output became unavailable")
	}
	if Code(w.s.PublishProjection(ctx, JobToken{later.AdvisoryID, laterResult.Generation}, Projection{Model: "m1", Vector: make([]byte, 256)})) != "stale_projection" {
		t.Fatal("semantic source loss failed worker fence")
	}
	w.s.Close()
	s, e := Open(ctx, w.o)
	if e != nil {
		t.Fatal(e)
	}
	w.s = s
	if e = s.Reindex(ctx); e != nil {
		t.Fatal(e)
	}
	for _, input := range []SignedRecord{later, unknown, copy} {
		if x := find(w.snapshot(), input.AdvisoryID); x.State != "ancestry-pending" || len(x.BodyJCS) != 0 {
			t.Fatal("restart/reindex lost semantic eligibility")
		}
	}
}
func TestOversizeAndSignatureMetadataRefuseBeforePersistence(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	base := w.task(1, "valid signed record")
	canary := "precopy_rejection_canary_b188f1"
	cases := []SignedRecord{}
	x := base
	x.HeaderJCS = bytes.Repeat([]byte(canary), record.MaxHeaderBytes/len(canary)+1)
	cases = append(cases, x)
	x = base
	x.BodyJCS = bytes.Repeat([]byte(canary), record.MaxBodyBytes/len(canary)+1)
	cases = append(cases, x)
	for _, field := range []string{"key", "alg", "ctx", "value", "count"} {
		x = base
		x.Sigs = append([]record.Signature(nil), base.Sigs...)
		switch field {
		case "key":
			x.Sigs[0].KeyID = canary
		case "alg":
			x.Sigs[0].Alg = canary
		case "ctx":
			x.Sigs[0].Ctx = canary
		case "value":
			x.Sigs[0].Value = canary
		case "count":
			x.Sigs = append(x.Sigs, x.Sigs[0], x.Sigs[0])
		}
		cases = append(cases, x)
	}
	before := w.snapshot()
	for _, x := range cases {
		if _, e := w.s.Append(ctx, x); Code(e) != "invalid_record" || e.Error() != "invalid_record" {
			t.Fatal("input bounds leaked or ignored", e)
		}
	}
	after := w.snapshot()
	if after.Generation != before.Generation || len(after.Entries) != len(before.Entries) {
		t.Fatal("rejection wrote state")
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, e := os.ReadFile(w.s.path + suffix)
		if e == nil && bytes.Contains(b, []byte(canary)) {
			t.Fatal("rejected input persisted", suffix)
		}
	}
}
