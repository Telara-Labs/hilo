package contract_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"github.com/Telara-Labs/hilo/contract/invalidate"
	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
	"testing"
)

func TestV3InvalidLateBodyNoMembership(t *testing.T) {
	var fs []struct{ Name, HeaderJCS, BodyJCS string }
	fixture(t, "v03-records.json", &fs)
	var source *record.Record
	for _, f := range fs {
		if f.Name == "chunk" {
			var err error
			source, err = record.Parse([]byte(f.HeaderJCS), []byte(f.BodyJCS), "")
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	pub := key.Public().(ed25519.PublicKey)
	owner := sig.KeyID(pub)
	genesis, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(pub, record.RoleDevice, source.Header.Author.MachineID), Genesis: owner}, pub, source.Header.Author.MachineID, 1, key)
	if err != nil {
		t.Fatal(err)
	}
	kr := sig.NewKeyring(owner)
	if result := sig.VerifyKeyOp(kr, genesis); result.Status != sig.OpAuthorized {
		t.Fatal(result)
	}
	h := source.Header
	h.Author.KeyID = owner
	body := source.Body.(*record.ChunkBody)
	body.Salt = ""
	valid, err := record.Build(h, body)
	if err != nil {
		t.Fatal(err)
	}
	events := valid.Body.(*record.ChunkBody).Events
	m := invalidate.NewModel()
	controlID := record.H("signed-event-ban")
	if m.Apply(invalidate.Control{ID: controlID, Kind: record.KindErasure, Owner: owner, Erasure: &record.ErasureBody{EventCoverage: "complete", Reason: "user_request", Selectors: record.Selectors{Events: []record.EventSelector{{Owner: owner, SessionKey: h.Subj.SessionKey, EventID: events[0].ID}}}}}) != nil {
		t.Fatal("primary ban")
	}
	// Correct outer digest AND signature cannot hide an invalid second event.
	var fields map[string]any
	json.Unmarshal(valid.BodyJCS, &fields)
	fields["events"].([]any)[1].(map[string]any)["revision"] = record.H("invalid nested revision")
	badBody, _ := jcs.MarshalRecord(fields)
	badHeader := valid.Header
	badHeader.Body = &record.BodyRef{Digest: record.BodyDigest(badBody), Size: int64(len(badBody))}
	header, _ := jcs.MarshalRecord(badHeader)
	bad := &record.Record{ID: record.ContentID(header), HeaderJCS: header, BodyJCS: badBody}
	sg, _ := sig.SignRecord(key, bad.ID)
	result := sig.VerifyRecord(bad, []record.Signature{sg}, kr.State(), sig.Context{})
	if result.Status != sig.StatusRejected || result.Status.Quarantined() {
		t.Fatal("invalid signed body reached quarantine/admission", result)
	}
	if m.Evaluate().OwnerPending[owner] || m.EventErased(owner, h.Subj.SessionKey, events[1].ID) || !m.EventErased(owner, h.Subj.SessionKey, events[0].ID) {
		t.Fatal("invalid late body created membership/bans or cleared primary tomb")
	}
	// A valid verified late body does saturate and requires a signed supplement.
	sg, _ = sig.SignRecord(key, valid.ID)
	result = sig.VerifyRecord(valid, []record.Signature{sg}, kr.State(), sig.Context{})
	if result.Status != sig.StatusVerified {
		t.Fatal(result)
	}
	m.Admit(invalidate.Item{ID: valid.ID, LID: valid.Header.LID, Kind: record.KindChunk, Prov: record.ProvTranscript, Owner: owner, SessionKey: h.Subj.SessionKey, Events: []string{events[0].ID, events[1].ID}, EventMembershipComplete: true})
	if !m.Evaluate().OwnerPending[owner] || !m.EventErased(owner, h.Subj.SessionKey, events[1].ID) || m.Evaluate().StatusOf(valid.ID) != invalidate.Invalidated {
		t.Fatal("valid late membership not saturated before completion")
	}
}
