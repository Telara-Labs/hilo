package sig

import (
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"testing"
)

func TestV3MalformedBodiesCannotAcquireQuarantine(t *testing.T) {
	w := newWorld(t)
	state := w.fold([]string{"genesis"})
	h := record.Header{Type: record.KindRetraction, LID: hx("control"), Author: record.Author{KeyID: w.gid(), MachineID: mA}, At: 1, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}
	body := []byte(`{"ids":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"prose":"private","reason":"rule_removed"}`)
	h.V = 3
	h.Body = &record.BodyRef{Digest: record.BodyDigest(body), Size: int64(len(body))}
	header, err := jcs.MarshalRecord(h)
	if err != nil {
		t.Fatal(err)
	}
	r := &record.Record{ID: record.ContentID(header), HeaderJCS: header, BodyJCS: body}
	for _, sigs := range [][]record.Signature{nil, signed(t, r, w.genesis)} {
		res := VerifyRecord(r, sigs, state, Context{})
		if res.Status != StatusRejected || res.Status.Quarantined() {
			t.Fatal("recognized invalid raw bytes quarantined", res)
		}
	}
}

func TestV3SignedEventSelectorOwnerScope(t *testing.T) {
	w := newWorld(t)
	state := w.fold([]string{"genesis"})
	h := record.Header{Type: record.KindErasure, LID: hx("erasure"), Author: record.Author{KeyID: w.gid(), MachineID: mA}, At: 1, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}
	makeRecord := func(owner string) *record.Record {
		r, err := record.Build(h, &record.ErasureBody{EventCoverage: "complete", Reason: "user_request", Selectors: record.Selectors{Events: []record.EventSelector{{Owner: owner, SessionKey: "sk1:" + hx("s"), EventID: "ev1:" + hx("event")}}}})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	own := makeRecord(w.gid())
	if VerifyRecord(own, signed(t, own, w.genesis), state, Context{}).Status != StatusVerified {
		t.Fatal("own event selector refused")
	}
	foreign := makeRecord("22222222222222222222222222222222")
	if VerifyRecord(foreign, signed(t, foreign, w.genesis), state, Context{}).Status == StatusVerified {
		t.Fatal("foreign event selector verified")
	}
}

func TestV3SelfReviewUnknownMajorStillQuarantines(t *testing.T) {
	w := newWorld(t)
	st := w.fold([]string{"genesis"})
	r := taskRecord(t, w.gid(), pub(w.genesis), mA, record.ProvMCPExplicit)
	h := r.Header
	h.V = 4
	header, _ := jcs.MarshalRecord(h)
	future := &record.Record{ID: record.ContentID(header), HeaderJCS: header, BodyJCS: r.BodyJCS}
	res := VerifyRecord(future, signed(t, future, w.genesis), st, Context{})
	if !res.Status.Quarantined() {
		t.Fatal("unknown future major lost mandatory envelope retention")
	}
}
