package bundle

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
	"github.com/Telara-Labs/hilo/contract/transport"
)

// A hosted acceptance receipt is not a grant. Encode carries a selection's
// receipts on their envelopes; Decode keeps each one bound to its record id,
// apart from any grant, which still refuses the whole bundle. A receipt
// naming another record is refused, never reassigned.
func TestReceiptsTravelApartFromGrants(t *testing.T) {
	ctx := context.Background()
	st, key, genesis := fixtureNode(t)
	h := record.Header{Type: record.KindTask, LID: record.TaskLID(genesis, "4c555555-5555-4555-8555-555555555555"), Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: "4c555555-5555-4555-8555-555555555555"}, Op: record.H("op", "receipt-framing"), At: 1761150000100, Author: record.Author{MachineID: fixtureMachine, KeyID: genesis}, Red: record.Redact{Profile: record.ProfileLocal}}
	r, err := record.Build(h, &record.TaskBody{Name: "task", Goal: "receipt framing", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	sg, err := sig.SignRecord(key, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	item := store.SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: []record.Signature{sg}, AdvisoryID: r.ID}
	if _, err = st.Append(ctx, item); err != nil {
		t.Fatal(err)
	}
	keyring, err := st.Keyring(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rc := record.Receipt{ID: r.ID, Tenant: "tenant-framing", DeviceID: fixtureMachine, AcceptedAt: 1000, HSeq: 1, Policy: strings.Repeat("d", 64), Sig: &record.Signature{Alg: sig.AlgEd25519, KeyID: genesis, Ctx: sig.CtxReceipt, Value: strings.Repeat("A", 86)}}
	sel := store.BundleSelection{Keyring: keyring, Data: []store.SignedRecord{item}, Receipts: map[string]record.Receipt{r.ID: rc}}
	plain, _, err := Encode(sel, genesis, key, 1761150000200)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Decode(plain, genesis)
	if err != nil {
		t.Fatal("receipt-bearing bundle refused", err)
	}
	if got, ok := c.Receipts[r.ID]; !ok || got.Tenant != rc.Tenant || got.AcceptedAt != rc.AcceptedAt || len(c.Data) != 1 {
		t.Fatal("receipt not preserved", c.Receipts)
	}
	if err = Verify(c, keyring); err != nil {
		t.Fatal(err)
	}

	// Re-frame one data line, re-signing the manifest, to probe Decode.
	reframe := func(mutate func(*record.Envelope)) []byte {
		t.Helper()
		lines := strings.Split(strings.TrimSuffix(string(plain), "\n"), "\n")
		var e record.Envelope
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &e); err != nil {
			t.Fatal(err)
		}
		mutate(&e)
		line, err := jcs.MarshalRecord(e)
		if err != nil {
			t.Fatal(err)
		}
		lines[len(lines)-1] = string(line)
		items := make([][]byte, 0, len(lines)-1)
		for _, l := range lines[1:] {
			items = append(items, []byte(l))
		}
		return resign(t, key, lines[0], items)
	}
	granted := reframe(func(e *record.Envelope) {
		e.Grant = &record.DeliveryGrant{RecordID: e.ID, Tenant: "tenant-framing", Generation: 1, Policy: strings.Repeat("a", 64), RecipientGenesis: genesis}
	})
	if _, err = Decode(granted, genesis); err != ErrGranted {
		t.Fatal("granted content decoded", err)
	}
	foreign := reframe(func(e *record.Envelope) {
		other := *e.Receipt
		other.ID = strings.Repeat("b", 64)
		e.Receipt = &other
	})
	if _, err = Decode(foreign, genesis); err != ErrInvalid {
		t.Fatal("receipt for another record accepted", err)
	}
}

// resign recomputes the item digest over items and signs the manifest again
// with the exporter key, so only the probed envelope differs.
func resign(t *testing.T, key ed25519.PrivateKey, head string, items [][]byte) []byte {
	t.Helper()
	var m transport.Manifest
	if err := json.Unmarshal([]byte(head), &m); err != nil {
		t.Fatal(err)
	}
	m.Sigs = nil
	m.ItemsDigest = transport.ItemsDigest(items)
	unsigned, err := jcs.MarshalRecord(m)
	if err != nil {
		t.Fatal(err)
	}
	m.Sigs = []record.Signature{sig.Sign(key, sig.CtxBundle, sig.BundleMessage(unsigned))}
	line, err := jcs.MarshalRecord(m)
	if err != nil {
		t.Fatal(err)
	}
	out := append(line, '\n')
	for _, it := range items {
		out = append(append(out, it...), '\n')
	}
	return out
}
