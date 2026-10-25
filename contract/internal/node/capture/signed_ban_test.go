//go:build linux || darwin

package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// A sibling device erases events of a session by signed event selectors. This
// node never held any record of that session, so no occurrence ban was derived
// from its own records. The collector still skips the unit before any read:
// the transcript is gone, and the hint is acknowledged as suppressed rather
// than opened, dropped or recorded as a gap.
func TestCollectorSkipsUnitBannedBySiblingSelectorNeverHeld(t *testing.T) {
	ctx := context.Background()
	const canary = "siblingbannedunitcanaryorrin"
	data := sourceMessages(t, 1, 0, canary)

	// The sibling's own capture of the same global session supplies the event
	// identities its erasure names.
	sibling := runtimeWorld(t, data)
	quietSource()
	requireCaptured(t, sibling)
	records, _ := runtimeSnapshot(t, sibling.s)
	events := runtimeErasureEvents(sibling.c.OwnerGenesis, records)
	if len(events) == 0 {
		t.Fatal("sibling captured no events")
	}

	f := runtimeWorld(t, data)
	keyring, err := f.s.Keyring(ctx)
	if err != nil || len(keyring) != 1 {
		t.Fatal("genesis", err)
	}
	const siblingMachine = "55555555-5555-4555-8555-555555555555"
	bKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{53}, 32))
	bPub := bKey.Public().(ed25519.PublicKey)
	add, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: sig.KeyRefOf(bPub, record.RoleDevice, siblingMachine), Genesis: f.c.OwnerGenesis, Parents: []string{keyring[0].AdvisoryID}}, f.key.Public().(ed25519.PublicKey), f.c.MachineID, 1761150000001, bKey, f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Append(ctx, store.SignedRecord{HeaderJCS: add.Rec.HeaderJCS, BodyJCS: add.Rec.BodyJCS, Sigs: add.Sigs, AdvisoryID: add.Rec.ID}); err != nil {
		t.Fatal(err)
	}
	lid, _ := record.ControlLID(record.KindErasure, sig.KeyID(bPub), strings.Repeat("e", 32))
	control, err := record.Build(record.Header{Type: record.KindErasure, LID: lid, Author: record.Author{KeyID: sig.KeyID(bPub), MachineID: siblingMachine}, At: 1761150000002, Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, &record.ErasureBody{EventCoverage: "complete", Selectors: record.Selectors{Events: events}, Reason: "user_request"})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := sig.SignRecord(bKey, control.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The sync worker admits another device's erasure through this path.
	if _, err = f.s.ApplySupplement(ctx, store.SignedRecord{HeaderJCS: control.HeaderJCS, BodyJCS: control.BodyJCS, Sigs: []record.Signature{signature}, AdvisoryID: control.ID}, nil); err != nil {
		t.Fatal("sibling erasure", err)
	}
	before, _ := runtimeSnapshot(t, f.s)
	for _, r := range before {
		if r.Header.Type == record.KindChunk || r.Header.Type == record.KindSession {
			t.Fatal("fixture node already held the session")
		}
	}
	session, _ := record.SessionKey("claude-code", "local", record.NativeGlobal, syntheticSession, f.c.MachineID)
	if supp, err := f.s.Suppressed(ctx, store.SourceOccurrence{Owner: f.c.OwnerGenesis, SessionKey: session}); err != nil || !supp.Suppressed {
		t.Fatal("signed selector ban not reported by the gate", supp, err)
	}

	// Any read would now fail: the transcript no longer exists.
	if err = os.Remove(f.path); err != nil {
		t.Fatal(err)
	}
	c, err := NewCollector(f.p, filepath.Join(f.c.Home, "synthetic-node"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(transport.HookSignal{V: 3, At: 1, Client: "claude", Event: "Stop", NativeSession: syntheticSession, TranscriptPath: f.path, HookPID: os.Getpid()})
	name := testSignalULID[:25] + "7"
	spoolFile(t, c, "new", name+".json", raw)
	if err = c.Drain(ctx, "credential"); err != nil {
		t.Fatal("drain", err)
	}
	if st := c.Stats(); st.Done != 1 || st.Dropped != 0 || st.Gap != 0 {
		t.Fatal("banned unit not skipped as suppressed", st)
	}
	if done, err := f.s.SignalDone(ctx, "claude", name); err != nil || !done {
		t.Fatal("skip receipt missing", done, err)
	}
	if r, err := f.p.Capture(ctx, f.unit); Code(err) != "suppressed" || len(r.CommittedRecordIDs) != 0 {
		t.Fatal("direct capture of a banned unit", r, err)
	}
	if runtimeBodiesContain(t, f.s, canary) {
		t.Fatal("banned unit captured")
	}
}
