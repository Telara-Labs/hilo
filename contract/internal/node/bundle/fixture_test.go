package bundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
	"github.com/Telara-Labs/hilo/contract/transport"
)

const (
	fixtureMachine = "6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b"
	fixtureScope   = "sc1:6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b:00112233445566778899aabbccddeeff"
)

// fixtureNode is the genesis device that 07 §8.4.1's canonical manifest names:
// the deterministic test-only seed 0x09 and the enrolled origin machine.
func fixtureNode(t *testing.T) (*store.Store, ed25519.PrivateKey, string) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	pub := key.Public().(ed25519.PublicKey)
	genesis := sig.KeyID(pub)
	if genesis != "dbc298251c51321b7266e78d1c151c2b" {
		t.Fatal("fixture genesis", genesis)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), store.Options{Dir: filepath.Join(base, "data"), PinnedGenesisID: genesis, LocalMachineID: fixtureMachine})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(pub, record.RoleDevice, fixtureMachine), Genesis: genesis}, pub, fixtureMachine, 1761150000000, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.Append(context.Background(), store.SignedRecord{HeaderJCS: op.Rec.HeaderJCS, BodyJCS: op.Rec.BodyJCS, Sigs: op.Sigs, AdvisoryID: op.Rec.ID}); err != nil {
		t.Fatal(err)
	}
	return st, key, genesis
}

func fixturePlaintext(t *testing.T) []byte {
	t.Helper()
	raw, err := readPinnedPureFixture("..", queryPureModule)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Manifest string   `json:"manifest_jcs"`
		Facts    []string `json:"facts_jcs"`
	}
	if err = json.Unmarshal(raw, &f); err != nil || len(f.Facts) != 3 {
		t.Fatal(err)
	}
	return []byte(f.Manifest + "\n" + strings.Join(f.Facts, "\n") + "\n")
}

// The three complete 07 §8.4.1 fact fixtures travel in their canonical signed
// manifest, sealed with age to an export key, and are verified and unioned on
// the enrolled node before any data. Absent recalled roots grant nothing; a
// later call in the fixture's origin scope stays held.
func TestFixtureFactsTravelSignedEncryptedAndHoldLaterArrivals(t *testing.T) {
	ctx := context.Background()
	st, key, genesis := fixtureNode(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	plain := fixturePlaintext(t)
	sealed, err := SealTransfer(plain, []string{identity.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	opened, kinds, err := OpenTransfer(sealed, identity)
	if err != nil || !bytes.Equal(opened, plain) || len(kinds) != 1 || kinds[0] != "x25519" {
		t.Fatal(kinds, err)
	}
	c, err := Decode(opened, genesis)
	if err != nil || len(c.Facts) != 3 || len(c.FactLines) != 3 {
		t.Fatal(err)
	}
	local, err := st.Keyring(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = Verify(c, local); err != nil {
		t.Fatal(err)
	}
	report, err := st.ImportBundle(ctx, store.BundleImport{LocalKeyID: genesis, Facts: c.FactLines})
	if err != nil || report.Facts != 3 || report.Data != 0 {
		t.Fatal(report, err)
	}

	// A later call in the fixture scope names the absent recalled root as a
	// semantic dependency; its own checkpoint root stays live.
	task := "4a333333-3333-4333-8333-333333333333"
	op := record.H("fixture-scope-op")
	at := int64(1761150000100)
	h := record.Header{Type: record.KindCheckpoint, LID: record.CheckpointLID(genesis, task, fixtureMachine, op), At: at, Author: record.Author{MachineID: fixtureMachine, KeyID: genesis}, Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: op, Red: record.Redact{Profile: record.ProfileLocal}}
	p, err := record.Build(h, &record.CheckpointBody{Milestone: "fixture checkpoint"})
	if err != nil {
		t.Fatal(err)
	}
	ps, _ := sig.SignRecord(key, p.ID)
	ref, err := record.NewCallRef()
	if err != nil {
		t.Fatal(err)
	}
	call, err := record.BuildCall(record.Header{Type: record.KindCall, LID: record.CallLID(ref), At: at + 1, Author: record.Author{MachineID: fixtureMachine, KeyID: genesis}, Prov: record.ProvMCPExplicit, Subj: record.Subject{TaskID: task}, Op: op, Red: record.Redact{Profile: record.ProfileLocal}, Links: record.Links{DerivedFrom: []string{p.ID}}}, record.CallBody{CallRef: ref, ScopeID: fixtureScope, Tool: "telara_task_checkpoint", TaskID: task, Outcome: "ok", CommitmentDeps: []string{p.ID}}, json.RawMessage(`{"milestone":"fixture checkpoint"}`), json.RawMessage(`{"status":"checkpointed"}`))
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := sig.SignRecord(key, call.ID)
	for _, r := range []store.SignedRecord{{HeaderJCS: p.HeaderJCS, BodyJCS: p.BodyJCS, Sigs: []record.Signature{ps}, AdvisoryID: p.ID}, {HeaderJCS: call.HeaderJCS, BodyJCS: call.BodyJCS, Sigs: []record.Signature{cs}, AdvisoryID: call.ID}} {
		if _, err = st.Append(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := st.Snapshot(ctx, store.ReadRequest{IDs: []string{p.ID, call.ID}})
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, e := range snap.Entries {
		states[e.ID] = e.State
	}
	if states[p.ID] != "live" || states[call.ID] == "live" {
		t.Fatalf("absent recalled root did not hold the later scope call %v", states)
	}
	// The held call is not exportable, and the facts are forwarded unchanged.
	sel, err := st.SelectBundle(ctx, []string{p.ID, call.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Data) != 1 || sel.Data[0].AdvisoryID != p.ID {
		t.Fatalf("held call exported %+v", sel.Excluded)
	}
	// Re-importing the same facts is idempotent and still releases nothing.
	if _, err = st.ImportBundle(ctx, store.BundleImport{LocalKeyID: genesis, Facts: c.FactLines}); err != nil {
		t.Fatal(err)
	}
	if snap, err = st.Snapshot(ctx, store.ReadRequest{IDs: []string{call.ID}}); err != nil || snap.Entries[0].State == "live" {
		t.Fatal("re-import released the hold", err)
	}
}

// Omission, tag, bound and namespace negatives on the exact fixture bytes
// refuse the whole bundle before any admission.
func TestFixtureNegativesRefuseWhole(t *testing.T) {
	_, _, genesis := fixtureNode(t)
	plain := fixturePlaintext(t)
	lines := bytes.Split(plain[:len(plain)-1], []byte{'\n'})
	digest := regexp.MustCompile(`"items_digest":"[0-9a-f]{64}"`)
	// mutate changes one line and, for item lines, recomputes the manifest
	// digest so the item's own schema check is what refuses it.
	mutate := func(i int, from, to string) []byte {
		out := make([][]byte, len(lines))
		copy(out, lines)
		changed := bytes.Replace(out[i], []byte(from), []byte(to), 1)
		if bytes.Equal(changed, out[i]) {
			t.Fatalf("mutation %q did not apply", from)
		}
		out[i] = changed
		if i > 0 {
			out[0] = digest.ReplaceAll(out[0], []byte(`"items_digest":"`+transport.ItemsDigest(out[1:])+`"`))
		}
		return append(bytes.Join(out, []byte{'\n'}), '\n')
	}
	// Positive control: the recomputed digest of a valid but different
	// ordinal is accepted by framing, so the negatives below fail on schema.
	if _, err := Decode(mutate(1, `"ordinal":7`, `"ordinal":8`), genesis); err != nil {
		t.Fatal("digest recomputation", err)
	}
	for name, b := range map[string][]byte{
		"omitted seq0":          mutate(2, `,"seq":0`, ``),
		"call tag with seq":     mutate(1, `"ordinal":7`, `"ordinal":7,"seq":1`),
		"unknown not pending":   mutate(3, `"pending_attribution":true`, `"pending_attribution":false`),
		"foreign scope machine": mutate(1, `"scope_id":"sc1:6f1d2c3b`, `"scope_id":"sc1:7f1d2c3b`),
		"no final LF":           plain[:len(plain)-1],
		"extra line":            append(append([]byte(nil), plain...), []byte("{}\n")...),
		"count mismatch":        mutate(0, `"exposures":3`, `"exposures":2`),
	} {
		if _, err := Decode(b, genesis); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := Decode(plain, strings.Repeat("ab", 16)); err != ErrForeignGenesis {
		t.Fatal("foreign genesis", err)
	}
	// A valid, signed fixture whose exporter is not this genesis's device.
	c, err := Decode(plain, genesis)
	if err != nil {
		t.Fatal(err)
	}
	if err = Verify(c, nil); err != ErrExporter {
		t.Fatal("exporter without keyring", err)
	}
}
