//go:build linux || darwin

package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

type runtimeFixture struct {
	p    *Pipeline
	s    *store.Store
	c    Config
	unit Unit
	key  ed25519.PrivateKey
	path string
}

func runtimeWorld(t *testing.T, data []byte) *runtimeFixture {
	t.Helper()
	return runtimeWorldClient(t, data, "claude-code")
}
func runtimeWorldClient(t *testing.T, data []byte, client string) *runtimeFixture {
	t.Helper()
	ctx := context.Background()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, "synthetic-"+client)
	if err = os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{51}, 32))
	pub := key.Public().(ed25519.PublicKey)
	cfg := Config{Home: home, OwnerGenesis: sig.KeyID(pub), MachineID: syntheticSession, Roots: map[string]Root{"fixture": {Client: client, AbsPath: root}}, CaptureEnabled: true}
	s, err := store.Open(ctx, store.Options{Dir: filepath.Join(home, "synthetic-node"), PinnedGenesisID: cfg.OwnerGenesis, LocalMachineID: cfg.MachineID})
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Genesis: cfg.OwnerGenesis, Subject: sig.KeyRefOf(pub, record.RoleDevice, cfg.MachineID)}, pub, cfg.MachineID, 1761150000000, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Append(ctx, store.SignedRecord{HeaderJCS: genesis.Rec.HeaderJCS, BodyJCS: genesis.Rec.BodyJCS, Sigs: genesis.Sigs, AdvisoryID: genesis.Rec.ID}); err != nil {
		t.Fatal(err)
	}
	material, err := PreloadKeys(bytes.Repeat([]byte{52}, 32), key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPipeline(ctx, s, cfg, material)
	material.Clear()
	if err != nil {
		t.Fatal(err)
	}
	u := Unit{RootID: "fixture", RelativePath: syntheticSession + ".jsonl"}
	path := filepath.Join(root, u.RelativePath)
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f := &runtimeFixture{p: p, s: s, c: cfg, unit: u, key: key, path: path}
	t.Cleanup(func() { _ = p.Close(); _ = s.Close(); clear(key) })
	return f
}
func quietSource() { time.Sleep(2100 * time.Millisecond) }
func sourceMessages(t *testing.T, count, changed int, value string) []byte {
	t.Helper()
	var out bytes.Buffer
	for i := 0; i < count; i++ {
		text := fmt.Sprintf("synthetic text %d", i)
		if i == changed {
			text = value
		}
		line, err := json.Marshal(map[string]any{"type": "assistant", "message": map[string]any{"id": fmt.Sprintf("msg_%d", i), "content": []any{map[string]any{"type": "text", "text": text}}}})
		if err != nil {
			t.Fatal(err)
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}
func runtimeSnapshot(t *testing.T, s *store.Store) (map[string]*record.Record, map[string]record.Event) {
	t.Helper()
	snap, err := s.Snapshot(context.Background(), store.ReadRequest{})
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]*record.Record{}
	events := map[string]record.Event{}
	for _, entry := range snap.Entries {
		if len(entry.BodyJCS) == 0 {
			continue
		}
		r, err := record.Parse(entry.HeaderJCS, entry.BodyJCS, entry.ID)
		if err != nil {
			t.Fatal(err)
		}
		records[r.ID] = r
		if b, ok := r.Body.(*record.ChunkBody); ok {
			for _, e := range b.Events {
				events[e.Revision] = e
			}
		}
	}
	return records, events
}
func latestEvents(t *testing.T, f *runtimeFixture) map[string]record.Event {
	t.Helper()
	session, _ := record.SessionKey("claude-code", "local", record.NativeGlobal, syntheticSession, f.c.MachineID)
	source, _ := record.SourceKey("claude-code", f.c.MachineID, "synthetic-claude-code/"+f.unit.RelativePath)
	ins, err := f.s.InspectCapture(context.Background(), store.SourceOccurrence{Owner: f.c.OwnerGenesis, Source: source, SessionKey: session})
	if err != nil {
		t.Fatal(err)
	}
	records, _ := runtimeSnapshot(t, f.s)
	out := map[string]record.Event{}
	for _, ref := range ins.Progress.LastSourceRecords {
		r := records[ref.ID]
		if r == nil {
			t.Fatal("committed baseline missing")
		}
		b, ok := r.Body.(*record.ChunkBody)
		if !ok {
			t.Fatal("baseline was not chunk")
		}
		for _, e := range b.Events {
			out[e.ID] = e
		}
	}
	return out
}
func requireCaptured(t *testing.T, f *runtimeFixture) Result {
	t.Helper()
	r, err := f.p.Capture(context.Background(), f.unit)
	if err != nil || r.Status != "committed" {
		t.Fatalf("capture got %s %v", r.Status, err)
	}
	return r
}

func TestRuntimeActualSQLiteCommitNoChangeCorrectionAndRevert(t *testing.T) {
	f := runtimeWorld(t, sourceMessages(t, 96, -1, ""))
	quietSource()
	first := requireCaptured(t, f)
	if first.ProgressVersion != 1 || len(first.CommittedRecordIDs) != 2 {
		t.Fatal("initial chunk/page did not commit together", first)
	}
	original := latestEvents(t, f)
	initialRecords, _ := runtimeSnapshot(t, f.s)
	var id40, id90 string
	for id, e := range original {
		if e.Seq == 40 {
			id40 = id
		}
		if e.Seq == 90 {
			id90 = id
		}
	}
	noChange, err := f.p.Capture(context.Background(), f.unit)
	if err != nil || noChange.Status != "no_change" || noChange.ProgressVersion != 1 {
		t.Fatal("unchanged read reminted/advanced", noChange, err)
	}
	afterRecords, _ := runtimeSnapshot(t, f.s)
	if !reflect.DeepEqual(first.CommittedRecordIDs, noChange.CommittedRecordIDs) || len(initialRecords) != len(afterRecords) {
		t.Fatal("no-change wrote new wrapper/IDs")
	}
	if !reflect.DeepEqual(original, latestEvents(t, f)) {
		t.Fatal("unchanged exact seals changed")
	}
	if err = os.WriteFile(f.path, sourceMessages(t, 96, 40, "synthetic corrected forty"), 0600); err != nil {
		t.Fatal(err)
	}
	quietSource()
	second := requireCaptured(t, f)
	if second.ProgressVersion != 2 {
		t.Fatal("correction failed atomic progress")
	}
	corrected := latestEvents(t, f)
	if corrected[id40].Revision == original[id40].Revision || !equalStrings(corrected[id40].Replaces, []string{original[id40].Revision}) {
		t.Fatal("correction did not replace prior frontier")
	}
	if !reflect.DeepEqual(original[id90], corrected[id90]) {
		t.Fatal("event90 exact seal lost during event40 correction")
	}
	records, _ := runtimeSnapshot(t, f.s)
	var page *record.SessionBody
	for _, id := range second.CommittedRecordIDs {
		if r := records[id]; r != nil {
			if b, ok := r.Body.(*record.SessionBody); ok {
				page = b
			}
		}
	}
	if page == nil || len(page.Chunks) != 2 {
		t.Fatal("new snapshot dropped prior membership")
	}
	if err = os.WriteFile(f.path, sourceMessages(t, 96, -1, ""), 0600); err != nil {
		t.Fatal(err)
	}
	quietSource()
	third := requireCaptured(t, f)
	if third.ProgressVersion != 3 {
		t.Fatal("revert failed")
	}
	reverted := latestEvents(t, f)
	if reverted[id40].Revision == original[id40].Revision || reverted[id40].Salt == original[id40].Salt || !equalStrings(reverted[id40].Replaces, []string{corrected[id40].Revision}) {
		t.Fatal("revert collapsed to old equal text")
	}
	if !reflect.DeepEqual(original[id90], reverted[id90]) {
		t.Fatal("unchanged seal did not survive repacks")
	}
	for _, e := range reverted {
		if e.Text != nil && e.Text.Digest != "" {
			t.Fatal("optional text comparison digest retained")
		}
	}
}

func TestRuntimeStrictInputsQuietConfigAndLifecycle(t *testing.T) {
	f := runtimeWorld(t, sourceMessages(t, 1, -1, ""))
	r, err := f.p.Capture(context.Background(), f.unit)
	if r.Status != "held" || Code(err) != "source_unsettled" || len(r.CommittedRecordIDs) != 0 {
		t.Fatal("fresh file did not hold without IDs", r, err)
	}
	r, err = f.p.Capture(context.Background(), Unit{RootID: "fixture", RelativePath: "non-uuid.jsonl"})
	if Code(err) != "unresolved_session" || len(r.CommittedRecordIDs) != 0 {
		t.Fatal("nonUUID was probed", r, err)
	}
	r, err = f.p.Capture(context.Background(), Unit{RootID: "absent", RelativePath: f.unit.RelativePath})
	if Code(err) != "unknown_root" {
		t.Fatal("unconfigured root accepted", err)
	}
	// Mutating the caller's root map/config after construction cannot retarget.
	f.c.Roots["fixture"] = Root{Client: "codex", AbsPath: "/does-not-exist"}
	quietSource()
	requireCaptured(t, f)
	if err = f.p.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = f.p.Capture(context.Background(), f.unit)
	if Code(err) != "closed" || len(r.CommittedRecordIDs) != 0 {
		t.Fatal("closed keys still usable", r, err)
	}
	if _, err = PreloadKeys([]byte{1}, f.key); Code(err) != "key_material" {
		t.Fatal("short salt accepted")
	}
	broken := append(ed25519.PrivateKey(nil), f.key...)
	broken[63] ^= 1
	if _, err = PreloadKeys(bytes.Repeat([]byte{1}, 32), broken); Code(err) != "key_material" {
		t.Fatal("inconsistent key accepted")
	}
}

func TestRuntimeSuppressionPreventsMissingPathReadAndNoReseal(t *testing.T) {
	f := runtimeWorld(t, sourceMessages(t, 1, -1, ""))
	quietSource()
	first := requireCaptured(t, f)
	recordsBefore, _ := runtimeSnapshot(t, f.s)
	chunkID := ""
	for _, id := range first.CommittedRecordIDs {
		if r := recordsBefore[id]; r != nil {
			if _, ok := r.Body.(*record.ChunkBody); ok {
				chunkID = id
			}
		}
	}
	if chunkID == "" {
		t.Fatal("missing committed chunk")
	}
	lid, _ := record.ControlLID(record.KindErasure, f.c.OwnerGenesis, strings.Repeat("b", 32))
	control, err := record.Build(record.Header{Type: record.KindErasure, LID: lid, Author: record.Author{KeyID: f.c.OwnerGenesis, MachineID: f.c.MachineID}, At: time.Now().UnixMilli(), Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, &record.ErasureBody{Selectors: record.Selectors{IDs: []string{chunkID}}, Reason: "user_request"}, bytes.Repeat([]byte{52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := sig.SignRecord(f.key, control.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Append(context.Background(), store.SignedRecord{HeaderJCS: control.HeaderJCS, BodyJCS: control.BodyJCS, Sigs: []record.Signature{signature}, AdvisoryID: control.ID}); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(f.path); err != nil {
		t.Fatal(err)
	}
	r, err := f.p.Capture(context.Background(), f.unit)
	if r.Status != "held" || len(r.CommittedRecordIDs) != 0 || Code(err) != "suppressed" {
		t.Fatal("erased source opened/resealed", r, err)
	}
}

func TestConcurrentRealPipelinesCommitOnceThenReuse(t *testing.T) {
	f := runtimeWorld(t, sourceMessages(t, 1, -1, ""))
	keys, err := PreloadKeys(bytes.Repeat([]byte{52}, 32), f.key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPipeline(context.Background(), f.s, f.c, keys)
	keys.Clear()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	quietSource()
	var wg sync.WaitGroup
	results := make(chan Result, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		p := f.p
		if i%2 == 1 {
			p = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := p.Capture(context.Background(), f.unit)
			if e != nil {
				failures <- e
				return
			}
			results <- r
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	commits := 0
	for r := range results {
		if r.ProgressVersion != 1 {
			t.Fatal("concurrent retry advanced progress")
		}
		switch r.Status {
		case "committed":
			commits++
		case "no_change", "prior_transition_committed":
		default:
			t.Fatal("unexpected retry state", r.Status)
		}
	}
	if commits != 1 {
		t.Fatal("expected exactly one original commit", commits)
	}
	records, _ := runtimeSnapshot(t, f.s)
	if len(records) != 3 {
		t.Fatal("concurrent retries persisted extra records", len(records))
	}
}
