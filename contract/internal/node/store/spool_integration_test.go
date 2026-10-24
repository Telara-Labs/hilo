//go:build linux || darwin

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/capture"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// Minimal synthetic sources isolate multi-client store admission from the
// separately tracked duplicate-result decoder refusal in the MCP fixture.
// The original positive MCP test remains unchanged and is still required.
func TestSpoolRealCollectorTwoClientsMinimalSources(t *testing.T) {
	f := newCaptureFixture(t, "unused plan")
	ctx := context.Background()
	home := filepath.Dir(f.opts.Dir)
	cfg := capture.Config{Home: home, OwnerGenesis: f.opts.PinnedGenesisID, MachineID: f.opts.LocalMachineID, CaptureEnabled: true, Roots: map[string]capture.Root{}}
	for _, c := range []clients.Client{clients.Claude, clients.Codex} {
		loc, err := clients.Locations(clients.Options{Client: c, Home: home})
		if err != nil {
			t.Fatal(err)
		}
		reader := string(c)
		if c == clients.Claude {
			reader = "claude-code"
		}
		cfg.Roots[string(c)] = capture.Root{Client: reader, AbsPath: loc.Transcripts}
		if err = os.MkdirAll(loc.Transcripts, 0700); err != nil {
			t.Fatal(err)
		}
		raw := []byte(`{"type":"user","sessionId":"01990000-0000-4000-8000-000000000001","message":{"role":"user","content":[{"type":"text","text":"Synthetic Claude observation"}]}}` + "\n")
		if c == clients.Codex {
			raw = []byte(`{"type":"session_meta","payload":{"id":"01990000-0000-4000-8000-000000000001"}}` + "\n" + `{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Synthetic Codex observation"}]}}` + "\n")
		}
		name := "01990000-0000-4000-8000-000000000001.jsonl"
		if c == clients.Codex {
			name = "rollout-2026-10-24-" + name
		}
		path := filepath.Join(loc.Transcripts, name)
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		input, _ := json.Marshal(map[string]string{"hook_event_name": "Stop", "session_id": "01990000-0000-4000-8000-000000000001", "transcript_path": path})
		result := clients.RunHook(ctx, clients.Options{Client: c, Home: home, StateDir: f.opts.Dir}, bytes.NewReader(input))
		if !result.Published {
			t.Fatal(result.Code)
		}
	}
	keys, err := capture.PreloadKeys(make([]byte, 32), f.key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := capture.NewPipeline(ctx, f.s, cfg, keys)
	keys.Clear()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	collector, err := capture.NewCollector(p, f.opts.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	time.Sleep(2100 * time.Millisecond)
	if err = collector.Drain(ctx, "synthetic-credential"); err != nil {
		t.Fatal("first drain", err)
	}
	if collector.Stats().Done != 2 {
		t.Fatal(collector.Stats())
	}
	if err = collector.Drain(ctx, "synthetic-credential"); err != nil {
		t.Fatal("second drain", err)
	}
	if collector.Stats().Done != 2 {
		t.Fatal("duplicate drain", collector.Stats())
	}
}

// Real collector restart performs receipt-only cleanup even after source removal
// and physical record erasure. No fake SignalStore participates in this test.
func TestSpoolRealCollectorRecoveryAfterErasure(t *testing.T) {
	f := newCaptureFixture(t, "unused source")
	ctx := context.Background()
	home := filepath.Dir(f.opts.Dir)
	loc, err := clients.Locations(clients.Options{Client: clients.Claude, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(loc.Transcripts, 0700); err != nil {
		t.Fatal(err)
	}
	const native = "01990000-0000-4000-8000-000000000001"
	const marker = "SPOOL_ERASABLE_5f3c2b917ac548bb"
	path := filepath.Join(loc.Transcripts, native+".jsonl")
	raw := []byte(`{"type":"user","sessionId":"` + native + `","message":{"role":"user","content":[{"type":"text","text":"` + marker + `"}]}}` + "\n")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]string{"hook_event_name": "Stop", "session_id": native, "transcript_path": path})
	if res := clients.RunHook(ctx, clients.Options{Client: clients.Claude, Home: home, StateDir: f.opts.Dir}, bytes.NewReader(input)); !res.Published {
		t.Fatal(res.Code)
	}
	dir := filepath.Join(f.opts.Dir, "spool", "claude", "new")
	names, err := os.ReadDir(dir)
	if err != nil || len(names) != 1 {
		t.Fatal(names, err)
	}
	signalPath := filepath.Join(dir, names[0].Name())
	pending, err := os.ReadFile(signalPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := capture.Config{Home: home, OwnerGenesis: f.opts.PinnedGenesisID, MachineID: f.opts.LocalMachineID, CaptureEnabled: true, Roots: map[string]capture.Root{"claude": {Client: "claude-code", AbsPath: loc.Transcripts}}}
	open := func() (*capture.Pipeline, *capture.Collector) {
		keys, err := capture.PreloadKeys(make([]byte, 32), f.key)
		if err != nil {
			t.Fatal(err)
		}
		p, err := capture.NewPipeline(ctx, f.s, cfg, keys)
		keys.Clear()
		if err != nil {
			t.Fatal(err)
		}
		c, err := capture.NewCollector(p, f.opts.Dir)
		if err != nil {
			p.Close()
			t.Fatal(err)
		}
		return p, c
	}
	p, c := open()
	time.Sleep(2100 * time.Millisecond)
	if err = c.Drain(ctx, "synthetic-credential"); err != nil {
		t.Fatal(err)
	}
	if c.Stats().Done != 1 {
		t.Fatal(c.Stats())
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	snap, err := f.s.Snapshot(ctx, store.ReadRequest{})
	if err != nil {
		t.Fatal(err)
	}
	selectors := record.Selectors{}
	for _, entry := range snap.Entries {
		r, err := record.Parse(entry.HeaderJCS, entry.BodyJCS, entry.ID)
		if err != nil {
			t.Fatal(err)
		}
		if r.Header.Type == record.KindChunk || r.Header.Type == record.KindSession {
			selectors.IDs = append(selectors.IDs, r.ID)
		}
		if b, ok := r.Body.(*record.ChunkBody); ok {
			for _, e := range b.Events {
				selectors.Events = append(selectors.Events, record.EventSelector{Owner: f.opts.PinnedGenesisID, SessionKey: r.Header.Subj.SessionKey, EventID: e.ID})
			}
		}
	}
	if len(selectors.IDs) != 2 || len(selectors.Events) != 1 {
		t.Fatal("capture output missing", selectors)
	}
	sort.Strings(selectors.IDs)
	lid, err := record.ControlLID(record.KindErasure, f.opts.PinnedGenesisID, "b2222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	control, err := record.Build(record.Header{Type: record.KindErasure, LID: lid, At: 1761150000002, Prov: record.ProvUser, Author: record.Author{KeyID: f.opts.PinnedGenesisID, MachineID: f.opts.LocalMachineID}, Red: record.Redact{Profile: record.ProfileLocal}}, &record.ErasureBody{EventCoverage: "complete", Selectors: selectors, Reason: "user_request"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.ApplyControl(ctx, extensionInput(t, control, f.key)); err != nil {
		t.Fatal(err)
	}
	scrub, err := f.s.Scrub(ctx, control.ID)
	if err != nil || scrub.State != "complete" {
		t.Fatal(scrub, err)
	}
	// Recreate the committed-but-not-unlinked hint, then remove its replay source.
	if err = os.WriteFile(signalPath, pending, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = f.s.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoManagedCanary(t, f.opts.Dir, marker)
	f.s, err = store.Open(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	p, c = open()
	defer p.Close()
	defer c.Close()
	if err = c.Recover(ctx); err != nil {
		t.Fatal("restart reopened erased/missing source", err)
	}
	if _, err = os.Stat(signalPath); !os.IsNotExist(err) {
		t.Fatal("restart left acknowledged signal", err)
	}
	if err = c.Drain(ctx, "synthetic-credential"); err != nil {
		t.Fatal(err)
	}
	final, err := f.s.Snapshot(ctx, store.ReadRequest{})
	if err != nil || len(final.Entries) != len(snap.Entries)+1 || c.Stats().Done != 1 {
		t.Fatal("restart recaptured", len(final.Entries), c.Stats(), err)
	}
}
