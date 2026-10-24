//go:build linux || darwin

package mcp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/capture"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
)

type ingressRuntime struct {
	world  *adapterWorld
	config capture.Config
}

func (p ingressRuntime) Load(ctx context.Context) (Runtime, error) {
	r, err := p.world.Load(ctx)
	if err != nil {
		return Runtime{}, err
	}
	keys, err := capture.PreloadKeys(make([]byte, 32), p.world.key)
	if err != nil {
		r.Material.Clear()
		return Runtime{}, err
	}
	r.CaptureConfig = &p.config
	r.CaptureKeys = keys
	return r, nil
}
func ingressWorld(t *testing.T, selected ...clients.Client) (*adapterWorld, ingressRuntime) {
	if len(selected) == 0 {
		selected = []clients.Client{clients.Claude, clients.Codex}
	}
	t.Helper()
	w := newAdapterWorld(t)
	home := filepath.Dir(w.paths.Data)
	cfg := capture.Config{Home: home, OwnerGenesis: w.cfg.OwnerGenesis, MachineID: w.cfg.MachineID, CaptureEnabled: true, Roots: map[string]capture.Root{}}
	for _, client := range selected {
		location, err := clients.Locations(clients.Options{Client: client, Home: home})
		if err != nil {
			t.Fatal(err)
		}
		name := string(client)
		if client == clients.Claude {
			name = "claude-code"
		}
		if client == clients.Cursor {
			name = "cursor-agent"
		}
		cfg.Roots[string(client)] = capture.Root{Client: name, AbsPath: location.Transcripts}
	}
	return w, ingressRuntime{w, cfg}
}
func startIngress(t *testing.T, w *adapterWorld, provider RuntimeProvider) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Config{Paths: w.paths, Ready: func() { close(ready) }, Open: func(ctx context.Context) (daemon.Backend, error) {
			b, err := Open(ctx, w.paths.Data, provider)
			w.backend = b
			return b, err
		}})
	}()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("startup timeout")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("shutdown timeout")
		}
	})
}
func publishIngressFixtures(t *testing.T, w *adapterWorld, provider ingressRuntime) map[string]string {
	t.Helper()
	paths := map[string]string{}
	for clientName, configuredRoot := range provider.config.Roots {
		client := clients.Client(clientName)
		root := configuredRoot.AbsPath
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		fixture := string(client)
		if client == clients.Cursor {
			fixture = "cursor-agent-2026.10.22"
		}
		if client == clients.Pi {
			fixture = "pi-1.1.0"
		}
		raw, err := os.ReadFile(filepath.Join("..", "capture", "testdata", fixture+".jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		name := "01990000-0000-4000-8000-000000000001.jsonl"
		if client == clients.Codex {
			name = "rollout-2026-10-24-" + name
		}
		if client == clients.Pi {
			name = "2026-10-24T12-00-00-000Z_" + name
		}
		if client == clients.Cursor {
			name = filepath.Join("synthetic-project", "agent-transcripts", strings.TrimSuffix(name, ".jsonl"), name)
		}
		if err = os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name)
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		paths[string(client)] = path
	}
	// The real capture opener requires two seconds without source mutation.
	time.Sleep(2100 * time.Millisecond)
	publishIngressHooks(t, w, provider, paths)

	return paths
}

func publishIngressHooks(t *testing.T, w *adapterWorld, provider ingressRuntime, paths map[string]string) {
	t.Helper()
	for client, path := range paths {
		event := "Stop"
		input := map[string]any{"session_id": "01990000-0000-4000-8000-000000000001", "transcript_path": path}
		switch clients.Client(client) {
		case clients.Cursor:
			event = "stop"
			delete(input, "session_id")
			input["conversation_id"] = "01990000-0000-4000-8000-000000000001"
			input["generation_id"] = "synthetic-generation"
		case clients.Pi:
			event = "agent_end"
		}
		input["hook_event_name"] = event
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		result := clients.RunHook(context.Background(), clients.Options{Client: clients.Client(client), Home: provider.config.Home, StateDir: w.paths.Data}, bytes.NewReader(raw))
		if !result.Published || !result.TranscriptHintVerified {
			t.Fatalf("hook not published/verified %s: %+v", client, result)
		}
	}
}

// A real SQLite refusal at the final receipt insert rolls back the entire
// signal transaction. The collector must retain the hint and deny MCP until
// the exact same pending signal is successfully admitted on retry.
func TestCaptureIngressStoreRefusalRealDaemonShim(t *testing.T) {
	w, provider := ingressWorld(t, clients.Codex)
	startIngress(t, w, provider)
	publishIngressFixtures(t, w, provider)
	db, err := sql.Open("sqlite", "file:"+filepath.Join(w.paths.Data, "memory.sqlite")+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TRIGGER ingress_refuse_receipt BEFORE INSERT ON spool_done BEGIN SELECT RAISE(ABORT,'synthetic receipt refusal'); END`); err != nil {
		t.Fatal(err)
	}
	before := w.count("SELECT count(*) FROM record")
	result := w.session().call("telara_task_list", map[string]any{}, "", "ingress-negative")
	if !result.IsError || textOf(t, result) != "identity_unavailable" {
		t.Fatal("store refusal bypassed", result)
	}
	if w.count("SELECT count(*) FROM record") != before {
		t.Fatal("refused signal committed records")
	}
	for _, table := range []string{"spool_announcement", "spool_process", "spool_done", "capture_progress"} {
		if w.count("SELECT count(*) FROM "+table) != 0 {
			t.Fatal("partial signal transaction", table)
		}
	}
	files, err := os.ReadDir(filepath.Join(w.paths.Data, "spool", "codex", "new"))
	if err != nil || len(files) != 1 {
		t.Fatal("refused signal ACKed", err)
	}
	if _, err = db.Exec("DROP TRIGGER ingress_refuse_receipt"); err != nil {
		t.Fatal(err)
	}
	goodText(t, w.session().call("telara_task_list", map[string]any{}, "", "ingress-retry"))
	assertIngressSessions(t, w, provider)
}

// Real daemon, shim, hook writer, capture pipeline, SQLite and MCP disclosure.
// Only fixture key/grant provisioning is supplied in-process. This is NOT a
// native vault/installed client acceptance test. No fake capture/ACK service.
func TestCaptureIngressClaudeCodexRealDaemonShim(t *testing.T) {
	testCaptureIngress(t, clients.Claude, clients.Codex)
}
func TestCaptureIngressCursorRealDaemonShim(t *testing.T) {
	testCaptureIngress(t, clients.Cursor)
}
func TestCaptureIngressPiRealDaemonShim(t *testing.T) {
	testCaptureIngress(t, clients.Pi)
}
func TestCaptureIngressFourClientsRealDaemonShim(t *testing.T) {
	testCaptureIngress(t, clients.Claude, clients.Codex, clients.Cursor, clients.Pi)
}

func testCaptureIngress(t *testing.T, selected ...clients.Client) {
	t.Helper()
	w, provider := ingressWorld(t, selected...)
	startIngress(t, w, provider)
	paths := publishIngressFixtures(t, w, provider)
	goodText(t, w.session().call("telara_task_list", map[string]any{}, "", "ingress-positive"))
	assertIngressSessions(t, w, provider)
	captureIDs := w.scalar(`SELECT group_concat(id,',') FROM (SELECT id FROM record WHERE json_extract(CAST(header AS TEXT),'$.type') IN ('session','chunk') ORDER BY id)`)
	goodText(t, w.session().call("telara_task_list", map[string]any{}, "", "ingress-fresh"))
	if ids := w.scalar(`SELECT group_concat(id,',') FROM (SELECT id FROM record WHERE json_extract(CAST(header AS TEXT),'$.type') IN ('session','chunk') ORDER BY id)`); ids != captureIDs {
		t.Fatal("empty drain duplicated captured records")
	}
	// Fresh hook signals for unchanged sources exercise the real no-change
	// admission transaction, adding receipts without resealing records.
	publishIngressHooks(t, w, provider, paths)
	goodText(t, w.session().call("telara_task_list", map[string]any{}, "", "ingress-no-change"))
	assertIngressSessions(t, w, provider)
	if ids := w.scalar(`SELECT group_concat(id,',') FROM (SELECT id FROM record WHERE json_extract(CAST(header AS TEXT),'$.type') IN ('session','chunk') ORDER BY id)`); ids != captureIDs {
		t.Fatal("unchanged source resealed captured records")
	}
	if w.count("SELECT count(*) FROM spool_done") != 2*len(selected) {
		t.Fatal("no-change receipt missing")
	}
}

func assertIngressSessions(t *testing.T, w *adapterWorld, provider ingressRuntime) {
	t.Helper()
	if w.count("SELECT count(*) FROM record WHERE json_extract(CAST(header AS TEXT),'$.type')='session'") != len(provider.config.Roots) {
		t.Fatal("fixture sessions were not admitted")
	}
	for client, root := range provider.config.Roots {
		files, err := os.ReadDir(filepath.Join(w.paths.Data, "spool", client, "new"))
		if err != nil || len(files) != 0 {
			t.Fatal("signal not ACKed", client, err)
		}
		if w.count("SELECT count(*) FROM spool_done WHERE client=?", client) == 0 || w.count("SELECT count(*) FROM spool_announcement WHERE client=?", client) == 0 {
			t.Fatal("signal ACKed without receipt", client)
		}
		id := w.scalar("SELECT id FROM record WHERE json_extract(CAST(header AS TEXT),'$.type')='session' AND json_extract(CAST(header AS TEXT),'$.subj.client.id')=?", root.Client)
		if len(id) != 64 {
			t.Fatal("session ID unavailable", client)
		}
		text := goodText(t, w.session().call("telara_get_context", map[string]any{"entity_id": id, "entity_type": "session", "include_content": false}, "", "ingress-readback"))
		if !strings.Contains(text, id) {
			t.Fatal("session not readable through MCP", client)
		}
	}
}

func publishCodexLifecycleHook(t *testing.T, w *adapterWorld, provider ingressRuntime, path, event string) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"session_id": "01990000-0000-4000-8000-000000000001", "transcript_path": path, "hook_event_name": event})
	if err != nil {
		t.Fatal(err)
	}
	result := clients.RunHook(context.Background(), clients.Options{Client: clients.Codex, Home: provider.config.Home, StateDir: w.paths.Data}, bytes.NewReader(raw))
	if !result.Published || !result.TranscriptHintVerified {
		t.Fatalf("hook %s not published with verified path: %+v", event, result)
	}
}

func codexLiveIngress(t *testing.T, w *adapterWorld, provider ingressRuntime) (string, []byte) {
	t.Helper()
	root := provider.config.Roots["codex"].AbsPath
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "capture", "testdata", "codex-0.161.0.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "rollout-2026-10-24-01990000-0000-4000-8000-000000000001.jsonl")
	// A real client's stream can end halfway through the next record, even
	// though its immutable SessionStart/UserPromptSubmit signals are complete.
	prefix := append(append([]byte(nil), raw[:bytes.IndexByte(raw, '\n')+1]...), []byte(`{"type":`)...)
	if err = os.WriteFile(path, prefix, 0600); err != nil {
		t.Fatal(err)
	}
	return path, raw
}

func TestCaptureIngressCodexLiveHookOrderRealDaemonShim(t *testing.T) {
	w, provider := ingressWorld(t, clients.Codex)
	startIngress(t, w, provider)
	path, full := codexLiveIngress(t, w, provider)
	publishCodexLifecycleHook(t, w, provider, path, "SessionStart")
	publishCodexLifecycleHook(t, w, provider, path, "UserPromptSubmit")
	a := w.session()
	goodText(t, a.call("telara_task_list", map[string]any{}, "", "codex-session-a"))
	if w.count("SELECT count(*) FROM spool_announcement") != 2 || w.count("SELECT count(*) FROM spool_done") != 0 || w.count("SELECT count(*) FROM capture_progress") != 0 {
		t.Fatal("live hints not observed or falsely ACKed/captured")
	}
	files, err := os.ReadDir(filepath.Join(w.paths.Data, "spool", "codex", "new"))
	if err != nil || len(files) != 2 {
		t.Fatal("pending signals lost", err)
	}
	// Repeated MCP calls reapply pending announcements idempotently.
	goodText(t, a.call("telara_task_list", map[string]any{}, "", "codex-session-a"))
	if w.count("SELECT count(*) FROM spool_announcement") != 2 || w.count("SELECT count(*) FROM spool_done") != 0 {
		t.Fatal("pending replay not idempotent")
	}
	if err = os.WriteFile(path, full, 0600); err != nil {
		t.Fatal(err)
	}
	publishCodexLifecycleHook(t, w, provider, path, "Stop")
	goodText(t, a.call("telara_task_list", map[string]any{}, "", "codex-session-a"))
	// Canonical quiet-period settling remains in force for the trailing line.
	time.Sleep(2100 * time.Millisecond)
	publishCodexLifecycleHook(t, w, provider, path, "SessionEnd")
	b := w.session()
	goodText(t, b.call("telara_task_list", map[string]any{}, "", "codex-session-b"))
	assertIngressSessions(t, w, provider)
	if w.count("SELECT count(*) FROM spool_done") != 4 {
		t.Fatal("terminal/later drain did not complete every pending hint")
	}
	id := w.scalar("SELECT id FROM record WHERE json_extract(CAST(header AS TEXT),'$.type')='session'")
	text := goodText(t, b.call("telara_get_context", map[string]any{"entity_id": id, "entity_type": "session", "include_content": false}, "", "codex-session-b"))
	if !strings.Contains(text, id) {
		t.Fatal("fresh session did not read A's captured session")
	}
}

func TestCaptureIngressPendingIdentityRefusalsRealDaemonShim(t *testing.T) {
	for _, scenario := range []string{"malformed", "hostile-path", "store-failure"} {
		t.Run(scenario, func(t *testing.T) {
			w, provider := ingressWorld(t, clients.Codex)
			startIngress(t, w, provider)
			path, _ := codexLiveIngress(t, w, provider)
			publishCodexLifecycleHook(t, w, provider, path, "SessionStart")
			dir := filepath.Join(w.paths.Data, "spool", "codex", "new")
			switch scenario {
			case "malformed":
				files, err := os.ReadDir(dir)
				if err != nil || len(files) != 1 {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, files[0].Name()), []byte(`{"v":3,"unknown":"synthetic"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "hostile-path":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".old", path); err != nil {
					t.Fatal(err)
				}
			case "store-failure":
				db, err := sql.Open("sqlite", "file:"+filepath.Join(w.paths.Data, "memory.sqlite")+"?mode=rw")
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				if _, err = db.Exec(`CREATE TRIGGER refuse_pending BEFORE INSERT ON spool_announcement BEGIN SELECT RAISE(ABORT,'synthetic observation refusal'); END`); err != nil {
					t.Fatal(err)
				}
			}
			result := w.session().call("telara_task_list", map[string]any{}, "", "pending-negative")
			if !result.IsError || textOf(t, result) != "identity_unavailable" {
				t.Fatal("unsafe identity processing allowed MCP", result)
			}
			if w.count("SELECT count(*) FROM spool_done") != 0 || w.count("SELECT count(*) FROM spool_announcement") != 0 || w.count("SELECT count(*) FROM capture_progress") != 0 {
				t.Fatal("unsafe pending hint committed")
			}
		})
	}
}
