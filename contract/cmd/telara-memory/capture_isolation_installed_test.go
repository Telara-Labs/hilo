//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
)

// TestInstalledStuckClientHintDoesNotBlockOtherClient runs the installed
// daemon, shim, hooks, collector and SQLite. Claude has a hint whose
// transcript is not settled (pending) and a hint whose transcript holds
// uncovered content (gap). Neither denies MCP, and a Codex hint published
// after them is captured by the same request. The pending Claude hint stays
// pending until its transcript settles, then it is captured too.
func TestInstalledStuckClientHintDoesNotBlockOtherClient(t *testing.T) {
	n := startInstalledNode(t)
	const codexCanary, claudeCanary = "codexisolationcanaryperrin", "claudesettledcanaryoswin"
	const gapSession, pendingSession, codexSession = "01990000-0000-4000-8000-000000000011", "01990000-0000-4000-8000-000000000012", "01990000-0000-4000-8000-000000000001"
	write := func(client clients.Client, session string, data []byte) string {
		t.Helper()
		rules, err := clients.HookRules(clients.Options{Client: client, Home: n.home})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.MkdirAll(rules.TranscriptRoot, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(rules.TranscriptRoot, session+".jsonl")
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	signal := func(client clients.Client, session, path string) {
		t.Helper()
		hook, _ := json.Marshal(map[string]any{"session_id": session, "transcript_path": path, "hook_event_name": "Stop"})
		if r := clients.RunHook(context.Background(), clients.Options{Client: client, Home: n.home, StateDir: n.paths.Data}, bytes.NewReader(hook)); !r.Published {
			t.Fatalf("hook not published %+v", r)
		}
	}
	pending := func(client string) int {
		t.Helper()
		names, err := os.ReadDir(filepath.Join(n.paths.Data, "spool", client, "new"))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return len(names)
	}
	claudeLine := func(text string) []byte {
		b, _ := json.Marshal(map[string]any{"type": "assistant", "message": map[string]any{"id": "msg_0", "content": []any{map[string]any{"type": "text", "text": text}}}})
		return append(b, '\n')
	}
	gapPath := write(clients.Claude, gapSession, append(claudeLine("synthetic text"), []byte("{\"type\":\"assistant\",\"message\":7}\n")...))
	pendingPath := write(clients.Claude, pendingSession, []byte("{\"type\":"))
	codex, err := os.ReadFile(filepath.Join("..", "..", "internal", "node", "capture", "testdata", "codex.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	codex = bytes.Replace(codex, []byte("Inspect the fixture."), []byte("Inspect the "+codexCanary+"."), 1)
	if !bytes.Contains(codex, []byte(codexCanary)) {
		t.Fatal("codex fixture not planted")
	}
	codexPath := write(clients.Codex, codexSession, codex)
	// The capture opener requires two seconds without source mutation.
	time.Sleep(2100 * time.Millisecond)
	signal(clients.Claude, gapSession, gapPath)
	signal(clients.Claude, pendingSession, pendingPath)
	signal(clients.Codex, codexSession, codexPath)
	for i := 0; i < 3; i++ {
		if r := n.callToolResult("telara_task_list", map[string]any{}); r.IsError {
			t.Fatalf("call %d refused while claude hints are stuck %+v", i, r)
		}
	}
	if len(n.recordsContaining(codexCanary)) == 0 {
		t.Fatal("codex hint not captured past claude's stuck hints")
	}
	if pending("codex") != 0 || pending("claude") != 1 {
		t.Fatal("spool outcomes", pending("codex"), pending("claude"))
	}
	// The pending hint is retried, not lost: once settled, it is captured.
	if err = os.WriteFile(pendingPath, claudeLine(claudeCanary), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2100 * time.Millisecond)
	if r := n.callToolResult("telara_task_list", map[string]any{}); r.IsError {
		t.Fatalf("call after settling refused %+v", r)
	}
	if pending("claude") != 0 || len(n.recordsContaining(claudeCanary)) == 0 {
		t.Fatal("settled pending hint not captured", pending("claude"))
	}
}
