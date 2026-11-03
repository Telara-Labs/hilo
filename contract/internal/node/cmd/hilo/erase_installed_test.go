//go:build darwin || linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/clients"
	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/mcp"
	"github.com/Telara-Labs/hilo/contract/internal/node/shim"
)

// Disposable custody and peer doubles replace only the OS vault and the
// verified peer image. Daemon, shim, disclosure, capture and SQLite are real.
type eraseVault struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (v *eraseVault) Put(_ context.Context, k string, b []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.values == nil {
		v.values = map[string][]byte{}
	}
	if v.values[k] != nil {
		return errors.New("exists")
	}
	v.values[k] = append([]byte(nil), b...)
	return nil
}
func (v *eraseVault) Get(_ context.Context, k string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.values[k] == nil {
		return nil, errors.New("missing")
	}
	return append([]byte(nil), v.values[k]...), nil
}
func (v *eraseVault) Delete(_ context.Context, k string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	clear(v.values[k])
	delete(v.values, k)
	return nil
}

type erasePeer struct{}

func (erasePeer) VerifyAndDrain(ctx context.Context, h ipc.Hello, _ string) error {
	if h.PID != os.Getpid() || daemon.AuthenticatedPeerPID(ctx) != h.PID {
		return errors.New("peer denied")
	}
	return nil
}

type installedNode struct {
	t     *testing.T
	paths ipc.Paths
	home  string
	stop  func()
}

func startInstalledNode(t *testing.T) *installedNode {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	p, err := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	if err = os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	v := &eraseVault{}
	if err = disclosure.BootstrapInstalled(context.Background(), p.Data, "Erasure test", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, disclosure.TaskWriteGrant{Repos: disclosure.AllLocalRepos(), AllowUnscoped: true, Actions: []disclosure.TaskMutation{disclosure.Create, disclosure.Checkpoint}}, v); err != nil {
		t.Fatal(err)
	}
	provider := mcp.InstalledRuntimeProvider{Provider: disclosure.InstalledProvider{Dir: p.Data, Vault: v, Peers: erasePeer{}}, CaptureHome: home}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Config{Paths: p, Ready: func() { close(ready) }, Open: installedOpener(p.Data, "", provider)})
	}()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("daemon not ready")
	}
	var once sync.Once
	n := &installedNode{t: t, paths: p, home: home}
	n.stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("daemon did not stop")
			}
		})
	}
	t.Cleanup(n.stop)
	return n
}

// callTool sends one tools/call through a real shim session and requires success.
func (n *installedNode) callTool(tool string, args map[string]any) mcp.Result {
	n.t.Helper()
	r := n.callToolResult(tool, args)
	if r.IsError {
		n.t.Fatalf("tool error %+v", r)
	}
	return r
}

// callToolResult sends one tools/call through a real shim session.
func (n *installedNode) callToolResult(tool string, args map[string]any) mcp.Result {
	n.t.Helper()
	input, write := io.Pipe()
	read, output := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- shim.Run(ctx, input, output, shim.Config{Paths: n.paths, Hello: ipc.Hello{Shim: "erase-test-shim"}})
		output.Close()
	}()
	defer func() {
		cancel()
		write.Close()
		read.Close()
		input.Close()
		<-done
	}()
	req := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args, "_meta": map[string]any{"com.telara/conversation": "erase-conversation"}}}
	if err := json.NewEncoder(write).Encode(req); err != nil {
		n.t.Fatal(err)
	}
	line, err := bufio.NewReader(read).ReadBytes('\n')
	if err != nil {
		n.t.Fatal(err)
	}
	var response struct {
		Error  *daemon.RPCError `json:"error"`
		Result mcp.Result       `json:"result"`
	}
	if err = json.Unmarshal(line, &response); err != nil || response.Error != nil {
		n.t.Fatalf("%s %v", line, err)
	}
	return response.Result
}

func (n *installedNode) db() *sql.DB {
	n.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(n.paths.Data, "memory.sqlite")+"?mode=ro")
	if err != nil {
		n.t.Fatal(err)
	}
	return db
}

// recordsContaining returns the ids of records whose stored body or indexed
// passage holds needle.
func (n *installedNode) recordsContaining(needle string) []string {
	n.t.Helper()
	db := n.db()
	defer db.Close()
	rows, err := db.Query("SELECT id FROM record_body WHERE instr(body, ?) > 0 UNION SELECT id FROM passage WHERE instr(text, ?) > 0", needle, needle)
	if err != nil {
		n.t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			n.t.Fatal("scan id")
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		n.t.Fatal("no record holds the planted bytes")
	}
	return ids
}

// filesContaining walks every file under the data directory and returns the
// relative paths whose raw bytes contain needle.
func (n *installedNode) filesContaining(needle string) []string {
	n.t.Helper()
	var hits []string
	err := filepath.WalkDir(n.paths.Data, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(needle)) {
			rel, _ := filepath.Rel(n.paths.Data, path)
			hits = append(hits, rel)
		}
		return nil
	})
	if err != nil {
		n.t.Fatal(err)
	}
	return hits
}

// ftsShadowHits reads every FTS shadow table row and reports tables whose
// stored bytes contain needle, then checks the index itself by MATCH.
func (n *installedNode) ftsShadowHits(needle string) []string {
	n.t.Helper()
	db := n.db()
	defer db.Close()
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'search_%'")
	if err != nil {
		n.t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) != nil {
			n.t.Fatal("scan")
		}
		tables = append(tables, name)
	}
	rows.Close()
	if len(tables) == 0 {
		n.t.Fatal("no FTS shadow tables found")
	}
	var hits []string
	for _, table := range tables {
		r, err := db.Query("SELECT * FROM " + table)
		if err != nil {
			n.t.Fatal(err)
		}
		cols, _ := r.Columns()
		for r.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if r.Scan(ptrs...) != nil {
				n.t.Fatal("scan shadow row")
			}
			for _, v := range values {
				var b []byte
				switch x := v.(type) {
				case []byte:
					b = x
				case string:
					b = []byte(x)
				}
				if bytes.Contains(b, []byte(needle)) {
					hits = append(hits, table)
				}
			}
		}
		r.Close()
	}
	var matched int
	if err = db.QueryRow("SELECT count(*) FROM search WHERE search MATCH ?", needle).Scan(&matched); err != nil {
		n.t.Fatal(err)
	}
	if matched > 0 {
		hits = append(hits, "search MATCH")
	}
	return hits
}

// TestInstalledEraseRemovesPlantedBytesFromEveryFile plants distinctive bytes
// through the real task-create path, erases them through the CLI, and then
// scans the actual SQLite file, WAL, FTS shadow tables and every other file
// under the data directory for those bytes.
func TestInstalledEraseRemovesPlantedBytesFromEveryFile(t *testing.T) {
	n := startInstalledNode(t)
	canary := "plantedzephyrquokkamarmaladecanary"
	n.callTool("telara_task_create", map[string]any{"goal": "Investigate the " + canary + " fixture"})

	// Positive control: the planted bytes really are on disk and indexed.
	if hits := n.filesContaining(canary); len(hits) == 0 {
		t.Fatal("planted bytes never reached the data directory")
	}
	if hits := n.ftsShadowHits(canary); len(hits) == 0 {
		t.Fatal("planted bytes never reached the full-text index")
	}
	ids := n.recordsContaining(canary)
	var err error
	args := []string{"erase", "--data-dir", n.paths.Data, "--run-dir", n.paths.Run}
	for _, id := range ids {
		args = append(args, "--id", id)
	}

	// Without --yes a wrong confirmation is a refusal and changes nothing.
	var out bytes.Buffer
	if err = run(context.Background(), args, strings.NewReader("no\n"), &out); publicCode(err) != "confirmation_required" {
		t.Fatal("unconfirmed erase", err, out.String())
	}
	if hits := n.filesContaining(canary); len(hits) == 0 {
		t.Fatal("refused erase removed data")
	}

	out.Reset()
	if err = run(context.Background(), args, strings.NewReader("erase\n"), &out); err != nil {
		t.Fatal(publicCode(err), out.String())
	}
	text := out.String()
	for _, want := range []string{"Erasure receipt", "physical scrub", "complete at generation", "Not reachable by this erasure", "vendor transcripts"} {
		if !strings.Contains(text, want) {
			t.Fatalf("receipt missing %q\n%s", want, text)
		}
	}
	for _, id := range ids {
		if !strings.Contains(text, id+" ") || strings.Contains(text, canary) {
			t.Fatalf("receipt does not name %s or prints content\n%s", id, text)
		}
	}

	// The scrub has completed under the live daemon; check while it runs.
	if hits := n.filesContaining(canary); len(hits) != 0 {
		t.Fatal("planted bytes remain in", hits)
	}
	if hits := n.ftsShadowHits(canary); len(hits) != 0 {
		t.Fatal("planted bytes remain in FTS", hits)
	}

	// JSON receipts for a repeat erasure report no new effect.
	out.Reset()
	if err = run(context.Background(), append(args, "--yes", "--json"), strings.NewReader(""), &out); err != nil {
		t.Fatal(publicCode(err), out.String())
	}
	var repeat struct {
		Receipt struct {
			Control   string `json:"control"`
			Requested []struct {
				ID, Status string
			} `json:"requested"`
		} `json:"receipt"`
		Scrub struct {
			State string `json:"state"`
		} `json:"scrub"`
		NotReachable []string `json:"not_reachable"`
	}
	if err = json.Unmarshal(out.Bytes(), &repeat); err != nil || repeat.Scrub.State != "complete" || len(repeat.NotReachable) == 0 {
		t.Fatal(out.String(), err)
	}
	for _, r := range repeat.Receipt.Requested {
		if r.Status != "already_invalidated" {
			t.Fatalf("repeat %+v", repeat.Receipt)
		}
	}
	out.Reset()
	if err = run(context.Background(), []string{"erase", "--data-dir", n.paths.Data, "--run-dir", n.paths.Run, "--scrub-pending"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(publicCode(err), out.String())
	}

	// After a clean shutdown (final checkpoint) the bytes are still absent.
	n.stop()
	if hits := n.filesContaining(canary); len(hits) != 0 {
		t.Fatal("planted bytes reappeared after shutdown in", hits)
	}
}

func TestEraseArgumentsAndUnavailableDaemon(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, run2 := filepath.Join(base, "data"), filepath.Join(base, "run")
	id := strings.Repeat("ab", 32)
	for _, args := range [][]string{
		{"erase", "--data-dir", data, "--run-dir", run2},
		{"erase", "--data-dir", data, "--run-dir", run2, "--id", id, "--scrub-pending"},
		{"erase", "--data-dir", data, "--run-dir", run2, "--id", id, "extra"},
		{"erase", "--data-dir", data, "--run-dir", run2, "--bogus"},
	} {
		if err := run(context.Background(), args, strings.NewReader(""), io.Discard); publicCode(err) != "invalid_arguments" {
			t.Fatal(args, err)
		}
	}
	if err := run(context.Background(), []string{"erase", "--data-dir", data, "--run-dir", run2, "--id", id}, strings.NewReader(""), io.Discard); publicCode(err) != "confirmation_required" {
		t.Fatal("closed input consented", err)
	}
	if err := run(context.Background(), []string{"erase", "--data-dir", data, "--run-dir", run2, "--id", id, "--yes"}, strings.NewReader(""), io.Discard); publicCode(err) != "daemon_unavailable" {
		t.Fatal("no daemon", err)
	}
}

func TestEraseRefusesMCPConnections(t *testing.T) {
	n := startInstalledNode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := ipc.Dial(ctx, n.paths)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if err = ipc.WriteFrame(c, ipc.Hello{T: "hello", V: 1, Kind: "mcp", PID: os.Getpid(), Client: "test"}); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	if _, err = ipc.ReadFrame(r); err != nil {
		t.Fatal(err)
	}
	if err = ipc.WriteFrame(c, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "erase", "params": map[string]any{"ids": []string{strings.Repeat("ab", 32)}}}); err != nil {
		t.Fatal(err)
	}
	b, err := ipc.ReadFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(`"receipt"`)) || !bytes.Contains(b, []byte("error")) {
		t.Fatalf("MCP connection reached erase: %s", b)
	}
}

// TestInstalledEraseCapturedTranscriptBytes plants bytes through the real
// transcript capture path (hook signal, collector, sealing), erases the
// captured session records through the CLI and scans every data file. A later
// re-read of the unchanged vendor transcript must not recapture them.
func TestInstalledEraseCapturedTranscriptBytes(t *testing.T) {
	n := startInstalledNode(t)
	canary := "capturedwombatlanternmeridiancanary"
	rules, err := clients.HookRules(clients.Options{Client: clients.Claude, Home: n.home})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "capture", "testdata", "claude.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte("Read the synthetic guide."), []byte("Read the "+canary+" guide."), 1)
	if !bytes.Contains(raw, []byte(canary)) {
		t.Fatal("fixture not planted")
	}
	if err = os.MkdirAll(rules.TranscriptRoot, 0700); err != nil {
		t.Fatal(err)
	}
	transcript := filepath.Join(rules.TranscriptRoot, "01990000-0000-4000-8000-000000000001.jsonl")
	if err = os.WriteFile(transcript, raw, 0600); err != nil {
		t.Fatal(err)
	}
	// The capture opener requires two seconds without source mutation.
	time.Sleep(2100 * time.Millisecond)
	signal := func() {
		hook, _ := json.Marshal(map[string]any{"session_id": "01990000-0000-4000-8000-000000000001", "transcript_path": transcript, "hook_event_name": "Stop"})
		result := clients.RunHook(context.Background(), clients.Options{Client: clients.Claude, Home: n.home, StateDir: n.paths.Data}, bytes.NewReader(hook))
		if !result.Published {
			t.Fatalf("hook not published %+v", result)
		}
	}
	signal()
	// Every MCP request drains the client's spool before it resolves.
	n.callTool("telara_task_list", map[string]any{})
	if hits := n.filesContaining(canary); len(hits) == 0 {
		t.Fatal("captured bytes never reached the data directory")
	}
	ids := n.recordsContaining(canary)
	args := []string{"erase", "--data-dir", n.paths.Data, "--run-dir", n.paths.Run, "--yes", "--json"}
	for _, id := range ids {
		args = append(args, "--id", id)
	}
	var out bytes.Buffer
	if err = run(context.Background(), args, strings.NewReader(""), &out); err != nil {
		t.Fatal(publicCode(err), out.String())
	}
	var receipt struct {
		Receipt struct {
			EventBans int  `json:"event_bans"`
			Pending   bool `json:"erasure_pending"`
		} `json:"receipt"`
		Scrub struct {
			State string `json:"state"`
		} `json:"scrub"`
	}
	if err = json.Unmarshal(out.Bytes(), &receipt); err != nil || receipt.Scrub.State != "complete" || receipt.Receipt.EventBans == 0 || receipt.Receipt.Pending {
		t.Fatalf("captured erase %s %v", out.String(), err)
	}
	if bytes.Contains(out.Bytes(), []byte(canary)) {
		t.Fatal("receipt printed captured content")
	}
	if hits := n.filesContaining(canary); len(hits) != 0 {
		t.Fatal("captured bytes remain in", hits)
	}
	if hits := n.ftsShadowHits(canary); len(hits) != 0 {
		t.Fatal("captured bytes remain in FTS", hits)
	}
	// Re-signal the unchanged transcript: the erased unit is suppressed, so the
	// drain skips it. The signal is acknowledged, nothing is recaptured and MCP
	// keeps working, on this call and on later ones.
	signal()
	for i := 0; i < 3; i++ {
		if r := n.callToolResult("telara_task_list", map[string]any{}); r.IsError {
			t.Fatalf("call %d after re-signal refused %+v", i, r)
		}
		if hits := n.filesContaining(canary); len(hits) != 0 {
			t.Fatal("erased transcript content was recaptured into", hits)
		}
		if i == 0 {
			signal()
		}
	}
	if names, err := os.ReadDir(filepath.Join(n.paths.Data, "spool", "claude", "new")); err != nil || len(names) != 0 {
		t.Fatal("suppressed signals left pending", len(names), err)
	}
	n.stop()
	if hits := n.filesContaining(canary); len(hits) != 0 {
		t.Fatal("captured bytes reappeared after shutdown in", hits)
	}
}
