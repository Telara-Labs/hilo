//go:build e2e && darwin

package clients_test

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/TAP-Runtime/discover/redact"
	"github.com/Telara-Labs/hilo/contract/internal/node/clients"
	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/record"
	_ "modernc.org/sqlite"
)

const canary = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func runClient(t *testing.T, s clientSpec) {
	t.Helper()
	r := receipt{Client: s.name, Mode: "native", Verdict: "UNVERIFIED", Started: time.Now().UTC(), Version: "UNVERIFIED", Paths: map[string]string{}, Timings: map[string]float64{}, Checks: map[string]string{}, Cleanup: "not_needed"}
	if *dryRun {
		r.Mode = "synthetic_dry_run"
	}
	var cfg installedConfig
	var installed *installation
	defer func() {
		if installed != nil {
			if err := installed.cleanup(); err != nil {
				r.Cleanup = "FAIL"
				r.Failure += "; cleanup failed"
				t.Error(err)
			} else {
				r.Cleanup = "PASS"
			}
		}
		if cfg.Data != "" {
			r.Calls, r.Hooks = readEvidence(t, cfg.Data)
			r.Diagnostics = readDiagnostics(t, cfg.Data)
			if cfg.Debug && installed != nil && installed.manual != nil && installed.manual.Process != nil && len(r.Diagnostics) == 0 {
				t.Error("debug requested but no proof diagnostics were recorded")
			}
		}
		if cfg.Root != "" {
			if err := os.RemoveAll(cfg.Root); err != nil {
				r.Cleanup = "FAIL"
				t.Error("temp-root cleanup failed")
			}
		}
		if t.Failed() {
			r.Verdict = "FAIL"
		} else if t.Skipped() {
			r.Verdict = "SKIP"
		} else if *dryRun {
			r.Verdict = "DRY_RUN_PASS_NATIVE_UNVERIFIED"
		} else {
			r.Verdict = "PASS"
		}
		r.Seconds = time.Since(r.Started).Seconds()
		if *resultsDir != "" {
			if err := writeReceipt(*resultsDir, r); err != nil {
				t.Error("cannot write JSON receipt", err)
			}
		}
	}()
	if !*dryRun && *s.auth == "" {
		r.Failure = "operator auth flag absent"
		t.Skip("UNVERIFIED — supply -e2e-" + s.name + "-auth=/canonical/private/operator-auth.json; no user credentials are discovered")
	}
	if *resultsDir == "" {
		t.Fatal("-e2e-results-dir must name the existing canonical STATUS directory")
	}
	if err := validateResultsDir(*resultsDir); err != nil {
		r.Failure = "results directory preflight failed"
		t.Fatal(err)
	}
	parent := *tempParent
	if parent == "" {
		parent = os.TempDir()
	}
	parent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		t.Fatal(err)
	}
	ownerHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if parent == ownerHome || under(ownerHome, parent) {
		t.Fatal("temporary parent must be outside the real home")
	}
	root, err := os.MkdirTemp(parent, "mc-")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		_ = os.RemoveAll(root)
		t.Fatal(err)
	}
	cfg = installedConfig{Root: canonical, Home: filepath.Join(canonical, "home"), Data: filepath.Join(canonical, "data"), Run: filepath.Join(canonical, "run"), Install: filepath.Join(canonical, "install"), Keychain: filepath.Join(canonical, "probe.keychain"), Client: s.name, Timeout: *childTimeout, Debug: *debugRun}
	cfg.ClientConfig = filepath.Join(cfg.Home, filepath.FromSlash(s.configRelative))
	for _, p := range []string{cfg.Home, cfg.ClientConfig, filepath.Join(cfg.Home, "tmp"), filepath.Join(cfg.Home, "work-a"), filepath.Join(cfg.Home, "work-b")} {
		if err = os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	r.Paths = map[string]string{"root": cfg.Root, "home": cfg.Home, "client_config": cfg.ClientConfig, "data": cfg.Data, "run": cfg.Run, "install": cfg.Install, "keychain": cfg.Keychain}
	if !*dryRun {
		dest := filepath.Join(cfg.ClientConfig, s.authName)
		if err = copyAuth(*s.auth, dest); err != nil {
			r.Failure = "operator auth copy refused"
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4**childTimeout)
	defer cancel()
	start := time.Now()
	installed, err = setupInstallation(ctx, cfg)
	recordFailureCodes(t, &r, err)
	r.Timings["install"] = time.Since(start).Seconds()
	if err != nil {
		r.Failure = "native installation failed"
		t.Fatal(err)
	}
	r.Paths["launchd_label"] = installed.label
	env := isolatedEnv(cfg.Home, cfg.ClientConfig, s)
	start = time.Now()
	args := []string{"clients", "install", "--client", s.name, "--home", cfg.Home, "--config-root", cfg.ClientConfig, "--state-dir", cfg.Data, "--executable", installed.record.Executable}
	out, err := run(ctx, cfg.Home, env, nil, installed.record.Executable, args...)
	recordFailureCodes(t, &r, err)
	if err != nil {
		r.Failure = "adapter install failed"
		t.Fatal(err)
	}
	var report clients.Report
	if err = json.Unmarshal(out, &report); err != nil {
		t.Fatal("invalid adapter report")
	}
	if err = mergeReport(cfg, report); err != nil {
		r.Failure = "manual snippet merge failed"
		t.Fatal(err)
	}
	r.Timings["client_registration"] = time.Since(start).Seconds()
	r.Checks["registration"] = "PASS via real clients.Install in installed test image"
	n := nonce()
	if *dryRun {
		// These are synthetic drivers over real stdio/IPC/backend/SQLite, never
		// stand-ins for Claude/Codex/Cursor/Pi or proof of their tool invocation.
		for _, phaseName := range []string{"A", "B"} {
			if err = setPhase(cfg, phaseName); err != nil {
				t.Fatal(err)
			}
			tool, args := "telara_task_create", map[string]any{"goal": n}
			if phaseName == "B" {
				tool, args = "telara_task_list", map[string]any{"query": n, "mode": "detail"}
			}
			start = time.Now()
			out, err = syntheticCall(ctx, cfg, installed.record.Executable, tool, args)
			recordFailureCodes(t, &r, err)
			r.Timings["session_"+phaseName] = time.Since(start).Seconds()
			if err != nil || !bytes.Contains(out, []byte(n)) {
				r.Failure = "synthetic MCP round trip failed"
				t.Fatal("synthetic MCP call failed", err)
			}
		}
		if err = setPhase(cfg, "A"); err != nil {
			t.Fatal(err)
		}
		native := "01990000-0000-4000-8000-000000000001"
		transcript := writeSyntheticTranscript(t, cfg, native, n)
		// The production opener requires mtime and ctime quiet for two seconds.
		time.Sleep(2100 * time.Millisecond)
		payload := syntheticHook(cfg, native, transcript)
		_, err = run(ctx, cfg.Home, env, payload, installed.record.Executable, "hook", "--client", s.name, "--home", cfg.Home, "--config-root", cfg.ClientConfig, "--state-dir", cfg.Data)
		if err != nil {
			t.Fatal(err)
		}
		out, err = syntheticCall(ctx, cfg, installed.record.Executable, "telara_task_list", map[string]any{"query": n, "mode": "detail"})
		if err != nil || responseError(out) || responseTask(out, n) == "" {
			t.Fatal("pending spool capture/drain MCP failed", err)
		}
		calls, hooks := readEvidence(t, cfg.Data)
		if !sameTaskReadBack(calls, n) || terminalSession(hooks, s.name) != native {
			t.Fatal("synthetic tool/hook evidence missing or wrong task")
		}
		r.SessionIDs, err = captured(ctx, cfg.Data, s.name, native, n)
		if err != nil {
			t.Fatal("synthetic capture/redaction failed", err)
		}
		if err = captureACK(ctx, cfg.Data, s.name, 1); err != nil {
			t.Fatal(err)
		}
		// The captured session itself must also be readable through installed MCP.
		out, err = syntheticCall(ctx, cfg, installed.record.Executable, "telara_get_context", map[string]any{"entity_id": r.SessionIDs[0], "entity_type": "session", "include_content": false})
		if err != nil || responseError(out) || !responseTextContains(out, r.SessionIDs[0]) {
			t.Fatal("captured session MCP read-back failed", err)
		}
		r.Checks["mcp_round_trip"] = "PASS same task through two fresh installed shim processes"
		r.Checks["hook"] = "PASS synthetic terminal input through real hook and spool"
		r.Checks["pending_spool"] = "PASS real ingress captured and ACKed with durable receipt"
		r.Checks["capture_and_redaction"] = "PASS synthetic native format, persisted verified session/chunk, redacted canary, MCP session read-back"
		r.Checks["native_capture"] = "UNVERIFIED dry-run does not launch client binaries"
		return
	}
	binary := *s.executable
	if binary == "" {
		binary, err = exec.LookPath(s.binary)
		if err != nil {
			realHome, _ := os.UserHomeDir()
			binary = filepath.Join(realHome, ".local/bin", s.binary)
		}
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		r.Failure = "client executable unavailable"
		t.Fatal("use -e2e-" + s.name + "-bin for this installed client")
	}
	realHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	// Refuse a broad code exception that could expose credential directories.
	if codeRoot(binary) == realHome || under(codeRoot(binary), realHome) {
		t.Fatal("client binary needs a dedicated installation directory")
	}
	profile := filepath.Join(cfg.Root, "client.sb")
	if err = privateWrite(profile, []byte(clientProfile(realHome, binary, cfg))); err != nil {
		t.Fatal(err)
	}
	if err = privateWrite(filepath.Join(cfg.Root, "denied-read", "canary"), []byte("synthetic blocked-home canary")); err != nil {
		t.Fatal(err)
	}
	canaryVault := isolatedVault{cfg: cfg, exe: installed.record.Executable}
	if err = canaryVault.Put(ctx, keychainCanaryHandle, keychainCanaryValue); err != nil {
		t.Fatal("keychain canary could not be planted", err)
	}
	defer func() { _ = canaryVault.Delete(context.Background(), keychainCanaryHandle) }()
	if _, err = run(ctx, cfg.Home, env, nil, "/usr/bin/sandbox-exec", "-f", profile, installed.record.Executable, "sandbox-probe", "--data-dir", cfg.Data); err != nil {
		recordFailureCodes(t, &r, err)
		r.Failure = "native client sandbox preflight failed"
		t.Fatal(err)
	}
	r.Checks["client_sandbox"] = "PASS synthetic denied read, protected state writes and explicit isolated keychain refusal"
	clientEnv, err := isolatedClientEnv(cfg.Home, cfg.ClientConfig, s)
	if err != nil {
		t.Fatal(err)
	}
	launch := func(phaseName string, args []string) ([]byte, error) {
		return run(ctx, filepath.Join(cfg.Home, "work-"+strings.ToLower(phaseName)), clientEnv, nil, "/usr/bin/sandbox-exec", append([]string{"-f", profile, binary}, args...)...)
	}
	if out, err = launch("A", []string{"--version"}); err != nil {
		recordFailureCodes(t, &r, err)
		r.Failure = "isolated version preflight failed"
		t.Fatal(err)
	}
	r.Version = strings.TrimSpace(string(out))
	if len(r.Version) > 512 {
		r.Version = "UNVERIFIED"
		t.Fatal("unexpected version output")
	}
	r.Paths["client_binary"] = binary
	prompts := map[string]string{
		"A": "Use the hilo MCP server. Call telara_task_create exactly once with goal " + n + ". After success, write this synthetic capture canary as plain response text: CAPTURE_CANARY " + n + " " + canary + ". Then end the session. Do not use any other tools or read files.",
		"B": "This is a fresh session. Use the hilo MCP server to call telara_task_list with query " + n + " and mode detail. Print the returned task goal. Do not create a task, use shell tools or read files.",
	}
	var failures []string
	for _, phaseName := range []string{"A", "B"} {
		if err = setPhase(cfg, phaseName); err != nil {
			t.Fatal(err)
		}
		start = time.Now()
		out, err = launch(phaseName, clientArgs(s, prompts[phaseName]))
		recordFailureCodes(t, &r, err)
		r.Timings["session_"+phaseName] = time.Since(start).Seconds()
		if err != nil {
			failures = append(failures, "client session "+phaseName+" failed")
		}
		if phaseName == "A" {
			calls, hooks := readEvidence(t, cfg.Data)
			if !hasCall(calls, "A", "telara_task_create", n) {
				failures = append(failures, "successful create call not observed")
			}
			session := terminalSession(hooks, s.name)
			if session == "" {
				failures = append(failures, "published terminal hook not observed")
			} else {
				// Terminal hooks publish after the client's last memory call.
				// A separately labelled harness call triggers real ingress; it
				// cannot satisfy the required native session A/B call evidence.
				if err = setPhase(cfg, "capture"); err != nil {
					t.Fatal(err)
				}
				// Native files have the same two-second quiet requirement as
				// synthetic fixtures, even after a terminal hook has published.
				time.Sleep(2100 * time.Millisecond)
				drainOut, drainErr := syntheticCall(ctx, cfg, installed.record.Executable, "telara_task_list", map[string]any{"query": n, "mode": "detail"})
				recordFailureCodes(t, &r, drainErr)
				if drainErr != nil || responseError(drainOut) {
					failures = append(failures, "terminal capture drain failed")
				}
				clear(drainOut)
				probe, stop := context.WithTimeout(ctx, 5*time.Second)
				r.SessionIDs, err = waitCaptured(probe, cfg.Data, s.name, session, n)
				stop()
				if err != nil {
					failures = append(failures, "session capture/redaction absent or invalid")
				} else {
					r.Checks["capture_and_redaction"] = "PASS persisted native session and redacted chunk"
				}
			}
		} else {
			calls, _ := readEvidence(t, cfg.Data)
			if !hasCall(calls, "B", "telara_task_list", n) {
				failures = append(failures, "nonce not returned by successful MCP list in session B")
			}
			if !sameTaskReadBack(calls, n) {
				failures = append(failures, "session B did not return session A task identity")
			}
			if !finalTextContains(s.name, out, n) {
				failures = append(failures, "session B assistant output did not contain nonce")
			}
		}
		clear(out)
	}
	if len(failures) > 0 {
		r.Failure = strings.Join(failures, "; ")
		t.Fatal(r.Failure)
	}
	r.Checks["native_round_trip"] = "PASS two separately launched client processes, observed MCP request/response and fresh assistant output"
}

func mergeReport(cfg installedConfig, r clients.Report) error {
	for _, change := range r.Changes {
		if !under(cfg.ClientConfig, change.Path) {
			return errors.New("adapter change escaped isolated config root")
		}
		if change.Action != "manual_merge" {
			continue
		}
		// This root is new. There are no unrelated settings to overwrite. Refuse
		// even an existing destination rather than generic TOML/JSON surgery.
		if err := privateWrite(change.Path, []byte(change.Snippet)); err != nil {
			return err
		}
	}
	if cfg.Client == "cursor" {
		// Server approval and tool approval are separate Cursor controls. Only
		// these two local task tools are needed by this disposable round trip.
		// The vendor merges this profile with its defaults; allowlist mode stays
		// enabled and no wildcard, shell or filesystem permission is added.
		return privateWrite(filepath.Join(cfg.ClientConfig, "cli-config.json"), []byte(`{"approvalMode":"allowlist","permissions":{"allow":["Mcp(hilo:telara_task_create)","Mcp(hilo:telara_task_list)"],"deny":[]}}`))
	}
	if cfg.Client == "codex" {
		// Existing vendor setting forces file custody; never ask login keyring.
		p := filepath.Join(cfg.ClientConfig, "config.toml")
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(p, append([]byte("cli_auth_credentials_store = \"file\"\n"), b...), 0600)
	}
	return nil
}
func setPhase(cfg installedConfig, name string) error {
	return os.WriteFile(filepath.Join(cfg.Data, "phase"), []byte(name), 0600)
}
func terminalEvent(client string) string {
	switch client {
	case "cursor":
		return "sessionEnd"
	case "pi":
		return "session_shutdown"
	default:
		return "SessionEnd"
	}
}
func terminalSession(hooks []hookObservation, client string) string {
	for _, h := range hooks {
		if h.Phase == "A" && h.Client == client && h.Result.Published {
			switch h.Event {
			case "SessionEnd", "Stop", "stop", "sessionEnd", "agent_end", "session_shutdown":
				return h.Session
			}
		}
	}
	return ""
}
func readEvidence(t *testing.T, data string) ([]observation, []hookObservation) {
	t.Helper()
	var calls []observation
	var hooks []hookObservation
	paths, err := filepath.Glob(filepath.Join(data, "observations", "*.json"))
	if err != nil {
		t.Error(err)
		return calls, hooks
	}
	for _, p := range paths {
		b, e := privateRead(p, 2<<20)
		if e != nil {
			t.Error("observation read failed")
			continue
		}
		if strings.HasPrefix(filepath.Base(p), "call-") {
			var v observation
			if e = json.Unmarshal(b, &v); e != nil {
				t.Error("invalid call observation")
			} else {
				calls = append(calls, v)
			}
		} else if strings.HasPrefix(filepath.Base(p), "hook-") {
			var v hookObservation
			if e = json.Unmarshal(b, &v); e != nil {
				t.Error("invalid hook observation")
			} else {
				hooks = append(hooks, v)
			}
		}
	}
	sort.Slice(calls, func(i, j int) bool { return calls[i].At.Before(calls[j].At) })
	sort.Slice(hooks, func(i, j int) bool { return hooks[i].At.Before(hooks[j].At) })
	return calls, hooks
}
func hasCall(calls []observation, phaseName, tool, n string) bool {
	for _, c := range calls {
		if c.Phase == phaseName && c.Tool == tool && c.Success && bytes.Contains(c.Arguments, []byte(n)) && responseTask(c.Response, n) != "" {
			return true
		}
	}
	return false
}

var taskIdentityPattern = regexp.MustCompile(`task_id\s+([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})`)

func responseTask(raw []byte, n string) string {
	var r struct {
		Error  any `json:"error"`
		Result struct {
			IsError bool                          `json:"isError"`
			Content []struct{ Type, Text string } `json:"content"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &r) != nil || r.Error != nil || r.Result.IsError {
		return ""
	}
	for _, content := range r.Result.Content {
		if content.Type == "text" && strings.Contains(content.Text, n) {
			match := taskIdentityPattern.FindStringSubmatch(content.Text)
			if len(match) == 2 {
				return match[1]
			}
		}
	}
	return ""
}
func sameTaskReadBack(calls []observation, n string) bool {
	created := map[string]bool{}
	for _, c := range calls {
		if c.Phase == "A" && c.Tool == "telara_task_create" && c.Success {
			if id := responseTask(c.Response, n); id != "" {
				created[id] = true
			}
		}
	}
	for _, c := range calls {
		if c.Phase == "B" && c.Tool == "telara_task_list" && c.Success && created[responseTask(c.Response, n)] {
			return true
		}
	}
	return false
}
func responseError(raw []byte) bool {
	var r struct {
		Error  any `json:"error"`
		Result struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	return json.Unmarshal(raw, &r) == nil && (r.Error != nil || r.Result.IsError)
}

func responseTextContains(raw []byte, text string) bool {
	var response struct {
		Error  any `json:"error"`
		Result struct {
			IsError bool                          `json:"isError"`
			Content []struct{ Type, Text string } `json:"content"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &response) != nil || response.Error != nil || response.Result.IsError {
		return false
	}
	for _, part := range response.Result.Content {
		if part.Type == "text" && strings.Contains(part.Text, text) {
			return true
		}
	}
	return false
}

func syntheticCall(ctx context.Context, cfg installedConfig, exe, tool string, args map[string]any) ([]byte, error) {
	if err := verifyShimImage(cfg, exe); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, *childTimeout)
	defer cancel()
	cmd := command(ctx, cfg.Home, isolatedEnv(cfg.Home, cfg.ClientConfig, specFor(cfg.Client)), exe, "shim", "--data-dir", cfg.Data)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	defer func() { in.Close(); _ = cmd.Cancel(); _ = cmd.Wait() }()
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": args, "_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": daemon.LatestProtocolVersion, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}})
	if err = ipc.WriteFrame(in, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params}); err != nil {
		return nil, err
	}
	return ipc.ReadFrame(bufio.NewReader(out))
}

// Parse typed assistant output only, never echoed prompt/argument substrings.
func finalTextContains(client string, out []byte, n string) bool {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 4096), 8<<20)
	for scanner.Scan() {
		var m map[string]json.RawMessage
		if json.Unmarshal(scanner.Bytes(), &m) != nil {
			continue
		}
		str := func(raw json.RawMessage) string { var s string; _ = json.Unmarshal(raw, &s); return s }
		typ := str(m["type"])
		if client == "codex" && typ == "item.completed" {
			var item struct{ Type, Text string }
			if json.Unmarshal(m["item"], &item) == nil && item.Type == "agent_message" && strings.Contains(item.Text, n) {
				return true
			}
		}
		if (client == "claude" || client == "cursor") && typ == "result" && strings.Contains(str(m["result"]), n) {
			return true
		}
		if typ == "assistant" || typ == "message_end" {
			var msg struct {
				Role    string
				Content []struct{ Type, Text string }
			}
			if json.Unmarshal(m["message"], &msg) == nil && msg.Role == "assistant" {
				for _, b := range msg.Content {
					if b.Type == "text" && strings.Contains(b.Text, n) {
						return true
					}
				}
			}
		}
	}
	return false
}

func waitCaptured(ctx context.Context, data, client, native, n string) ([]string, error) {
	for {
		ids, err := captured(ctx, data, client, native, n)
		if err == nil {
			return ids, nil
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func captured(ctx context.Context, data, client, native, n string) ([]string, error) {
	u := url.URL{Scheme: "file", Path: filepath.Join(data, "memory.sqlite"), RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, err := db.QueryContext(ctx, "SELECT r.id,r.header,b.body,r.state,r.sig_status FROM record r JOIN record_body b ON b.id=r.id ORDER BY r.seq")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	clientID := captureClient(client)
	var ids []string
	sessionKeys := map[string]bool{}
	sessionChunks := map[string]map[string]bool{}
	chunks := map[string][]*record.Record{}
	for rows.Next() {
		var id string
		var state, signature string
		var h, b []byte
		if err = rows.Scan(&id, &h, &b, &state, &signature); err != nil {
			return nil, err
		}
		rec, e := record.Parse(h, b, id)
		if e != nil {
			return nil, errors.New("invalid stored record")
		}
		if bytes.Contains(b, []byte(canary)) {
			return nil, errors.New("raw canary persisted in store")
		}
		if state != "live" || signature != "verified" {
			continue
		}
		if rec.Header.Subj.Client == nil || rec.Header.Subj.Client.ID != clientID {
			continue
		}
		if rec.Header.Type != record.KindSession && rec.Header.Type != record.KindChunk {
			continue
		}
		if rec.Header.Red.Epoch <= 0 || rec.Header.Red.Fingerprint == "" || rec.Header.Prov != record.ProvTranscript {
			return nil, errors.New("missing transcript provenance/redaction state")
		}
		if body, ok := rec.Body.(*record.SessionBody); ok && body.NativeID == native {
			ids = append(ids, id)
			sessionKeys[rec.Header.Subj.SessionKey] = true
			if sessionChunks[rec.Header.Subj.SessionKey] == nil {
				sessionChunks[rec.Header.Subj.SessionKey] = map[string]bool{}
			}
			for _, chunkID := range body.Chunks {
				sessionChunks[rec.Header.Subj.SessionKey][chunkID] = true
			}
		}
		if _, ok := rec.Body.(*record.ChunkBody); ok {
			chunks[rec.Header.Subj.SessionKey] = append(chunks[rec.Header.Subj.SessionKey], rec)
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	for key := range sessionKeys {
		for _, chunk := range chunks[key] {
			if !sessionChunks[key][chunk.ID] {
				continue
			}
			body := chunk.Body.(*record.ChunkBody)
			for _, event := range body.Events {
				if event.Text != nil && strings.Contains(event.Text.Body, "CAPTURE_CANARY "+n) && strings.Contains(event.Text.Body, redact.Redact(canary)) {
					return ids, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("native session with redacted canary absent for %s", client)
}
