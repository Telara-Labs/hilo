//go:build e2e && darwin

package clients_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
)

func canonicalTemp(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHarnessAuthIsolation(t *testing.T) {
	root := canonicalTemp(t)
	source := filepath.Join(root, "operator.json")
	payload := []byte(`{"token":"operator-supplied-synthetic"}`)
	if err := privateWrite(source, payload); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "isolated/auth.json")
	if err := copyAuth(source, dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("auth copy changed")
	}
	if b, e := privateRead(dest, 1024); e != nil || !bytes.Equal(b, payload) {
		t.Fatal("private read failed")
	}
	if _, e := privateRead(dest, 1); e == nil {
		t.Fatal("private read exceeded bound")
	}
	st, err := os.Stat(dest)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("auth permissions")
	}
	if err = copyAuth(source, dest); err == nil {
		t.Fatal("overwrote an existing config")
	}
	link := filepath.Join(root, "link.json")
	if err = os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if _, e := privateRead(link, 1024); e == nil {
		t.Fatal("private read followed symlink")
	}
	if err = copyAuth(link, filepath.Join(root, "linked.json")); err == nil {
		t.Fatal("followed source symlink")
	}
	if err = os.Chmod(source, 0644); err != nil {
		t.Fatal(err)
	}
	if err = copyAuth(source, filepath.Join(root, "public.json")); err == nil {
		t.Fatal("accepted public auth input")
	}
	if err = copyAuth(root, filepath.Join(root, "directory.json")); err == nil {
		t.Fatal("accepted directory")
	}
	if err = copyAuth("relative.json", filepath.Join(root, "relative.json")); err == nil {
		t.Fatal("accepted relative source")
	}
	parentLink := filepath.Join(root, "parent-link")
	if err = os.Symlink(filepath.Join(root, "isolated"), parentLink); err != nil {
		t.Fatal(err)
	}
	if err = privateWrite(filepath.Join(parentLink, "refused.json"), []byte("{}")); err == nil {
		t.Fatal("followed destination parent symlink")
	}
	if err = privateWrite(filepath.Join(root, "bad.json"), []byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	if err = copyAuth(filepath.Join(root, "bad.json"), filepath.Join(root, "bad-copy.json")); err == nil {
		t.Fatal("accepted non-object auth")
	}
	// Operator input stays untouched, even after destination deletion.
	if err = os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(source)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("operator source changed")
	}
}

func TestHarnessEnvironmentAndArguments(t *testing.T) {
	root := canonicalTemp(t)
	for _, s := range specs {
		t.Run(s.name, func(t *testing.T) {
			env := isolatedEnv(root, filepath.Join(root, s.configRelative), s)
			seen := map[string]string{}
			for _, v := range env {
				parts := strings.SplitN(v, "=", 2)
				if len(parts) != 2 {
					t.Fatal(v)
				}
				seen[parts[0]] = parts[1]
			}
			if seen["HOME"] != root || !under(root, seen[s.configVariable]) || !under(root, seen["TMPDIR"]) {
				t.Fatal("child escaped isolated homes")
			}
			if (s.name == "cursor" && seen["AGENT_CLI_CREDENTIAL_STORE"] != "file") || (s.name != "cursor" && seen["AGENT_CLI_CREDENTIAL_STORE"] != "") {
				t.Fatal("credential-store override escaped Cursor test scope")
			}
			for _, key := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CODEX_API_KEY", "CURSOR_API_KEY", "CLAUDECODE", "NODE_OPTIONS", "BASH_ENV"} {
				if _, ok := seen[key]; ok {
					t.Fatal("inherited secret or startup override", key)
				}
			}
			args := clientArgs(s, "unique prompt")
			if !strings.Contains(strings.Join(args, " "), "unique prompt") {
				t.Fatal("prompt absent")
			}
			for _, a := range args {
				if strings.Contains(a, "resume") || strings.Contains(a, "continue") {
					t.Fatal("session is not fresh")
				}
			}
		})
	}
	p := clientProfile("/Users/operator", "/opt/client/install/client", installedConfig{Root: "/private/probe", Home: "/private/probe/home", Data: "/private/probe/data", Run: "/private/probe/run", Install: "/private/probe/install"})
	for _, want := range []string{"deny file-read* file-write*", "com.apple.securityd", "com.apple.secd", "com.apple.security.agent", "/Users/operator"} {
		if !strings.Contains(p, want) {
			t.Fatal("missing sandbox rule", want)
		}
	}
	if codeRoot("/Users/operator/npm/node_modules/@vendor/pi/dist/cli.js") != "/Users/operator/npm/node_modules" {
		t.Fatal("package dependencies not isolated with code")
	}
}

func TestHarnessHelperConfiguration(t *testing.T) {
	root := canonicalTemp(t)
	cfg := installedConfig{Root: root, Home: filepath.Join(root, "home"), Data: filepath.Join(root, "data"), Run: filepath.Join(root, "run"), Install: filepath.Join(root, "install"), Keychain: filepath.Join(root, "probe.keychain"), Client: "claude", Timeout: time.Second}
	cfg.ClientConfig = filepath.Join(cfg.Home, ".claude")
	b, _ := json.Marshal(cfg)
	path := filepath.Join(cfg.Data, "harness.json")
	if err := privateWrite(path, b); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstalled(cfg.Data); err != nil {
		t.Fatal(err)
	}
	cfg.Home = "/Users/operator"
	b, _ = json.Marshal(cfg)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstalled(cfg.Data); err == nil {
		t.Fatal("helper accepted real-home escape")
	}
	if err := os.WriteFile(path, []byte(`{"Client":"unexpected"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstalled(cfg.Data); err == nil {
		t.Fatal("helper accepted invalid config")
	}
}

func TestHarnessAdapterMergeAndHookSpool(t *testing.T) {
	for _, s := range specs {
		t.Run(s.name, func(t *testing.T) {
			root := canonicalTemp(t)
			home := filepath.Join(root, "home")
			cfg := installedConfig{Root: root, Home: home, Data: filepath.Join(root, "data"), ClientConfig: filepath.Join(home, s.configRelative), Client: s.name}
			if err := os.MkdirAll(cfg.ClientConfig, 0700); err != nil {
				t.Fatal(err)
			}
			o := clients.Options{Client: clients.Client(s.name), Home: home, ConfigRoot: cfg.ClientConfig, Executable: mustExecutable(), StateDir: cfg.Data}
			report, err := clients.Install(context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			if err = mergeReport(cfg, report); err != nil {
				t.Fatal(err)
			}
			if s.name != "pi" {
				if err = mergeReport(cfg, report); err == nil {
					t.Fatal("manual merge overwrote prior config")
				}
			}
			malicious := clients.Report{Changes: []clients.Change{{Path: filepath.Join(root, "escaped"), Action: "manual_merge", Snippet: "{}"}}}
			if err = mergeReport(cfg, malicious); err == nil {
				t.Fatal("merge escaped config root")
			}
			payload, _ := json.Marshal(map[string]any{"hook_event_name": terminalEvent(s.name), "session_id": "harness_session_12345678", "cwd": home})
			r := clients.RunHook(context.Background(), o, bytes.NewReader(payload))
			if !r.Published {
				t.Fatalf("actual hook did not publish: %+v", r)
			}
			files, _ := filepath.Glob(filepath.Join(cfg.Data, "spool", s.name, "new", "*.json"))
			if len(files) != 1 {
				t.Fatal("terminal hook spool absent")
			}
			b, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(b, []byte(terminalEvent(s.name))) {
				t.Fatal("wrong native event")
			}
			if _, err = clients.Uninstall(context.Background(), o); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHarnessEvidenceRejectsEchoesAndFailures(t *testing.T) {
	n := "nonce_from_result"
	for _, s := range specs {
		if finalTextContains(s.name, []byte(`{"type":"user","result":"nonce_from_result","message":{"role":"user","content":[{"type":"text","text":"nonce_from_result"}]}}`), n) {
			t.Fatal("echo accepted", s.name)
		}
	}
	valid := map[string]string{
		"claude": `{"type":"result","result":"nonce_from_result"}`,
		"codex":  `{"type":"item.completed","item":{"type":"agent_message","text":"nonce_from_result"}}`,
		"cursor": `{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"nonce_from_result"}]}}`,
		"pi":     `{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"nonce_from_result"}]}}`,
	}
	for client, raw := range valid {
		if !finalTextContains(client, []byte(raw), n) {
			t.Fatal("valid assistant text rejected", client)
		}
	}
	calls := []observation{{Phase: "B", Tool: "telara_task_list", Arguments: json.RawMessage(`{"query":"nonce_from_result"}`), Response: json.RawMessage(`{"result":{"isError":false,"content":[{"type":"text","text":"task_id 01990000-0000-4000-8000-000000000001\ngoal nonce_from_result"}]}}`), Success: true}}
	if !hasCall(calls, "B", "telara_task_list", n) {
		t.Fatal("valid call rejected")
	}
	calls[0].Success = false
	if hasCall(calls, "B", "telara_task_list", n) {
		t.Fatal("failed call accepted")
	}
	calls[0].Success = true
	if sameTaskReadBack(calls, n) {
		t.Fatal("list without create accepted")
	}
	created := calls[0]
	created.Phase = "A"
	created.Tool = "telara_task_create"
	calls = append(calls, created)
	if !sameTaskReadBack(calls, n) {
		t.Fatal("same task read-back refused")
	}
	calls[0].Response = json.RawMessage(`{"result":{"isError":false,"content":[{"type":"text","text":"task_id 01990000-0000-4000-8000-000000000002\ngoal nonce_from_result"}]}}`)
	if sameTaskReadBack(calls, n) {
		t.Fatal("different task identity accepted")
	}
	hooks := []hookObservation{{Phase: "A", Client: "claude", Event: "SessionStart", Session: "native_session", Result: clients.HookResult{Published: true}}}
	if terminalSession(hooks, "claude") != "" {
		t.Fatal("start is not terminal evidence")
	}
	hooks[0].Event = "Stop"
	if terminalSession(hooks, "claude") != "native_session" {
		t.Fatal("stop evidence rejected")
	}
	hooks[0].Result.Published = false
	if terminalSession(hooks, "claude") != "" {
		t.Fatal("unpublished hook accepted")
	}
	if !responseError([]byte(`{"result":{"isError":true}}`)) || responseError([]byte(`garbage`)) {
		t.Fatal("invalid response classification")
	}
}

func TestHarnessSessionReadBackRejectsEchoAndMalformedOutput(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, raw := range []string{
		`{"params":{"entity_id":"` + id + `"}}`,
		`{"result":{"isError":true,"content":[{"type":"text","text":"` + id + `"}]}}`,
		`{"error":{"message":"` + id + `"},"result":{"content":[{"type":"text","text":"` + id + `"}]}}`,
		`{"result":{"content":[{"type":"image","text":"` + id + `"}]}}`,
		`garbage ` + id,
	} {
		if responseTextContains([]byte(raw), id) {
			t.Fatal("session read-back accepted request/failed/untyped output")
		}
	}
	if !responseTextContains([]byte(`{"result":{"isError":false,"content":[{"type":"text","text":"record_id `+id+`"}]}}`), id) {
		t.Fatal("valid typed session read-back refused")
	}
}

func TestHarnessReceiptAndBounds(t *testing.T) {
	root := canonicalTemp(t)
	if err := writeReceipt(root, receipt{Client: "claude", Verdict: "SKIP"}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(root, "clients-e2e-*.json"))
	if len(files) != 1 {
		t.Fatal("receipt missing")
	}
	st, err := os.Stat(files[0])
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("receipt not private")
	}
	var b cappedBuffer
	input := bytes.Repeat([]byte("x"), (8<<20)+1)
	count, err := b.Write(input)
	if err != nil || count != len(input) || !b.overflow || b.Len() != 8<<20 {
		t.Fatal("child output not bounded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = run(ctx, root, []string{"HOME=" + root}, nil, mustExecutable(), "-test.run=^TestHarnessSlowChild$")
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatal("child timeout failed", err)
	}
}

func TestHarnessNativeUtilityCompileAndIPCIsolation(t *testing.T) {
	root := canonicalTemp(t)
	source := filepath.Join(root, "keychain.c")
	if err := privateWrite(source, []byte(keychainSource)); err != nil {
		t.Fatal(err)
	}
	// Compile the utility. Only its peer-exe mode is executed below.
	if _, err := run(context.Background(), root, []string{"HOME=" + root, "PATH=/usr/bin:/bin", "TMPDIR=" + root}, nil, "/usr/bin/clang", "-Wno-deprecated-declarations", source, "-framework", "Security", "-framework", "CoreFoundation", "-o", filepath.Join(root, "keychain-helper")); err != nil {
		t.Fatal("native utility did not compile", err)
	}
	// Query only this test process with the public native executable API. This
	// utility mode returns before calling any Security/keychain operation.
	out, err := run(context.Background(), root, []string{"HOME=" + root, "PATH=/usr/bin:/bin"}, nil, filepath.Join(root, "keychain-helper"), "peer-exe", strconv.Itoa(os.Getpid()))
	expected, _ := filepath.EvalSymlinks(mustExecutable())
	if err != nil || string(out) != expected {
		t.Fatal("native peer executable query failed", err)
	}
	for _, pid := range []string{"0", "-1", "2147483648", "12bad"} {
		if _, err = run(context.Background(), root, []string{"HOME=" + root}, nil, filepath.Join(root, "keychain-helper"), "peer-exe", pid); err == nil {
			t.Fatal("invalid peer PID accepted")
		}
	}
	cfg := installedConfig{Root: "/private/short-owned", Data: "/private/short-owned/data", Run: "/private/short-owned/run"}
	if _, err := isolatedPaths(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Run = cfg.Root + "/" + strings.Repeat("x", 110)
	if _, err := isolatedPaths(cfg); err == nil {
		t.Fatal("allowed IPC fallback outside isolated root")
	}
}

func TestHarnessSlowChild(t *testing.T) {
	// Executed only when explicitly selected by the parent timeout regression.
	if len(os.Args) == 2 && os.Args[1] == "-test.run=^TestHarnessSlowChild$" {
		time.Sleep(5 * time.Second)
	}
}

func TestHarnessPrecompiledNativeHelper(t *testing.T) {
	root := canonicalTemp(t)
	source := filepath.Join(root, "ci-helper")
	payload := []byte("synthetic helper bytes")
	if err := privateWrite(source, payload); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	dest := filepath.Join(root, "copied-helper")
	if err := copyNativeHelper(source, digest, dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("native utility copy mismatch")
	}
	if err := copyNativeHelper(source, strings.Repeat("0", 64), filepath.Join(root, "bad")); err == nil {
		t.Fatal("untrusted utility accepted")
	}
	if err := copyNativeHelper(source, "", filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing utility digest accepted")
	}
}
