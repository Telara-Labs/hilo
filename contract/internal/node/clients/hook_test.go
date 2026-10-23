package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/transport"
)

const sessionFixture = "01234567-89ab-4cde-8fab-0123456789ab"

func payload(o Options, event string) map[string]any {
	return map[string]any{"hook_event_name": event, "session_id": sessionFixture, "cwd": o.Home,
		"prompt": "secret prompt MUST NOT PERSIST", "last_assistant_message": "secret response MUST NOT PERSIST",
		"tool_input": map[string]any{"command": "secret command MUST NOT PERSIST"}, "reason": "secret error MUST NOT PERSIST"}
}
func encoded(v any) []byte { b, _ := json.Marshal(v); return b }
func spoolFiles(t *testing.T, o Options) []string {
	t.Helper()
	files, e := filepath.Glob(filepath.Join(o.StateDir, "spool", string(o.Client), "new", "*.json"))
	if e != nil {
		t.Fatal(e)
	}
	return files
}

func TestHooksEveryClientEventIdentityOnlyDaemonDown(t *testing.T) {
	for _, c := range []Client{Claude, Codex, Cursor, Pi} {
		t.Run(string(c), func(t *testing.T) {
			o := options(t, c)
			_, l, _ := resolve(o)
			path := filepath.Join(l.Transcripts, "synthetic", "session.jsonl")
			put(t, path, []byte("private raw transcript never copied\n"))
			for event := range events(c) {
				p := payload(o, event)
				p["transcript_path"] = path
				if c == Codex {
					p["turn_id"] = sessionFixture
				}
				if c == Cursor {
					delete(p, "session_id")
					delete(p, "cwd")
					p["conversation_id"] = sessionFixture
					p["generation_id"] = sessionFixture
					p["cursor_version"] = "2.1.0"
					p["workspace_roots"] = []string{o.Home}
					p["status"] = "completed"
				}
				res := RunHook(context.Background(), o, bytes.NewReader(encoded(p)))
				if !res.Published {
					t.Fatal(res)
				}
			}
			files := spoolFiles(t, o)
			if len(files) != len(events(c)) {
				t.Fatalf("files %d", len(files))
			}
			seen := map[string]bool{}
			rules, _ := HookRules(o)
			for _, path := range files {
				if !regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}\.json$`).MatchString(filepath.Base(path)) {
					t.Fatal("non-ULID name")
				}
				b := mustRead(t, path)
				if strings.Contains(string(b), "MUST NOT PERSIST") || strings.Contains(string(b), "private raw transcript") {
					t.Fatal("raw content persisted")
				}
				h, e := transport.ParseHook(b, rules)
				if e != nil || h.NativeSession != sessionFixture {
					t.Fatalf("%v %+v", e, h)
				}
				seen[h.Event] = true
				info, _ := os.Stat(path)
				if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
					t.Fatalf("spool mode %v", info.Mode())
				}
			}
			if len(seen) != len(events(c)) {
				t.Fatal("missing events")
			}
			tmp, e := os.ReadDir(filepath.Join(o.StateDir, "spool", string(c), "tmp"))
			if e != nil || len(tmp) != 0 {
				t.Fatal("abandoned partial writes", e)
			}
		})
	}
}

func TestHookBoundsMalformedAndMetadataInjection(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"event":          func(p map[string]any) { p["hook_event_name"] = "../../upload" },
		"session":        func(p map[string]any) { p["session_id"] = "secret session prose" },
		"session-secret": func(p map[string]any) { p["session_id"] = "ghp_" + strings.Repeat("a", 36) },
		"path-secret":    func(p map[string]any) { p["cwd"] = "/tmp/ghp_" + strings.Repeat("a", 36) },
		"cwd-injection":  func(p map[string]any) { p["cwd"] = "/tmp/$(network)" },
		"path-outside":   func(p map[string]any) { p["transcript_path"] = "/etc/passwd" },
	} {
		t.Run(name, func(t *testing.T) {
			o := options(t, Claude)
			p := payload(o, "Stop")
			edit(p)
			r := RunHook(context.Background(), o, bytes.NewReader(encoded(p)))
			if r.Published || len(spoolFiles(t, o)) != 0 {
				t.Fatal(r)
			}
		})
	}
	for _, b := range [][]byte{[]byte(`{"session_id":"x","session_id":"y"}`), []byte(`{"x":1} {}`), []byte(`[]`), []byte(`{"bad":"\ud800"}`), bytes.Repeat([]byte("x"), maxHookInput+1)} {
		o := options(t, Claude)
		r := RunHook(context.Background(), o, bytes.NewReader(b))
		if r.Published || len(spoolFiles(t, o)) != 0 {
			t.Fatal(r)
		}
	}
	o := options(t, Claude)
	r, w := io.Pipe()
	defer w.Close()
	start := time.Now()
	res := RunHook(context.Background(), o, r)
	if res.Code != "hook_timeout" || time.Since(start) > time.Second {
		t.Fatal(res)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res = RunHook(ctx, o, bytes.NewReader(encoded(payload(o, "Stop"))))
	if res.Published {
		t.Fatal(res)
	}
}

func TestSpoolConcurrentWholeSignals(t *testing.T) {
	o := options(t, Codex)
	type outcome struct {
		id     string
		result HookResult
	}
	var wg sync.WaitGroup
	results := make(chan outcome, 32)
	for i := 0; i < 32; i++ {
		id := fmt.Sprintf("concurrent-session-%08d", i)
		b := encoded(map[string]any{"hook_event_name": "UserPromptSubmit", "session_id": id, "cwd": o.Home})
		wg.Add(1)
		go func() { defer wg.Done(); results <- outcome{id, RunHook(context.Background(), o, bytes.NewReader(b))} }()
	}
	wg.Wait()
	close(results)
	outcomes := map[string]HookResult{}
	published := 0
	for out := range results {
		r := out.result
		outcomes[out.id] = r
		if r.Published {
			published++
		} else if r.Code != "hook_timeout" && r.Code != "spool_unavailable" {
			t.Fatal(r)
		}
	}
	if published == 0 {
		t.Fatal("no confirmed publications")
	}
	rules, _ := HookRules(o)
	seen := map[string]bool{}
	for _, path := range spoolFiles(t, o) {
		h, e := transport.ParseHook(mustRead(t, path), rules)
		if e != nil {
			t.Fatal(e)
		}
		r, ok := outcomes[h.NativeSession]
		if !ok || seen[h.NativeSession] || (!r.Published && !r.PublicationUnknown) {
			t.Fatalf("unexpected/duplicate publication %s %+v", h.NativeSession, r)
		}
		seen[h.NativeSession] = true
	}
	for id, r := range outcomes {
		if r.Published && !seen[id] {
			t.Fatalf("confirmed publication absent %s", id)
		}
	}
	// A timeout can leave an OS rename in flight. It is explicitly unknown,
	// never counted as confirmed success or asserted to be absent.
}

func TestHookFailureAlwaysProcessSuccess(t *testing.T) {
	o := options(t, Claude)
	res := runIsolated(t, o.Home, o.Executable, append([]string{"hook"}, hookArgsForTest(o)...), []byte(`malformed`))
	if res.err != nil || len(res.output) != 0 {
		t.Fatalf("failure leaked or failed process %v %q", res.err, res.output)
	}
}

func hookArgsForTest(o Options) []string { return hookArgs(o)[1:] }

func TestStartupBeforeTranscriptAndMissingAncestryIsExplicit(t *testing.T) {
	o := options(t, Claude)
	l, _ := Locations(o)
	p := payload(o, "SessionStart")
	p["transcript_path"] = filepath.Join(l.Transcripts, "not-created", "session.jsonl")
	r := RunHook(context.Background(), o, bytes.NewReader(encoded(p)))
	if !r.Published || r.TranscriptHintVerified {
		t.Fatal(r)
	}
	files := spoolFiles(t, o)
	rules, _ := HookRules(o)
	h, e := transport.ParseHook(mustRead(t, files[0]), rules)
	if e != nil || h.TranscriptPath != "" || h.NativeSession != sessionFixture {
		t.Fatalf("%+v %v", h, e)
	}
	t.Logf("actual kernel ancestry complete %v, retained levels %d; missing path omitted", r.AncestryComplete, len(h.Ancestry))
	if res := RunHook(context.Background(), o, nil); res.Published || res.Code != "invalid_input" {
		t.Fatal(res)
	}
}
