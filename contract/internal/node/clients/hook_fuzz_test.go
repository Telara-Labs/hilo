package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/transport"
)

var fuzzClients = []Client{Claude, Codex, Cursor, Pi}

type hookFuzzWorld struct {
	opts  []Options
	rules []transport.HookRules
	paths []string
}

// newHookFuzzWorld prepares one private home per client with an existing
// transcript, so seeds reach the verified-path branch.
func newHookFuzzWorld(f *testing.F) hookFuzzWorld {
	f.Helper()
	exe, err := os.Executable()
	if err != nil {
		f.Fatal(err)
	}
	var w hookFuzzWorld
	for _, c := range fuzzClients {
		home := f.TempDir()
		if runtime.GOOS != "windows" {
			if err := os.Chmod(home, 0700); err != nil {
				f.Fatal(err)
			}
		}
		o := Options{Client: c, Home: home, Executable: exe, StateDir: filepath.Join(home, "state")}
		_, l, err := resolve(o)
		if err != nil {
			f.Fatal(err)
		}
		path := filepath.Join(l.Transcripts, "synthetic", "session.jsonl")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			f.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
			f.Fatal(err)
		}
		rules, err := HookRules(o)
		if err != nil {
			f.Fatal(err)
		}
		w.opts, w.rules, w.paths = append(w.opts, o), append(w.rules, rules), append(w.paths, path)
	}
	return w
}

func (w hookFuzzWorld) seedPayloads() [][]byte {
	var out [][]byte
	for i, c := range fuzzClients {
		o := w.opts[i]
		for event := range events(c) {
			p := payload(o, event)
			p["transcript_path"] = w.paths[i]
			p["source"] = "startup"
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
			out = append(out, encoded(p))
		}
	}
	// Symlinked and escaping transcript hints, oversized and deep inputs.
	link := filepath.Join(filepath.Dir(w.paths[0]), "link.jsonl")
	_ = os.Symlink(w.paths[0], link)
	out = append(out,
		encoded(map[string]any{"hook_event_name": "Stop", "session_id": sessionFixture, "transcript_path": link}),
		encoded(map[string]any{"hook_event_name": "Stop", "session_id": sessionFixture, "transcript_path": filepath.Join(filepath.Dir(w.paths[0]), "..", "..", "..", "etc")}),
		encoded(map[string]any{"hook_event_name": "Stop", "session_id": sessionFixture, "prompt": strings.Repeat("p", maxHookInput)}),
		[]byte(`{"hook_event_name":"Stop","session_id":"`+sessionFixture+`","x":`+strings.Repeat("[", 5000)+strings.Repeat("]", 5000)+`}`),
		[]byte(`{"hook_event_name":"Stop","session_id":"`+sessionFixture+`","hook_event_name":"Stop"}`),
	)
	return out
}

// allowedHookValues are the input members whose values may legitimately be
// copied into a published signal.
var allowedHookValues = map[string]bool{"hook_event_name": true, "session_id": true, "transcript_path": true, "cwd": true,
	"conversation_id": true, "generation_id": true, "cursor_version": true, "workspace_roots": true, "turn_id": true,
	"source": true, "reason": true, "status": true}

// FuzzRunHookPayload drives the native hook entry point with arbitrary
// client payloads. Published signals must parse under the consumer's
// rules, round-trip, and never carry a value from a non-identity member.
func FuzzRunHookPayload(f *testing.F) {
	w := newHookFuzzWorld(f)
	for _, p := range w.seedPayloads() {
		for i := range fuzzClients {
			f.Add(uint8(i), p)
		}
	}
	f.Fuzz(func(t *testing.T, which uint8, in []byte) {
		i := int(which) % len(fuzzClients)
		var spooled []byte
		res := runHook(context.Background(), w.opts[i], bytes.NewReader(in), func(_ context.Context, _ Options, b []byte) error {
			spooled = append([]byte(nil), b...)
			return nil
		})
		if !res.Published {
			if spooled != nil {
				t.Fatal("unpublished result spooled bytes")
			}
			return
		}
		h, err := transport.ParseHook(spooled, w.rules[i])
		if err != nil {
			t.Fatalf("published signal refused by the consumer: %v", err)
		}
		if h.Client != string(fuzzClients[i]) || h.V != 3 {
			t.Fatal("published signal identity differs")
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal(in, &raw) != nil {
			t.Fatal("published from non-object input")
		}
		keep := map[string]bool{}
		for k, v := range raw {
			if allowedHookValues[k] {
				var s string
				if json.Unmarshal(v, &s) == nil {
					keep[s] = true
				}
				var roots []string
				if json.Unmarshal(v, &roots) == nil {
					for _, r := range roots {
						keep[r] = true
					}
				}
			}
		}
		for k, v := range raw {
			if allowedHookValues[k] {
				continue
			}
			var s string
			if json.Unmarshal(v, &s) != nil || len(s) < 12 || keep[s] {
				continue
			}
			if bytes.Contains(spooled, []byte(s)) {
				t.Fatalf("value of member %q persisted", k)
			}
		}
	})
}

// FuzzParseHook parses arbitrary spool files under every client's rules.
// Accepted signals are bounded and re-encode to a signal that parses equal.
func FuzzParseHook(f *testing.F) {
	w := newHookFuzzWorld(f)
	for _, p := range w.seedPayloads() {
		for i := range fuzzClients {
			var spooled []byte
			runHook(context.Background(), w.opts[i], bytes.NewReader(p), func(_ context.Context, _ Options, b []byte) error {
				spooled = append([]byte(nil), b...)
				return nil
			})
			if spooled != nil {
				f.Add(uint8(i), spooled)
			}
			f.Add(uint8(i), p)
		}
	}
	f.Add(uint8(0), bytes.Repeat([]byte(" "), 16<<10+1))
	f.Add(uint8(0), []byte(`{"v":3,"ancestry":[`+strings.Repeat(`{"pid":1,"start_ms":1,"argv0":"x"},`, 6)+`{"pid":1,"start_ms":1,"argv0":"x"}]}`))
	f.Fuzz(func(t *testing.T, which uint8, raw []byte) {
		i := int(which) % len(fuzzClients)
		h, err := transport.ParseHook(raw, w.rules[i])
		if err != nil {
			return
		}
		if len(raw) > 16<<10 || len(h.Ancestry) > 6 || h.V != 3 || h.Client != string(fuzzClients[i]) || !w.rules[i].Events[h.Event] {
			t.Fatal("accepted signal outside its bounds")
		}
		if h.TranscriptPath != "" && !under(w.rules[i].TranscriptRoot, h.TranscriptPath) {
			t.Fatal("accepted transcript hint outside the client root")
		}
		again, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		h2, err := transport.ParseHook(again, w.rules[i])
		if err != nil || !reflect.DeepEqual(h, h2) {
			t.Fatalf("signal re-encode round trip: %v", err)
		}
	})
}
