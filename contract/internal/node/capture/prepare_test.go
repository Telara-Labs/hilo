//go:build linux || darwin

package capture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Telara-Labs/hilo/contract/record"
)

const syntheticSession = "01990000-0000-4000-8000-000000000001"

func fixture(t *testing.T, client string, data []byte) (preparationConfig, unitLocator) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	policy, err := selectLocalPolicy("local", false)
	if err != nil {
		t.Fatal(err)
	}
	u := unitLocator{client: client, relative: syntheticSession + ".jsonl"}
	if client == "codex" {
		u.relative = "rollout-2026-01-01T00-00-00-" + syntheticSession + ".jsonl"
	}
	if err = os.WriteFile(filepath.Join(root, u.relative), data, 0600); err != nil {
		t.Fatal(err)
	}
	c := preparationConfig{root: root, home: root, owner: strings.Repeat("a", 32), machine: syntheticSession, enabled: true, policy: policy}
	bindIdentity(t, c, &u, syntheticSession)
	return c, u
}

func bindIdentity(t *testing.T, c preparationConfig, u *unitLocator, native string) {
	t.Helper()
	rel, err := filepath.Rel(c.home, c.root)
	if err != nil {
		t.Fatal(err)
	}
	u.source, err = record.SourceKey(u.client, c.machine, filepath.ToSlash(filepath.Join(rel, u.relative)))
	if err != nil {
		t.Fatal(err)
	}
	kind := record.NativeLocal
	if record.IsUUID(native) {
		kind = record.NativeGlobal
	}
	u.session, err = record.SessionKey(u.client, "local", kind, native, c.machine)
	if err != nil {
		t.Fatal(err)
	}
}
func allow(context.Context, sourceOccurrence) (gateState, error) { return gateState{}, nil }
func requireHeld(t *testing.T, b preparedBatch, err error, code string) {
	t.Helper()
	if err == nil || err.Error() != "capture held: "+code {
		t.Fatalf("want fixed hold %s, got %v", code, err)
	}
	if !reflect.DeepEqual(b, preparedBatch{}) {
		t.Fatal("held batch exposed prepared state")
	}
}
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSyntheticNativeFilesKeepPositionsAndFixedProvenance(t *testing.T) {
	for _, client := range []string{"claude-code", "codex"} {
		t.Run(client, func(t *testing.T) {
			name := client
			if client == "claude-code" {
				name = "claude"
			}
			c, u := fixture(t, client, readFixture(t, name))
			batch, err := prepare(context.Background(), c, u, allow)
			if err != nil {
				t.Fatal(err)
			}
			if batch.provenance != "untrusted_local_file" || batch.occurrence.owner != c.owner || batch.occurrence.machine != c.machine || batch.reader != readerVersion || batch.ruleset != localPolicyID {
				t.Fatal("native fields influenced fixed context")
			}
			want := 9
			if client == "codex" {
				want = 7
			}
			if len(batch.observations) != want {
				t.Fatalf("want %d observations, got %d: %+v", want, len(batch.observations), batch.observations)
			}
			again, err := prepare(context.Background(), c, u, allow)
			if err != nil || !reflect.DeepEqual(batch, again) {
				t.Fatal("unchanged snapshot normalization is unstable", err)
			}
			if client == "claude-code" {
				if batch.observations[1].position != (position{1, 0, 0}) || batch.observations[2].position != (position{1, 1, 0}) || batch.observations[6].position != (position{3, 0, 0}) || batch.observations[7].position != (position{3, 0, 1}) {
					t.Fatal("native block positions lost")
				}
			} else {
				if batch.observations[1].position != (position{2, 0, 0}) || batch.observations[2].position != (position{2, 1, 0}) {
					t.Fatal("Codex request blocks coalesced")
				}
				args := batch.observations[3].fields
				found := false
				for _, f := range args {
					if f.name == "settings" && strings.Contains(f.text, "9007199254740993") && strings.Contains(f.text, "true") {
						found = true
					}
				}
				if !found {
					t.Fatal("structured arguments lost numeric precision/types")
				}
			}
		})
	}
}

func TestPreOpenFenceAndIdentityFailuresDoNotOpen(t *testing.T) {
	c, u := fixture(t, "claude-code", nil)
	if err := os.Remove(filepath.Join(c.root, u.relative)); err != nil {
		t.Fatal(err)
	}
	// The file does not exist. A filesystem error instead of the required gate
	// result demonstrates an impermissible open before the policy/fence check.
	calls := 0
	gate := func(_ context.Context, occ sourceOccurrence) (gateState, error) {
		calls++
		if occ != (sourceOccurrence{u.source, u.session, c.owner, c.machine}) {
			t.Fatal("wrong fence occurrence")
		}
		return gateState{suppressed: true}, nil
	}
	b, err := prepare(context.Background(), c, u, gate)
	requireHeld(t, b, err, "suppressed")
	if calls != 1 {
		t.Fatal("missing pre-open gate")
	}
	b, err = prepare(context.Background(), c, u, nil)
	requireHeld(t, b, err, "missing_gate")
	b, err = prepare(context.Background(), c, u, func(context.Context, sourceOccurrence) (gateState, error) {
		return gateState{}, errors.New("secret provider message")
	})
	requireHeld(t, b, err, "gate_unavailable")
	c.enabled = false
	b, err = prepare(context.Background(), c, u, allow)
	requireHeld(t, b, err, "no_capture")
	c.enabled = true
	u.relative = "unresolved.jsonl"
	calls = 0
	b, err = prepare(context.Background(), c, u, gate)
	requireHeld(t, b, err, "unresolved_session")
	if calls != 0 {
		t.Fatal("unresolved session reached gate/open")
	}
	for _, path := range []string{"../outside.jsonl", "/absolute.jsonl", "sub/../unit.jsonl"} {
		u.relative = path
		b, err = prepare(context.Background(), c, u, allow)
		requireHeld(t, b, err, "unsafe_path")
	}
	u.relative = "unit.jsonl.zst"
	b, err = prepare(context.Background(), c, u, allow)
	requireHeld(t, b, err, "unsupported_format")
	u.client = "unsupported-client"
	b, err = prepare(context.Background(), c, u, allow)
	requireHeld(t, b, err, "unsupported_client")
}

func TestTrustedMappingAndNativeSessionConflict(t *testing.T) {
	c, u := fixture(t, "claude-code", []byte(`{"type":"user","sessionId":"native_session","message":{"content":"synthetic"}}`+"\n"))
	old := u.relative
	u.relative = "mapped.jsonl"
	u.mappedSession = "native_session"
	bindIdentity(t, c, &u, u.mappedSession)
	if err := os.Rename(filepath.Join(c.root, old), filepath.Join(c.root, u.relative)); err != nil {
		t.Fatal(err)
	}
	if _, err := prepare(context.Background(), c, u, allow); err != nil {
		t.Fatal(err)
	}
	u.mappedSession = "other_native_session"
	bindIdentity(t, c, &u, u.mappedSession)
	b, err := prepare(context.Background(), c, u, allow)
	requireHeld(t, b, err, "session_mismatch")
}

func TestCanonicalIdentityMismatchHoldsBeforeGateOrOpen(t *testing.T) {
	for _, change := range []string{"source", "session", "filename", "mapped_filename", "home"} {
		t.Run(change, func(t *testing.T) {
			c, u := fixture(t, "claude-code", nil)
			if err := os.Remove(filepath.Join(c.root, u.relative)); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "source":
				u.source = strings.Repeat("b", 64)
			case "session":
				u.session = "sk1:" + strings.Repeat("b", 64)
			case "filename":
				u.relative = "01990000-0000-4000-8000-000000000002.jsonl"
			case "mapped_filename":
				u.mappedSession = "01990000-0000-4000-8000-000000000002"
			case "home":
				c.home = filepath.Dir(c.home)
			}
			calls := 0
			b, err := prepare(context.Background(), c, u, func(context.Context, sourceOccurrence) (gateState, error) { calls++; return gateState{}, nil })
			requireHeld(t, b, err, "identity_mismatch")
			if calls != 0 {
				t.Fatal("mismatched occurrence reached gate/open")
			}
		})
	}
}

func TestCopiedSourceStillChecksSameSuppressedSessionBeforeOpen(t *testing.T) {
	c, u := fixture(t, "claude-code", nil)
	originalSource := u.source
	erasedSession := u.session
	u.relative = filepath.Join("copied", u.relative)
	bindIdentity(t, c, &u, syntheticSession)
	if u.source == originalSource || u.session != erasedSession {
		t.Fatal("copy identities do not follow frozen derivation")
	}
	// The new path does not even exist. Session suppression must win before
	// the opener touches the copied source regardless of its new source key.
	calls := 0
	b, err := prepare(context.Background(), c, u, func(_ context.Context, occ sourceOccurrence) (gateState, error) {
		calls++
		return gateState{suppressed: occ.session == erasedSession}, nil
	})
	requireHeld(t, b, err, "suppressed")
	if calls != 1 {
		t.Fatal("missing copied-source session fence")
	}
}

type recordingNodeRules struct{ seen map[string]string }

func (r recordingNodeRules) text(s string) string {
	return strings.ReplaceAll(s, "NODE_ONLY_CANARY", "[node-redacted]")
}
func (r recordingNodeRules) argument(name, s string) string { r.seen[name] = s; return r.text(s) }

func TestFullNativeArgumentsReachNodeRulesBeforeAnyCap(t *testing.T) {
	// The canary starts beyond TAP Flatten's old 32-KiB bound. Recording the
	// actual input is essential: canary absence from capped output proves none.
	long := strings.Repeat("x", 40<<10) + "NODE_ONLY_CANARY" + strings.Repeat("y", 40<<10)
	args := map[string]any{"nested": map[string]any{"escaped_key": long, "n": json.Number("9007199254740993"), "enabled": true}}
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	claude := map[string]any{"type": "assistant", "message": map[string]any{"content": []any{map[string]any{"type": "tool_use", "id": "call_a", "name": "fixture", "input": json.RawMessage(encoded)}}}}
	encodedString, _ := json.Marshal(string(encoded))
	codex := map[string]any{"type": "response_item", "payload": map[string]any{"type": "function_call", "call_id": "call_a", "name": "fixture", "arguments": json.RawMessage(encodedString)}}
	for _, tc := range []struct {
		name   string
		native any
		decode func([]byte, int, string) ([]preparedObservation, error)
	}{{"claude", claude, decodeClaude}, {"codex", codex, decodeCodex}} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.native)
			if err := strictJSON(raw); err != nil {
				t.Fatal(err)
			}
			out, err := tc.decode(raw, 1, syntheticSession)
			if err != nil || len(out) != 1 {
				t.Fatal("decode", err)
			}
			rules := recordingNodeRules{seen: map[string]string{}}
			clean, err := redactObservation(out[0], rules)
			if err != nil {
				t.Fatal(err)
			}
			seen := rules.seen["nested"]
			if len(seen) <= 80<<10 || !strings.Contains(seen, long) || !strings.Contains(seen, "9007199254740993") || !strings.Contains(seen, "true") {
				t.Fatal("node rule did not receive complete typed raw field")
			}
			for _, f := range clean.fields {
				if f.name == "nested" && (!f.truncated || len(f.text) > maxText || strings.Contains(f.text, "NODE_ONLY_CANARY")) {
					t.Fatal("node redaction/bound order failed")
				}
			}
		})
	}
	// A smaller value retains the node-only replacement in the actual output,
	// independently proving the rule ran rather than merely losing the middle.
	o := preparedObservation{fields: []field{{name: "nested", text: `{"key":"NODE_ONLY_CANARY"}`, argument: true}}}
	clean, err := redactObservation(o, recordingNodeRules{seen: map[string]string{}})
	if err != nil || !strings.Contains(clean.fields[0].text, "[node-redacted]") {
		t.Fatal("node-only rule omitted", err)
	}
}

func TestActualLocalPolicyRedactsAllNativeTextAndNamedArguments(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a", 36)
	content := strings.Repeat("p", 40<<10) + secret + strings.Repeat("s", 40<<10)
	raw, _ := json.Marshal(map[string]any{"type": "assistant", "cwd": secret, "message": map[string]any{"content": []any{map[string]any{"type": "text", "text": content}, map[string]any{"type": "tool_use", "id": "call_a", "name": "fixture", "input": map[string]any{"settings": map[string]any{"api_key": "synthetic-secret", "enabled": true}, "text": content}}}}})
	c, u := fixture(t, "claude-code", append(raw, '\n'))
	batch, err := prepare(context.Background(), c, u, allow)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range batch.observations {
		for _, f := range o.fields {
			if strings.Contains(f.text, secret) || strings.Contains(f.text, "synthetic-secret") {
				t.Fatal("local rules did not redact full native fields")
			}
			if !utf8.ValidString(f.text) {
				t.Fatal("bound cut UTF-8")
			}
		}
	}
	for _, profile := range []string{"", "push-metadata", "tenant", "LOCAL"} {
		if _, err := selectLocalPolicy(profile, false); err == nil {
			t.Fatal("unsupported profile accepted")
		}
	}
	if _, err := selectLocalPolicy("local", true); err == nil {
		t.Fatal("tenant overlay silently ignored")
	}
	c.policy = localPolicy{}
	b, err := prepare(context.Background(), c, u, allow)
	requireHeld(t, b, err, "unsupported_policy")
}

func TestUnsupportedAndMalformedDoNotReturnPartialText(t *testing.T) {
	good := `{"type":"user","message":{"content":"already prepared synthetic text"}}` + "\n"
	for _, tc := range []struct{ name, record, code string }{
		{"unknown", `{"type":"progress"}`, "unsupported_native_record"},
		{"duplicate", `{"type":"user","type":"assistant"}`, "invalid_json"},
		{"escapedduplicate", `{"type":"user","ty\u0070e":"assistant"}`, "invalid_json"},
		{"trailing", `{} {}`, "invalid_json"},
		{"surrogate", `{"type":"user","message":{"content":"\ud800"}}`, "invalid_json"},
		{"badshape", `{"type":"user","message":{"content":null}}`, "native_shape"},
		{"image", `{"type":"user","message":{"content":[{"type":"image","source":"synthetic"}]}}`, "unsupported_content"},
		{"unsafeid", `{"type":"assistant","message":{"id":"bad id","content":[]}}`, "unsafe_native_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, u := fixture(t, "claude-code", []byte(good+tc.record+"\n"))
			b, err := prepare(context.Background(), c, u, allow)
			requireHeld(t, b, err, tc.code)
		})
	}
	c, u := fixture(t, "claude-code", []byte(good+`{"type":"user","message":{"content":"unfinished"}}`))
	b, err := prepare(context.Background(), c, u, allow)
	requireHeld(t, b, err, "partial_line")
	for _, name := range []string{"exec", "functions.exec", "functions__exec"} {
		raw, _ := json.Marshal(map[string]any{"type": "response_item", "payload": map[string]any{"type": "function_call", "name": name, "call_id": "c", "arguments": "{}"}})
		c, u := fixture(t, "codex", append(raw, '\n'))
		b, err := prepare(context.Background(), c, u, allow)
		requireHeld(t, b, err, "unsupported_nested_exec")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b, err = prepare(ctx, c, u, allow)
	requireHeld(t, b, err, "cancelled")
}

func TestStrictJSONAndBounds(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `[`, "\xff", `"\udc00"`, `"\ud800x"`, strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)} {
		if strictJSON([]byte(raw)) == nil {
			t.Fatal("invalid/ambiguous JSON accepted")
		}
	}
	for _, raw := range []string{`{"a":"\\ud800","b":"\ud83d\ude00"}`, `{"n":9007199254740993}`, `[true,false,null]`} {
		if err := strictJSON([]byte(raw)); err != nil {
			t.Fatal("valid native JSON rejected", err)
		}
	}
	s := strings.Repeat("😀", 20<<10)
	out, truncated := bound(s, maxText)
	if !truncated || len(out) > maxText || !utf8.ValidString(out) || !strings.Contains(out, "[...elided...]") {
		t.Fatal("invalid UTF-8 head/tail bound")
	}
}
