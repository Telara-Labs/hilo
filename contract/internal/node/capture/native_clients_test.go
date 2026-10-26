//go:build linux || darwin

package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

func TestCursorPiRealStoreFixtures(t *testing.T) {
	for _, tc := range []struct{ client, file string }{{"cursor-agent", "cursor-agent-2026.10.22.jsonl"}, {"pi", "pi-1.1.0.jsonl"}} {
		t.Run(tc.client, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			f := runtimeWorldClient(t, data, tc.client)
			if _, ok := any(f.s).(SignalStore); !ok {
				t.Skip("UNVERIFIED: store signal-receipt API and Cursor/Pi reader allowlist await store owner")
			}
			quietSource()
			first := requireCaptured(t, f)
			records, events := runtimeSnapshot(t, f.s)
			if len(events) == 0 {
				t.Fatal("no captured events")
			}
			var raw bytes.Buffer
			calls, results, contextSeen := 0, 0, false
			for _, r := range records {
				raw.Write(r.BodyJCS)
			}
			for _, secret := range []string{"cursor-synthetic-secret", "cursor-synthetic-token", "pi-synthetic-secret", "pi-synthetic-token"} {
				if bytes.Contains(raw.Bytes(), []byte(secret)) {
					t.Fatal("secret retained")
				}
			}
			for _, e := range events {
				if e.Call != nil {
					calls++
				}
				if e.Result != nil {
					results++
					if e.Result.Outcome != "unknown" || e.Result.CallEventID == "" {
						t.Fatal("result incorrectly attributed")
					}
				}
				if e.Kind == "injected_context" {
					contextSeen = true
				}
				if e.Prov != "transcript" {
					t.Fatal("wrong provenance")
				}
			}
			if !contextSeen || calls == 0 {
				t.Fatal("missing message/tool observations")
			}
			if tc.client == "pi" && results != 1 {
				t.Fatal("Pi result absent")
			}
			if tc.client == "cursor-agent" && (calls != 2 || results != 0) {
				t.Fatal("Cursor invented results or lost calls")
			}
			again, err := f.p.Capture(context.Background(), f.unit)
			if err != nil || again.Status != "no_change" || !reflect.DeepEqual(first.CommittedRecordIDs, again.CommittedRecordIDs) {
				t.Fatal("retry not idempotent", again, err)
			}
		})
	}
}

func TestCursorPiDecoderRefusals(t *testing.T) {
	cases := []struct{ client, input string }{
		{"cursor-agent", `{"role":"system","message":{"content":[]}}`},
		{"cursor-agent", `{"role":"user","message":{"content":[{"type":"tool_use","name":"read","input":{}}]}}`},
		{"cursor-agent", `{"type":"turn_ended","status":"forged"}`},
		{"cursor-agent", `{"role":"assistant","message":{"content":[{"type":"image","data":"omitted"}]}}`},
		{"pi", `{"type":"session","version":2,"id":"` + syntheticSession + `"}`},
		{"pi", `{"type":"session","version":3,"id":"11111111-1111-4111-8111-111111111111"}`},
		{"pi", `{"type":"message","id":"entry","parentId":null,"message":{"role":"assistant","content":[{"type":"unknown"}]}}`},
		{"pi", `{"type":"message","id":"entry","parentId":null,"message":{"role":"user","content":[{"type":"toolCall","id":"call","name":"read","arguments":{}}]}}`},
	}
	for i, tc := range cases {
		var err error
		if tc.client == "pi" {
			_, err = decodePi([]byte(tc.input), 1, syntheticSession)
		} else {
			_, err = decodeCursor([]byte(tc.input), 1)
		}
		if err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

func TestCursorPiRedactBeforeTruncateAndBounds(t *testing.T) {
	for _, client := range []string{"cursor-agent", "pi"} {
		t.Run(client, func(t *testing.T) {
			text := strings.Repeat("x", maxText+8) + " Authorization: Bearer synthetic-end-token"
			var msg any = map[string]any{"role": "assistant", "message": map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}}
			if client == "pi" {
				msg = map[string]any{"type": "message", "id": "00000001", "parentId": nil, "message": map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "text", "text": text}}}}
			}
			b, _ := json.Marshal(msg)
			var observations []preparedObservation
			var err error
			if client == "pi" {
				observations, err = decodePi(b, 2, syntheticSession)
			} else {
				observations, err = decodeCursor(b, 1)
			}
			if err != nil {
				t.Fatal(err)
			}
			p, _ := selectLocalPolicy("local", false)
			for _, o := range observations {
				o, err = redactObservation(o, p)
				if err != nil {
					t.Fatal(err)
				}
				for _, field := range o.fields {
					if strings.Contains(field.text, "synthetic-end-token") {
						t.Fatal("secret retained")
					}
					if field.name == "text" && (!field.truncated || len(field.text) > maxText || field.fullRedactedBytes <= maxText) {
						t.Fatal("field limit not applied")
					}
				}
			}
			frame := append(bytes.Repeat([]byte{' '}, maxFrame), '\n')
			if err := frameReader(context.Background(), bytes.NewReader(frame), func(int, []byte) error { return nil }, maxUnit, maxFrame, &frameMemory{}); Code(err) != "frame_limit" {
				t.Fatal("frame not bounded", err)
			}
		})
	}
}

func TestPiTimestampFilenameIdentity(t *testing.T) {
	f := runtimeWorldClient(t, []byte("{}\n"), "pi")
	c := preparationConfig{root: f.c.Roots["fixture"].AbsPath, home: f.c.Home, owner: f.c.OwnerGenesis, machine: f.c.MachineID}
	u := unitLocator{client: "pi", relative: "2026-10-24T12-00-00-000Z_" + syntheticSession + ".jsonl", source: strings.Repeat("0", 64), session: "sk1:" + strings.Repeat("0", 64)}
	if id, err := resolve(c, u); err != nil || id != syntheticSession {
		t.Fatal(id, err)
	}
	if !record.IsUUID(syntheticSession) {
		t.Fatal("bad synthetic session")
	}
}

func TestCursorPiPreparedFixtures(t *testing.T) {
	for _, tc := range []struct{ client, file string }{{"cursor-agent", "cursor-agent-2026.10.22.jsonl"}, {"pi", "pi-1.1.0.jsonl"}} {
		t.Run(tc.client, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			c, u := fixture(t, tc.client, raw)
			bindIdentity(t, c, &u, syntheticSession)
			batch, err := prepare(context.Background(), c, u, allow)
			if err != nil {
				t.Fatal(err)
			}
			rs, err := checkedRuleset()
			if err != nil {
				t.Fatal(err)
			}
			events, err := normalize(batch, rs)
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(events)
			for _, secret := range []string{"cursor-synthetic-secret", "cursor-synthetic-token", "pi-synthetic-secret", "pi-synthetic-token"} {
				if bytes.Contains(encoded, []byte(secret)) {
					t.Fatal("secret retained")
				}
			}
			calls, results := 0, 0
			for _, e := range events {
				if e.Call != nil {
					calls++
				}
				if e.Result != nil {
					results++
					if e.Result.Outcome != "unknown" || e.Result.CallEventID == "" {
						t.Fatal("result provenance fabricated")
					}
				}
			}
			if calls == 0 || tc.client == "pi" && results != 1 || tc.client == "cursor-agent" && (calls != 2 || results != 0) {
				t.Fatal("missing or invented event", calls, results)
			}
		})
	}
}

func TestPiTreeValidationAndUnknownBranches(t *testing.T) {
	header := `{"type":"session","version":3,"id":"` + syntheticSession + `","cwd":"/synthetic"}` + "\n"
	entry := func(id, parent, role string) string {
		p := `null`
		if parent != "" {
			p = `"` + parent + `"`
		}
		return `{"type":"message","id":"` + id + `","parentId":` + p + `,"message":{"role":"` + role + `","content":"synthetic"}}` + "\n"
	}
	cases := []struct{ name, data, code string }{
		{"self-cycle", entry("one", "one", "user"), "cyclic_native_entries"},
		{"cycle", entry("one", "two", "user") + entry("two", "one", "user"), "cyclic_native_entries"},
		{"duplicate", entry("one", "", "user") + entry("one", "", "user"), "duplicate_native_entry"},
		{"missing-parent", entry("one", "absent", "user"), ""},
		{"multiple-roots", entry("one", "", "user") + entry("two", "", "user"), ""},
		{"unknown-role", entry("one", "", "augmentedRole"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, u := fixture(t, "pi", []byte(header+tc.data))
			batch, err := prepare(context.Background(), c, u, allow)
			if Code(err) != tc.code {
				t.Fatal("wrong tree verdict", err)
			}
			if err != nil {
				return
			}
			unknown, gap := false, false
			for _, o := range batch.observations {
				for _, f := range o.fields {
					unknown = unknown || f.name == "branch_state" && f.text == "unknown"
					gap = gap || f.name == "parent_chain" && f.text == "incomplete"
				}
			}
			if !unknown || tc.name == "missing-parent" && !gap {
				t.Fatal("branch state not conservative")
			}
			if tc.name == "unknown-role" {
				for _, o := range batch.observations {
					if o.kind == "user_text" || o.kind == "assistant_text" || o.kind == "tool_result" {
						t.Fatal("unknown role promoted")
					}
				}
			}
		})
	}
}

func TestPiRedactedReasoningNeverRetainsOpaqueSignature(t *testing.T) {
	input := `{"type":"message","id":"00000001","parentId":null,"message":{"role":"assistant","content":[{"type":"thinking","redacted":true,"thinkingSignature":"opaque-must-not-retain"}]}}`
	observations, err := decodePi([]byte(input), 2, syntheticSession)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 2 || observations[1].kind != "native_meta_text" {
		t.Fatal("redacted reasoning not conservative")
	}
	for _, o := range observations {
		for _, f := range o.fields {
			if strings.Contains(f.text, "opaque-must-not-retain") {
				t.Fatal("opaque signature retained")
			}
		}
	}
}

func TestPiCompositeCallIdentity(t *testing.T) {
	raw := readFixture(t, "pi-1.1.0")
	composite := "call_syntheticA|fc_syntheticB"
	raw = bytes.ReplaceAll(raw, []byte("call_synthetic"), []byte(composite))
	f := runtimeWorldClient(t, raw, "pi")
	quietSource()
	requireCaptured(t, f)
	_, events := runtimeSnapshot(t, f.s)
	calls := map[string]bool{}
	results := 0
	exact := false
	for _, e := range events {
		if e.Call != nil {
			calls[e.ID] = true
			if e.Src != nil && e.Src.Record == composite {
				exact = true
			}
		}
	}
	for _, e := range events {
		if e.Result != nil {
			results++
			if !calls[e.Result.CallEventID] {
				t.Fatal("lost native correlation")
			}
		}
	}
	if !exact || results != 1 {
		t.Fatal("native identity not preserved", exact, results)
	}
	for _, good := range []string{"call_synthetic", composite} {
		if !piCallIdentifier(good) {
			t.Fatal("refused native ID")
		}
	}
	for _, bad := range []string{"call_a|fc_b|fc_c", "|fc_b", "call_a|", "call_a|other_b", "call_a|fc_../path", "call_a|fc_b\n", "call_a|fc_b\x00", "call_a|fc_" + strings.Repeat("x", 201), "call_a|fc_AKIAABCDEFGHIJKLMNOP"} {
		if piCallIdentifier(bad) {
			t.Fatal("accepted unsafe composite ID")
		}
	}
	o := preparedObservation{kind: "tool_call", callID: composite, position: position{1, 0, 0}}
	for _, client := range []string{"codex", "claude-code", "cursor-agent", ""} {
		if _, _, err := sourceAnchorForClient(o, "synthetic/path", client); Code(err) != "unsafe_native_id" {
			t.Fatal("composite escaped Pi", client, err)
		}
	}
	if _, _, err := sourceAnchorForClient(o, "synthetic/path", "pi"); err != nil {
		t.Fatal(err)
	}
	o.kind = "assistant_text"
	o.nativeID = composite
	if _, _, err := sourceAnchorForClient(o, "synthetic/path", "pi"); Code(err) != "unsafe_native_id" {
		t.Fatal("noncall composite accepted", err)
	}
}
