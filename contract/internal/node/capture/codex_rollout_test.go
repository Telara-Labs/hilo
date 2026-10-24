//go:build linux || darwin

package capture

import (
	"context"
	"strings"
	"testing"
)

func TestCodexRealRolloutShape(t *testing.T) {
	c, u := fixture(t, "codex", readFixture(t, "codex-0.161.0"))
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
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Kind]++
		if e.Prov != "transcript" || e.Call != nil || e.Result != nil {
			t.Fatal("bookkeeping gained execution authority", e)
		}
	}
	if counts["session_meta"] != 2 || counts["injected_context"] != 5 || counts["user_prompt"] != 2 || counts["assistant_text"] != 1 || len(events) != 10 {
		t.Fatal("messages lost, duplicated or promoted", counts)
	}
}

func TestCodexUnknownRecordsIgnoredButKnownShapesFailClosed(t *testing.T) {
	for _, raw := range []string{
		`{"type":"future_record","payload":null}`,
		`{"type":"world_state","payload":{"text":"ignored secret prose"}}`,
		`{"type":"event_msg","payload":{"type":"future_event","id":{"arbitrary":"ignored"}}}`,
		`{"type":"response_item","payload":{"type":"future_item","id":{"arbitrary":"ignored"}}}`,
	} {
		out, err := decodeCodex([]byte(raw), 1, syntheticSession)
		if err != nil || len(out) != 0 {
			t.Fatal("unknown record emitted observations", err)
		}
	}
	for _, raw := range []string{
		`{"type":"response_item","payload":{"type":"message","role":"user","content":null}}`,
		`{"type":"response_item","payload":{"type":"message","role":"future_role","content":[]}}`,
		`{"type":"response_item","payload":{"type":"function_call_output","call_id":{},"output":"x"}}`,
		`{"type":"session_meta","payload":{"id":"11111111-1111-4111-8111-111111111111"}}`,
	} {
		if _, err := decodeCodex([]byte(raw), 1, syntheticSession); err == nil || strings.Contains(err.Error(), "future_role") {
			t.Fatal("known malformed shape accepted or leaked", err)
		}
	}
	// Unknown records still pass the same strict bounded JSON validation.
	c, u := fixture(t, "codex", []byte(`{"type":"future","payload":{"secret":1,"secret":2}}`+"\n"))
	batch, err := prepare(context.Background(), c, u, allow)
	requireHeld(t, batch, err, "invalid_json")
}
