//go:build linux || darwin

package capture

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

func TestCodexResultObservationIdentity(t *testing.T) {
	raw := readFixture(t, "codex")
	for _, nativeItems := range []bool{false, true} {
		t.Run(map[bool]string{false: "positional", true: "native-items"}[nativeItems], func(t *testing.T) {
			input := string(raw)
			if nativeItems {
				input = strings.Replace(input, `"type":"function_call_output",`, `"type":"function_call_output","id":"output_item",`, 1)
				input = strings.Replace(input, `"type":"mcp_tool_call_end",`, `"type":"mcp_tool_call_end","id":"end_item",`, 1)
			}
			c, u := fixture(t, "codex", []byte(input))
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
			if len(events) != 7 {
				t.Fatalf("observations lost: %d", len(events))
			}
			call := events[3]
			if call.Call == nil {
				t.Fatal("call lost")
			}
			for i, excerpt := range []string{"Synthetic guide contents.", "Native success flag remains an untrusted observation."} {
				e := events[4+i]
				if e.Result == nil || e.Result.CallEventID != call.ID || e.Result.Outcome != "unknown" || e.Result.Excerpt != excerpt || e.Src.Line != int64(4+i) {
					t.Fatal("result observation or correlation lost", e)
				}
				want := record.Anchor{Path: batch.homeRelativeUnit, Line: int64(4 + i), Block: 1}
				if nativeItems {
					want = record.Anchor{NativeItemID: []string{"output_item", "end_item"}[i], Part: 4096}
				}
				id, err := record.EventID(batch.occurrence.session, "tool_result", want)
				if err != nil || e.ID != id {
					t.Fatal("call correlation replaced result occurrence", e.ID, id, err)
				}
			}
			if events[4].ID == events[5].ID {
				t.Fatal("separate result observations collapsed")
			}
			// Content changes create revisions of these occurrences, never new IDs.
			batch.observations[4].fields[0].text = "changed result"
			again, err := normalize(batch, rs)
			if err != nil || again[4].ID != events[4].ID || again[5].ID != events[5].ID {
				t.Fatal("content became identity", err)
			}
			if nativeItems {
				batch.observations[5].nativeID = batch.observations[4].nativeID
				if _, err = normalize(batch, rs); Code(err) != "ambiguous_native_occurrence" {
					t.Fatal("duplicate native result ID accepted", err)
				}
			}
		})
	}
}

func TestCodexResultsRealStoreNoChange(t *testing.T) {
	f := runtimeWorldClient(t, readFixture(t, "codex"), "codex")
	quietSource()
	first := requireCaptured(t, f)
	_, events := runtimeSnapshot(t, f.s)
	calls, results := 0, 0
	for _, e := range events {
		if e.Call != nil {
			calls++
		}
		if e.Result != nil {
			results++
			if e.Result.CallEventID == "" || e.Result.Outcome != "unknown" {
				t.Fatal("result authority invented or link lost")
			}
		}
	}
	if calls != 1 || results != 2 {
		t.Fatal("observations missing", calls, results)
	}
	again, err := f.p.Capture(context.Background(), f.unit)
	if err != nil || again.Status != "no_change" || !reflect.DeepEqual(first.CommittedRecordIDs, again.CommittedRecordIDs) {
		t.Fatal("unchanged reread resealed", again, err)
	}
}

// Historical result anchors used call_id. A reader correction must not turn
// the same source into new occurrences that evade retained history or erasure.
func TestCodexLegacyResultAnchorsRefuseRecapture(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(string(readFixture(t, "codex"))), "\n")
	// The old reader could admit one result observation, but not both.
	lines = append(lines[:4], lines[5:]...)
	f := runtimeWorldClient(t, []byte(strings.Join(lines, "\n")+"\n"), "codex")
	quietSource()
	first, err := f.p.capture(context.Background(), f.unit, func(ctx context.Context, c preparationConfig, u unitLocator, gate preOpenGate) (preparedBatch, *openedUnitHandle, error) {
		batch, h, err := prepareHeld(ctx, c, u, gate)
		if err == nil {
			for i := range batch.observations {
				if batch.observations[i].kind == "tool_result" {
					batch.observations[i].nativeID = batch.observations[i].callID
				}
			}
		}
		return batch, h, err
	})
	if err != nil || first.Status != "committed" {
		t.Fatal("legacy-anchor fixture not admitted", first, err)
	}
	before, _ := runtimeSnapshot(t, f.s)
	next, err := f.p.Capture(context.Background(), f.unit)
	if Code(err) != "producer_refused" || next.Status != "held" || len(next.CommittedRecordIDs) != 0 {
		t.Fatal("anchor correction silently recaptured historical occurrences", next, err)
	}
	after, _ := runtimeSnapshot(t, f.s)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("refused anchor correction changed retained records")
	}
}
