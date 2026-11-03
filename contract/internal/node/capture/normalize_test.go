//go:build linux || darwin

package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"golang.org/x/sys/unix"
)

func TestNativeAndPositionalAnchorInjectivity(t *testing.T) {
	for block := int64(1); block <= 4096; block++ {
		for part := int64(0); part < 4096; part++ {
			encoded := block*4096 + part
			if encoded/4096 != block || encoded%4096 != part {
				t.Fatal("noninjective part encoding")
			}
		}
	}
	seen := map[int64]bool{}
	for _, block := range []int{-1, 0, 1, 4095} {
		for _, part := range []int{0, 1, 4095} {
			o := preparedObservation{kind: "assistant_text", nativeID: "msg_native", position: position{1, block, part}}
			if block == -1 {
				if part != 0 {
					continue
				}
				o.kind = "metadata"
				o.position.inner = -1
			}
			a, _, err := sourceAnchor(o, "synthetic/file.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			if a.Path != "" || a.Line != 0 || a.Block != 0 || a.Inner != 0 || a.NativeItemID != "msg_native" || seen[a.Part] {
				t.Fatal("native form mixed/collided", a)
			}
			seen[a.Part] = true
			o.nativeID = ""
			a, _, err = sourceAnchor(o, "synthetic/file.jsonl")
			if err != nil || a.NativeItemID != "" || a.Path != "synthetic/file.jsonl" || a.Line != 1 || a.Block != int64(block+1) || a.Inner != 0 {
				t.Fatal("positional form invalid", a, err)
			}
		}
	}
	for _, position := range []position{{0, 0, 0}, {1, -2, 0}, {1, 4096, 0}, {1, 0, 4096}, {1, 0, -1}} {
		if _, _, err := sourceAnchor(preparedObservation{kind: "assistant_text", position: position}, "p"); err == nil {
			t.Fatal("invalid source ordinal accepted")
		}
	}
	rs, err := checkedRuleset()
	if err != nil {
		t.Fatal(err)
	}
	batch := preparedBatch{occurrence: sourceOccurrence{session: "sk1:" + strings.Repeat("a", 64)}, homeRelativeUnit: "synthetic/file.jsonl", observations: []preparedObservation{{kind: "assistant_text", nativeID: "repeated", position: position{1, 0, 0}, fields: []field{{name: "text", text: "one", fullRedactedBytes: 3}}}, {kind: "assistant_text", nativeID: "repeated", position: position{2, 0, 0}, fields: []field{{name: "text", text: "two", fullRedactedBytes: 3}}}}}
	if _, err = normalize(batch, rs); Code(err) != "ambiguous_native_occurrence" {
		t.Fatal("duplicate native ID guessed into revision", err)
	}
	batch.observations = batch.observations[:1]
	first, err := normalize(batch, rs)
	if err != nil {
		t.Fatal(err)
	}
	batch.observations[0].fields[0].text = "new"
	second, err := normalize(batch, rs)
	if err != nil || first[0].ID != second[0].ID {
		t.Fatal("same source anchor changed across rereads")
	}
}

func TestPrimitiveArgumentKindsAndBoundedTextAreProtectedPayload(t *testing.T) {
	rs, err := checkedRuleset()
	if err != nil {
		t.Fatal(err)
	}
	var first []byte
	for _, value := range []any{"1", json.Number("1"), "true", true, "null", nil, `{"n":1}`, map[string]any{"n": 1}} {
		raw, _ := json.Marshal(map[string]any{"type": "assistant", "message": map[string]any{"content": []any{map[string]any{"type": "tool_use", "id": "call_a", "name": "fixture", "input": map[string]any{"value": value}}}}})
		c, u := fixture(t, "claude-code", append(raw, '\n'))
		batch, err := prepare(context.Background(), c, u, allow)
		if err != nil {
			t.Fatal(err)
		}
		events, err := normalize(batch, rs)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 || events[0].Call == nil || events[0].Meta["capture_arg_types_v1"] == "" {
			t.Fatal("type metadata missing")
		}
		payload, err := record.EventPayload(events[0])
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(first, payload) {
			t.Fatal("distinct native kinds collapsed into equal payload")
		}
		first = payload
	}
	text := strings.Repeat("x", maxText+400)
	raw, _ := json.Marshal(map[string]any{"type": "user", "message": map[string]any{"content": text}})
	c, u := fixture(t, "claude-code", append(raw, '\n'))
	batch, err := prepare(context.Background(), c, u, allow)
	if err != nil {
		t.Fatal(err)
	}
	events, err := normalize(batch, rs)
	if err != nil {
		t.Fatal(err)
	}
	body := events[0].Text
	if body == nil || body.Bytes != len(text) || !body.Truncated || body.Digest != "" || len(body.Body) > maxText {
		t.Fatal("full redacted byte count/truncation semantics lost")
	}
}

func TestRetainedDirectoryBindingsDetectRootAndAncestorReplacement(t *testing.T) {
	for _, target := range []string{"root", "ancestor", "child"} {
		t.Run(target, func(t *testing.T) {
			c, u := fixture(t, "claude-code", readFixture(t, "claude"))
			base := c.root
			c.root = filepath.Join(base, "ancestor", "root")
			c.home = base
			if err := os.MkdirAll(c.root, 0700); err != nil {
				t.Fatal(err)
			}
			if target == "child" {
				if err := os.Mkdir(filepath.Join(c.root, "child"), 0700); err != nil {
					t.Fatal(err)
				}
				u.relative = filepath.Join("child", u.relative)
			}
			if err := os.WriteFile(filepath.Join(c.root, u.relative), readFixture(t, "claude"), 0600); err != nil {
				t.Fatal(err)
			}
			bindIdentity(t, c, &u, syntheticSession)
			_, h, err := prepareHeld(context.Background(), c, u, allow)
			if err != nil {
				t.Fatal(err)
			}
			defer h.close()
			path := c.root
			if target == "ancestor" {
				path = filepath.Dir(c.root)
			}
			if target == "child" {
				path = filepath.Join(c.root, "child")
			}
			if err = os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			if err = os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if h.stable() {
				t.Fatal("held source accepted renamed ancestor binding")
			}
			fds := append([]int(nil), h.directories...)
			h.close()
			h.close()
			for _, fd := range fds {
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
					t.Fatal("owned directory descriptor leaked")
				}
			}
		})
	}
	c, u := fixture(t, "claude-code", readFixture(t, "claude"))
	_, h, err := prepareHeld(context.Background(), c, u, allow)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	if err = os.WriteFile(filepath.Join(c.root, "unrelated-file"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if !h.stable() {
		t.Fatal("unrelated directory content invalidated stable source")
	}
}
