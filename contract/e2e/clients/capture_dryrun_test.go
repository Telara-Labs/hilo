//go:build e2e && darwin

package clients_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/capture"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// This deliberately bypasses absent daemon ingress in a separate fixture store.
// It verifies the real supported decoders, pipeline and SQLite assertion helper.
// It does not establish hook-driven capture or installed native custody.
func TestCaptureDryRun(t *testing.T) {
	for _, client := range []string{"claude", "codex"} {
		t.Run(client, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			root := canonicalTemp(t)
			sourceRoot := filepath.Join(root, "source")
			data := filepath.Join(root, "data")
			if err := os.Mkdir(sourceRoot, 0700); err != nil {
				t.Fatal(err)
			}
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(key)
			machine := "01990000-0000-4000-8000-000000000002"
			native := "01990000-0000-4000-8000-000000000001"
			owner := sig.KeyID(pub)
			st, err := store.Open(ctx, store.Options{Dir: data, PinnedGenesisID: owner, LocalMachineID: machine})
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			genesis, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Genesis: owner, Subject: sig.KeyRefOf(pub, record.RoleDevice, machine)}, pub, machine, 1, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = st.Append(ctx, store.SignedRecord{HeaderJCS: genesis.Rec.HeaderJCS, BodyJCS: genesis.Rec.BodyJCS, Sigs: genesis.Sigs, AdvisoryID: genesis.Rec.ID}); err != nil {
				t.Fatal(err)
			}
			material, err := capture.PreloadKeys(make([]byte, 32), key)
			if err != nil {
				t.Fatal(err)
			}
			defer material.Clear()
			reader := client
			if client == "claude" {
				reader = "claude-code"
			}
			pipeline, err := capture.NewPipeline(ctx, st, capture.Config{Home: root, OwnerGenesis: owner, MachineID: machine, Roots: map[string]capture.Root{"synthetic": {Client: reader, AbsPath: sourceRoot}}, CaptureEnabled: true}, material)
			if err != nil {
				t.Fatal(err)
			}
			defer pipeline.Close()
			n := nonce()
			text := "CAPTURE_CANARY " + n + " " + canary
			var lines []any
			if client == "claude" {
				lines = []any{map[string]any{"type": "user", "sessionId": native, "cwd": root, "message": map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": text}}}}}
			} else {
				lines = []any{map[string]any{"type": "session_meta", "payload": map[string]any{"id": native, "cwd": root}}, map[string]any{"type": "response_item", "payload": map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": text}}}}}
			}
			var transcript []byte
			for _, line := range lines {
				b, _ := json.Marshal(line)
				transcript = append(append(transcript, b...), '\n')
			}
			rel := native + ".jsonl"
			path := filepath.Join(sourceRoot, rel)
			if err = privateWrite(path, transcript); err != nil {
				t.Fatal(err)
			}
			// The actual opener checks both mtime and ctime. A fixture must meet
			// the same two-second quiet period as a native transcript.
			time.Sleep(2100 * time.Millisecond)
			result, err := pipeline.Capture(ctx, capture.Unit{RootID: "synthetic", RelativePath: rel})
			if err != nil || result.Status != "committed" {
				t.Fatalf("real capture failed %s %v", result.Status, err)
			}
			ids, err := captured(ctx, data, client, native, n)
			if err != nil || len(ids) == 0 {
				t.Fatal("session/redaction assertion failed", err)
			}
			if _, err = captured(ctx, data, client, "wrong_native_session", n); err == nil {
				t.Fatal("accepted different native session")
			}
			if _, err = captured(ctx, data, client, native, "wrong_nonce"); err == nil {
				t.Fatal("accepted different capture nonce")
			}
			if _, err = captured(ctx, data, "cursor", native, n); err == nil {
				t.Fatal("accepted different client")
			}
		})
	}
}
