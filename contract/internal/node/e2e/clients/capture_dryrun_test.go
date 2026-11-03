//go:build e2e && darwin

package clients_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/capture"
	"github.com/Telara-Labs/hilo/contract/internal/node/clients"
	"github.com/Telara-Labs/hilo/contract/internal/node/store"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

// This separate fixture store checks all four real transcript decoders, the
// pipeline and SQLite assertion helper independently of installed authority.
// It establishes synthetic hook-driven capture, not installed native custody.
func TestCaptureDryRun(t *testing.T) {
	for _, client := range []string{"claude", "codex", "cursor", "pi"} {
		t.Run(client, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			root := canonicalTemp(t)
			cfg := installedConfig{Root: root, Home: filepath.Join(root, "home"), Data: filepath.Join(root, "data"), Client: client}
			cfg.ClientConfig = filepath.Join(cfg.Home, specFor(client).configRelative)
			location, err := clients.Locations(clients.Options{Client: clients.Client(client), Home: cfg.Home, ConfigRoot: cfg.ClientConfig})
			if err != nil {
				t.Fatal(err)
			}
			sourceRoot := location.Transcripts
			data := cfg.Data
			if err := os.MkdirAll(sourceRoot, 0700); err != nil {
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
			reader := captureClient(client)
			pipeline, err := capture.NewPipeline(ctx, st, capture.Config{Home: cfg.Home, OwnerGenesis: owner, MachineID: machine, Roots: map[string]capture.Root{client: {Client: reader, AbsPath: sourceRoot}}, CaptureEnabled: true}, material)
			if err != nil {
				t.Fatal(err)
			}
			defer pipeline.Close()
			n := nonce()
			path := writeSyntheticTranscript(t, cfg, native, n)
			// The actual opener checks both mtime and ctime. A fixture must meet
			// the same two-second quiet period as a native transcript.
			time.Sleep(2100 * time.Millisecond)
			hook := clients.RunHook(ctx, clients.Options{Client: clients.Client(client), Home: cfg.Home, ConfigRoot: cfg.ClientConfig, StateDir: data}, bytes.NewReader(syntheticHook(cfg, native, path)))
			if !hook.Published || !hook.TranscriptHintVerified {
				t.Fatal("fixture terminal hook not verified", hook)
			}
			if err = captureACK(ctx, data, client, 1); err == nil {
				t.Fatal("pending signal accepted as ACKed")
			}
			collector, err := capture.NewCollector(pipeline, data)
			if err != nil {
				t.Fatal(err)
			}
			defer collector.Close()
			if err = collector.Drain(ctx, "synthetic-fixture-credential"); err != nil {
				t.Fatal("real collector drain failed", err)
			}
			if err = captureACK(ctx, data, client, 1); err != nil {
				t.Fatal("durable capture ACK missing", err)
			}
			if err = captureACK(ctx, data, client, 2); err == nil {
				t.Fatal("insufficient receipts accepted")
			}
			if err = captureACK(ctx, data, "wrong_client", 1); err == nil {
				t.Fatal("missing spool accepted")
			}
			if err = collector.Drain(ctx, "synthetic-fixture-credential"); err != nil {
				t.Fatal("empty drain failed", err)
			}
			if collector.Stats().Done != 1 {
				t.Fatal("wrong collector ACK count")
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
			if _, err = captured(ctx, data, "wrong_client", native, n); err == nil {
				t.Fatal("accepted different client")
			}
		})
	}
}

func captureClient(client string) string {
	switch client {
	case "claude":
		return "claude-code"
	case "cursor":
		return "cursor-agent"
	default:
		return client
	}
}

func syntheticRelativePath(client, native string) string {
	switch client {
	case "codex":
		return "rollout-2026-10-24-" + native + ".jsonl"
	case "cursor":
		return filepath.Join("synthetic-project", "agent-transcripts", native, native+".jsonl")
	case "pi":
		return "2026-10-24T12-00-00-000Z_" + native + ".jsonl"
	default:
		return filepath.Join("synthetic-project", native+".jsonl")
	}
}

func syntheticTranscript(client, native, cwd, n string) []byte {
	text := "CAPTURE_CANARY " + n + " " + canary
	var lines []any
	switch client {
	case "claude":
		lines = []any{map[string]any{"type": "user", "sessionId": native, "cwd": cwd, "message": map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": text}}}}}
	case "codex":
		lines = []any{map[string]any{"type": "session_meta", "payload": map[string]any{"id": native, "cwd": cwd}}, map[string]any{"type": "response_item", "payload": map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": text}}}}}
	case "cursor":
		lines = []any{map[string]any{"role": "user", "message": map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}}}
	case "pi":
		lines = []any{map[string]any{"type": "session", "version": 3, "id": native, "cwd": cwd, "timestamp": "2026-10-24T12:00:00.000Z"}, map[string]any{"type": "message", "id": "00000001", "parentId": nil, "timestamp": "2026-10-24T12:00:01.000Z", "message": map[string]any{"role": "user", "content": text, "timestamp": 1792843201000}}}
	}
	var transcript []byte
	for _, line := range lines {
		b, _ := json.Marshal(line)
		transcript = append(append(transcript, b...), '\n')
	}
	return transcript
}

func writeSyntheticTranscript(t *testing.T, cfg installedConfig, native, n string) string {
	t.Helper()
	location, err := clients.Locations(clients.Options{Client: clients.Client(cfg.Client), Home: cfg.Home, ConfigRoot: cfg.ClientConfig})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(location.Transcripts, syntheticRelativePath(cfg.Client, native))
	if err = privateWrite(path, syntheticTranscript(cfg.Client, native, filepath.Join(cfg.Home, "work-a"), n)); err != nil {
		t.Fatal(err)
	}
	return path
}

func syntheticHook(cfg installedConfig, native, path string) []byte {
	input := map[string]any{"hook_event_name": terminalEvent(cfg.Client), "session_id": native, "transcript_path": path, "cwd": filepath.Join(cfg.Home, "work-a")}
	if cfg.Client == "cursor" {
		delete(input, "session_id")
		input["conversation_id"] = native
		input["generation_id"] = "synthetic-generation"
	}
	b, _ := json.Marshal(input)
	return b
}
