//go:build linux || darwin

package capture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

func TestPrivacyRefusalClassification(t *testing.T) {
	for _, code := range []string{"privacy_hold_required", "bulk_confirmation_required"} {
		r, err := refused(storeFailure(&store.Error{Code: code, OwnerBlocked: true}))
		if Code(err) != code || r.Status != "owner_blocked" || !r.OwnerBlocked || len(r.CommittedRecordIDs) != 0 || r.ProgressVersion != 0 {
			t.Fatal("privacy refusal lost committed-barrier classification", code, r, err)
		}
	}
	r, err := refused(storeFailure(&store.Error{Code: "outcome_unknown"}))
	if r.Status != "outcome_unknown" || r.OwnerBlocked || Code(err) != "outcome_unknown" {
		t.Fatal(r, err)
	}
}

// Synthetic runtime/storage component gate, not native client or whole-node conformance.
func TestRuntimeRedactionAndPhysicalErasureComponentBytes(t *testing.T) {
	for _, client := range []string{"claude-code", "codex"} {
		t.Run(client, func(t *testing.T) {
			token := "ghp_" + strings.Repeat("a", 36)
			opaque := "syntheticopaquecredentialc6b910d7"
			ignored := "ignorednativeparsercanary74e3d91a"
			retained := "managedruntimefixturecanary"
			long := retained + " " + strings.Repeat("bounded synthetic filler ", 3100) + " " + token
			args := map[string]any{"api_key": opaque, "nested": map[string]any{"text": long}}
			var native []map[string]any
			if client == "claude-code" {
				native = []map[string]any{{"type": "assistant", "ignored_native_field": ignored, "message": map[string]any{"id": "synthetic_msg", "content": []any{map[string]any{"type": "text", "text": long}, map[string]any{"type": "tool_use", "id": "synthetic_call", "name": "fixture_read", "input": args}}}}}
			} else {
				encoded, _ := json.Marshal(args)
				native = []map[string]any{{"type": "response_item", "ignored_native_field": ignored, "payload": map[string]any{"type": "message", "id": "synthetic_msg", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": long}}}}, {"type": "response_item", "payload": map[string]any{"type": "function_call", "id": "synthetic_tool", "call_id": "synthetic_call", "name": "fixture_read", "arguments": string(encoded)}}}
			}
			var raw bytes.Buffer
			for _, line := range native {
				b, e := json.Marshal(line)
				if e != nil {
					t.Fatal(e)
				}
				raw.Write(b)
				raw.WriteByte('\n')
			}
			if len(long) < 64*1024 {
				t.Fatal("fixture must exceed cap")
			}
			f := runtimeWorldClient(t, raw.Bytes(), client)
			nodeDir := filepath.Join(f.c.Home, "synthetic-node")
			if rel, _ := filepath.Rel(nodeDir, f.path); rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatal("source inside managed store")
			}
			quietSource()
			requireCaptured(t, f)
			rawHash := sha256.Sum256(raw.Bytes())
			forbidden := [][]byte{[]byte(token), []byte(opaque), []byte(ignored), rawHash[:], []byte(hex.EncodeToString(rawHash[:]))}
			for _, secret := range [][]byte{f.key, f.key.Seed(), bytes.Repeat([]byte{52}, 32)} {
				forbidden = append(forbidden, append([]byte(nil), secret...), []byte(hex.EncodeToString(secret)), []byte(base64.StdEncoding.EncodeToString(secret)), []byte(base64.RawURLEncoding.EncodeToString(secret)))
			}
			records, events := runtimeSnapshot(t, f.s)
			var chunks []string
			var erasedSeals [][]byte
			addSeal := func(salt string) {
				erasedSeals = append(erasedSeals, []byte(salt))
				b, e := base64.RawURLEncoding.DecodeString(salt)
				if e != nil {
					t.Fatal(e)
				}
				erasedSeals = append(erasedSeals, b)
			}
			textSeen, callSeen := false, false
			for _, e := range events {
				if e.Text != nil {
					if e.Text.Digest != "" || !e.Text.Truncated || e.Text.Bytes <= 64*1024 {
						t.Fatal("text metadata/digest", e.Text)
					}
					textSeen = true
				}
				if e.Call != nil {
					callSeen = true
				}
				addSeal(e.Salt)
				payload, e := record.EventPayload(e)
				if e != nil {
					t.Fatal(e)
				}
				h := sha256.Sum256(payload)
				forbidden = append(forbidden, h[:], []byte(hex.EncodeToString(h[:])))
			}
			if !textSeen || !callSeen {
				t.Fatal("did not admit text and call")
			}
			for id, r := range records {
				switch b := r.Body.(type) {
				case *record.ChunkBody:
					chunks = append(chunks, id)
					addSeal(b.Salt)
				case *record.SessionBody:
					addSeal(b.Salt)
				}
			}
			// Native metadata cannot certify complete fresh projection. The retained
			// redacted source remains available through the separately authorized S view.
			quoteCapturedChunks(t, f, chunks, retained)
			inspectManagedBytes(t, f, nodeDir, forbidden, retained, true)
			lid, _ := record.ControlLID(record.KindErasure, f.c.OwnerGenesis, strings.Repeat("c", 32))
			control, e := record.Build(record.Header{Type: record.KindErasure, LID: lid, Author: record.Author{KeyID: f.c.OwnerGenesis, MachineID: f.c.MachineID}, At: time.Now().UnixMilli(), Prov: record.ProvUser, Red: record.Redact{Profile: record.ProfileLocal}}, &record.ErasureBody{Selectors: record.Selectors{IDs: chunks}, Reason: "user_request"}, bytes.Repeat([]byte{52}, 32))
			if e != nil {
				t.Fatal(e)
			}
			signature, e := sig.SignRecord(f.key, control.ID)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = f.s.Append(context.Background(), store.SignedRecord{HeaderJCS: control.HeaderJCS, BodyJCS: control.BodyJCS, Sigs: []record.Signature{signature}, AdvisoryID: control.ID}); e != nil {
				t.Fatal(e)
			}
			scrub, e := f.s.Scrub(context.Background(), control.ID)
			if e != nil || scrub.State != "complete" {
				t.Fatal("scrub incomplete", scrub, e)
			}
			after := append(append([][]byte(nil), forbidden...), erasedSeals...)
			after = append(after, []byte(retained))
			inspectManagedBytes(t, f, nodeDir, after, retained, false)
			source, e := os.ReadFile(f.path)
			if e != nil || !bytes.Equal(source, raw.Bytes()) {
				t.Fatal("external raw fixture changed", e)
			}
		})
	}
}

func quoteCapturedChunks(t *testing.T, f *runtimeFixture, chunks []string, needle string) {
	t.Helper()
	ctx := context.Background()
	material, err := disclosure.PreloadRuntimeMaterial(bytes.Repeat([]byte{52}, 32), f.key)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	svc, err := disclosure.New(ctx, f.s, disclosure.Config{OwnerGenesis: f.c.OwnerGenesis, MachineID: f.c.MachineID, MaxReplyBytes: 16384}, material)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	admin, err := svc.Administration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := admin.Register(ctx, disclosure.RegisterClient{AdminOpID: "register-byte-fixture", ClientName: "Capture byte fixture", ReadGrant: disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := registered.Secret.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(token)
	client, err := svc.Authenticate(ctx, disclosure.CredentialProof{CredentialID: registered.CredentialID, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	scope, err := client.Resolve(ctx, disclosure.IdentityInput{ConversationHandle: "capture-byte-conversation"})
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, id := range chunks {
		raw, err := json.Marshal(map[string]any{"record_id": id})
		if err != nil {
			t.Fatal(err)
		}
		command, err := disclosure.DecodeCommand("local.lookup_record", raw)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := client.Execute(ctx, scope, disclosure.CallIdentity{SuppliedOpID: "quote-captured-" + id, JSONRPCID: json.RawMessage(`1`)}, command, disclosure.ByteBudget{MaxBytes: 16384})
		if err != nil {
			t.Fatal(err)
		}
		result, err := reply.Release(ctx)
		if err != nil || result.IsError || len(result.Content) != 1 || result.Content[0].Type != "text" {
			t.Fatal("authorized native quoted source unavailable", err)
		}
		seen = seen || strings.Contains(result.Content[0].Text, needle)
	}
	if !seen {
		t.Fatal("authorized quoted S view lost retained native text")
	}
}

func inspectManagedBytes(t *testing.T, f *runtimeFixture, dir string, forbidden [][]byte, ftsToken string, wantRetained bool) {
	t.Helper()
	check := func(where string, b []byte) {
		t.Helper()
		for i, needle := range forbidden {
			if len(needle) > 0 && bytes.Contains(b, needle) {
				t.Fatalf("forbidden byte vector %d in %s", i, where)
			}
		}
	}
	snap, e := f.s.Snapshot(context.Background(), store.ReadRequest{})
	if e != nil {
		t.Fatal(e)
	}
	retained := false
	for _, entry := range snap.Entries {
		check("snapshot header", entry.HeaderJCS)
		check("snapshot body", entry.BodyJCS)
		retained = retained || bytes.Contains(entry.BodyJCS, []byte(ftsToken))
	}
	if retained != wantRetained {
		t.Fatal("actual retained native body presence", retained, wantRetained)
	}
	var dbPath string
	files := 0
	e = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		files++
		check("managed file "+filepath.Base(path), b)
		if strings.HasSuffix(path, ".sqlite") {
			dbPath = path
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if files == 0 || dbPath == "" {
		t.Fatal("managed SQLite not inspected")
	}
	uri := (&url.URL{Scheme: "file", Path: dbPath}).String() + "?mode=ro"
	db, e := sql.Open("sqlite", uri)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, e := db.Query("SELECT name FROM sqlite_schema WHERE type='table'")
	if e != nil {
		t.Fatal(e)
	}
	var tables []string
	for rows.Next() {
		var name string
		if e = rows.Scan(&name); e != nil {
			t.Fatal(e)
		}
		tables = append(tables, name)
	}
	if e = rows.Err(); e != nil {
		t.Fatal(e)
	}
	rows.Close()
	for _, table := range tables {
		q := `SELECT * FROM "` + strings.ReplaceAll(table, `"`, `""`) + `"`
		rows, e = db.Query(q)
		if e != nil {
			t.Fatal(e)
		}
		cols, e := rows.Columns()
		if e != nil {
			t.Fatal(e)
		}
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		for rows.Next() {
			if e = rows.Scan(ptrs...); e != nil {
				t.Fatal(e)
			}
			for _, v := range values {
				switch b := v.(type) {
				case []byte:
					check("SQLite "+table, b)
				case string:
					check("SQLite "+table, []byte(b))
				}
			}
		}
		if e = rows.Err(); e != nil {
			t.Fatal(e)
		}
		rows.Close()
	}
	var hits int
	if e = db.QueryRow("SELECT count(*) FROM search WHERE search MATCH ?", ftsToken).Scan(&hits); e != nil {
		t.Fatal(e)
	}
	if hits != 0 {
		t.Fatal("uncertified native text entered fresh FTS", hits)
	}
}

func TestRuntimeSecondPreOpenOwnerBarrierInterleaving(t *testing.T) {
	f := runtimeWorld(t, sourceMessages(t, 1, -1, ""))
	calls := 0
	result, err := f.p.capture(context.Background(), f.unit, func(ctx context.Context, c preparationConfig, u unitLocator, gate preOpenGate) (preparedBatch, *openedUnitHandle, error) {
		calls++
		// The real initial InspectCapture has completed. Commit the metadata fixture
		// through an independent SQLite handle before the real second gate. Barrier
		// creation/late-erasure semantics are tested by the store's own real API tests.
		dbPath := filepath.Join(f.c.Home, "synthetic-node", "memory.sqlite")
		db, e := sql.Open("sqlite", dbPath)
		if e != nil {
			t.Fatal(e)
		}
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		_, e = tx.Exec("INSERT INTO privacy_barrier(owner,control,reason,generation) SELECT ?,?, 'bulk_confirmation_required',generation+1 FROM meta WHERE singleton=1", f.c.OwnerGenesis, strings.Repeat("d", 64))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec("UPDATE meta SET generation=generation+1 WHERE singleton=1"); e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
		if e = db.Close(); e != nil {
			t.Fatal(e)
		}
		// Missing source is a deterministic zero-open guard. Any attempted source open
		// would report unsafe_file instead of this owner-wide result.
		if e = os.Remove(f.path); e != nil {
			t.Fatal(e)
		}
		return prepareHeld(ctx, c, u, gate)
	})
	if calls != 1 || Code(err) != "owner_blocked" || result.Status != "owner_blocked" || !result.OwnerBlocked || len(result.CommittedRecordIDs) != 0 || result.ProgressVersion != 0 {
		t.Fatal("second fence lost owner block", result, err, calls)
	}
}
