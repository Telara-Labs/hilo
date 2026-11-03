package sync

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

// Seal hostile bodies directly so these tests do not depend on the authoring
// parser accepting them. Each candidate has its own valid digest and signature.
func metadataCandidate(t *testing.T, f *fixture, body record.SessionMetaBody) (SignedRecord, *Operation) {
	t.Helper()
	h := f.signed(t, 1).Record.Header
	sk, err := record.SessionKey("codex", "local", record.NativeGlobal, "metadata-session", device)
	if err != nil {
		t.Fatal(err)
	}
	h.Type, h.Subj = record.KindSession, record.Subject{SessionKey: sk, RepoID: repo}
	h.LID = record.SessionLID(sk, device, 0)
	template, err := record.Build(h, &record.SessionMetaBody{NativeIDKind: record.NativeGlobal})
	if err != nil {
		t.Fatal(err)
	}
	body.Salt = template.Body.(*record.SessionMetaBody).Salt
	rawBody, err := jcs.MarshalRecord(body)
	if err != nil {
		t.Fatal(err)
	}
	h = template.Header
	h.Body = &record.BodyRef{Digest: record.BodyDigest(rawBody), Size: int64(len(rawBody))}
	rawHeader, err := jcs.MarshalRecord(h)
	if err != nil {
		t.Fatal(err)
	}
	id := record.ContentID(rawHeader)
	signature, err := sig.SignRecord(f.recordKey, id)
	if err != nil {
		t.Fatal(err)
	}
	// A conflicting typed body cannot mask invalid signed bytes.
	signed := SignedRecord{Record: &record.Record{ID: id, Header: template.Header, Body: template.Body, HeaderJCS: rawHeader, BodyJCS: rawBody}, Sigs: []record.Signature{signature}}
	raw, err := json.Marshal(request{OpID: "metadata-admission", Envelopes: []record.Envelope{{V: record.Version, ID: id, Header: b64.EncodeToString(rawHeader), Sigs: signed.Sigs, Body: &record.EnvelopeBody{Codec: "zstd", Bytes: b64.EncodeToString(rawZstd(rawBody))}}}})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return signed, &Operation{raw: raw, digest: hex.EncodeToString(sum[:]), id: "metadata-admission"}
}

func TestMetadataRejectBeforeEnqueueRestoreAndNetwork(t *testing.T) {
	valid := record.MetaPointer{Tool: "mcp:jira", Outcome: "ok", Kind: "file", Ref: "src/retry.go", Revision: "3f9c2e1"}
	pointers := map[string]func(*record.MetaPointer){
		"absolute-prose": func(p *record.MetaPointer) {
			p.Ref = "/Users/alice/notes/customer-plan.txt\nDiscuss the planned acquisition"
		},
		"absolute":            func(p *record.MetaPointer) { p.Ref = "/etc/passwd" },
		"windows":             func(p *record.MetaPointer) { p.Ref = `C:\Users\alice\notes.txt` },
		"backslash":           func(p *record.MetaPointer) { p.Ref = `src\..\secret` },
		"traverse":            func(p *record.MetaPointer) { p.Ref = "src/../secret" },
		"dot":                 func(p *record.MetaPointer) { p.Ref = "src/./file" },
		"encoded-traversal":   func(p *record.MetaPointer) { p.Ref = "src/%2e%2e/secret" },
		"home":                func(p *record.MetaPointer) { p.Ref = "~/secret" },
		"prose":               func(p *record.MetaPointer) { p.Ref = "Discuss the planned acquisition" },
		"empty-path":          func(p *record.MetaPointer) { p.Ref = "" },
		"empty-segment":       func(p *record.MetaPointer) { p.Ref = "src//secret" },
		"trailing-slash":      func(p *record.MetaPointer) { p.Ref = "src/" },
		"kind":                func(p *record.MetaPointer) { p.Kind = "prompt" },
		"empty-kind":          func(p *record.MetaPointer) { p.Kind = "" },
		"tool-prose":          func(p *record.MetaPointer) { p.Tool = "read the secret" },
		"tool-empty":          func(p *record.MetaPointer) { p.Tool = "" },
		"tool-prefix":         func(p *record.MetaPointer) { p.Tool = ":read" },
		"tool-bound":          func(p *record.MetaPointer) { p.Tool = strings.Repeat("x", 129) },
		"outcome":             func(p *record.MetaPointer) { p.Outcome = "the secret result" },
		"outcome-empty":       func(p *record.MetaPointer) { p.Outcome = "" },
		"revision":            func(p *record.MetaPointer) { p.Revision = "a secret revision" },
		"revision-short":      func(p *record.MetaPointer) { p.Revision = "abcdef" },
		"revision-case":       func(p *record.MetaPointer) { p.Revision = "ABCDEF0" },
		"revision-bound":      func(p *record.MetaPointer) { p.Revision = strings.Repeat("a", 65) },
		"path-bound":          func(p *record.MetaPointer) { p.Ref = strings.Repeat("x", 1025) },
		"issue-prose":         func(p *record.MetaPointer) { p.Kind = "issue"; p.Ref = "planned acquisition" },
		"issue-bound":         func(p *record.MetaPointer) { p.Kind = "issue"; p.Ref = "TEAM-" + strings.Repeat("1", 21) },
		"issue-zero":          func(p *record.MetaPointer) { p.Kind = "issue"; p.Ref = "TEAM-0" },
		"issue-lowercase":     func(p *record.MetaPointer) { p.Kind = "issue"; p.Ref = "team-1" },
		"issue-project-bound": func(p *record.MetaPointer) { p.Kind = "issue"; p.Ref = strings.Repeat("A", 33) + "-1" },
	}
	for name, ref := range map[string]string{
		"userinfo":            "https://alice:password@example.com/path",
		"query":               "https://example.com/path?private=value",
		"empty-query":         "https://example.com/path?",
		"fragment":            "https://example.com/path#secret",
		"empty-fragment":      "https://example.com/path#",
		"scheme":              "file:///Users/alice/secret",
		"opaque":              "https:secret",
		"url-prose":           "https://example.com/Discuss%20the%20acquisition",
		"url-traversal":       "https://example.com/a/%2e%2e/secret",
		"url-double-encoding": "https://example.com/%252e%252e/secret",
		"url-backslash":       "https://example.com/a%5csecret",
		"url-bound":           "https://example.com/" + strings.Repeat("a", 2048),
		"url-path-bound":      "https://example.com/" + strings.Repeat("a", 1025),
		"url-empty-host":      "https:///path",
		"url-host-underscore": "https://example_host/path",
		"url-parse":           "https://example.com/%zz",
		"url-empty-segment":   "https://example.com/a//b",
		"url-home":            "https://example.com/~/secret",
	} {
		pointers[name] = func(p *record.MetaPointer) { p.Kind = "url"; p.Ref = ref }
	}
	tests := map[string]func(*record.SessionMetaBody){
		"os-prose":            func(b *record.SessionMetaBody) { b.MachineOS = "secret prose" },
		"os-bound":            func(b *record.SessionMetaBody) { b.MachineOS = strings.Repeat("x", 33) },
		"os-case":             func(b *record.SessionMetaBody) { b.MachineOS = "Darwin" },
		"os-prefix":           func(b *record.SessionMetaBody) { b.MachineOS = "1linux" },
		"requests":            func(b *record.SessionMetaBody) { b.Counts = &record.MetaCounts{Requests: -1} },
		"calls":               func(b *record.SessionMetaBody) { b.Counts = &record.MetaCounts{ToolCalls: -1} },
		"failures":            func(b *record.SessionMetaBody) { b.Counts = &record.MetaCounts{ToolFailures: -1} },
		"repo-start":          func(b *record.SessionMetaBody) { b.Repo = &record.MetaRepo{CommitStart: "/Users/alice"} },
		"repo-end":            func(b *record.SessionMetaBody) { b.Repo = &record.MetaRepo{CommitEnd: "Discuss acquisition"} },
		"repo-revision-short": func(b *record.SessionMetaBody) { b.Repo = &record.MetaRepo{CommitStart: "abcdef"} },
		"repo-revision-bound": func(b *record.SessionMetaBody) { b.Repo = &record.MetaRepo{CommitEnd: strings.Repeat("a", 65)} },
		"repo-missing-id":     func(b *record.SessionMetaBody) { b.Repo = &record.MetaRepo{Remote: "github.com/acme/repo"} },
		"repo-id-mismatch":    func(b *record.SessionMetaBody) { b.Repo = &record.MetaRepo{ID: repo, Remote: "github.com/acme/repo"} },
	}
	for name, remote := range map[string]string{
		"query":       "github.com/acme/repo?secret=x",
		"fragment":    "github.com/acme/repo#secret",
		"credentials": "alice:password@github.com/acme/repo",
		"git-suffix":  "github.com/acme/repo.git",
		"scheme":      "https://github.com/acme/repo",
		"traversal":   "github.com/acme/../secret",
		"encoded":     "github.com/acme/%252e%252e/secret",
		"prose":       "github.com/acme/secret prose",
		"backslash":   `github.com/acme\secret`,
		"path-bound":  "github.com/" + strings.Repeat("a", 1025),
	} {
		tests["remote-"+name] = func(b *record.SessionMetaBody) {
			id, _ := record.RepoID(remote)
			b.Repo = &record.MetaRepo{ID: id, Remote: remote}
		}
	}
	for name, edit := range pointers {
		tests["pointer-"+name] = func(b *record.SessionMetaBody) {
			p := valid
			edit(&p)
			b.Pointers = []record.MetaPointer{valid, p, valid}
		}
	}
	f := newFixture(t, 0)
	f.keystore.beforeLoad = func() { t.Error("invalid metadata reached credential load") }
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			body := record.SessionMetaBody{NativeIDKind: record.NativeGlobal, MachineOS: "darwin"}
			edit(&body)
			signed, persisted := metadataCandidate(t, f, body)
			beforeBody, beforeHeader, beforeWire := append([]byte(nil), signed.Record.BodyJCS...), append([]byte(nil), signed.Record.HeaderJCS...), persisted.Bytes()
			if _, err := NewOperation(persisted.id, []SignedRecord{signed}); !errors.Is(err, ErrInvalid) {
				t.Error("enqueue accepted prohibited signed metadata", err)
			}
			if _, err := RestoreOperation(persisted.Bytes(), persisted.Digest()); !errors.Is(err, ErrInvalid) {
				t.Error("restore accepted prohibited signed metadata", err)
			}
			f.outbox.op = persisted
			if _, err := f.client.Push(t.Context()); !errors.Is(err, ErrInvalid) {
				t.Error("push accepted prohibited signed metadata", err)
			}
			if f.mintCount != 0 || f.pushCount != 0 || f.outbox.authCalls != 0 || f.outbox.completes != 0 || len(f.outbox.retries) != 0 || f.outbox.ctlCursor != 2 || f.outbox.dataCursor != 3 || f.outbox.op != persisted {
				t.Fatal("rejection crossed credential/network/outbox boundary")
			}
			if !bytes.Equal(beforeBody, signed.Record.BodyJCS) || !bytes.Equal(beforeHeader, signed.Record.HeaderJCS) || !bytes.Equal(beforeWire, persisted.Bytes()) {
				t.Fatal("rewrote rejected signed bytes")
			}
		})
	}
}

func TestMetadataAcceptedBytesAndReceipts(t *testing.T) {
	remote := "github.com/acme/repo"
	id, err := record.RepoID(remote)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]record.SessionMetaBody{
		"minimal":        {NativeIDKind: record.NativeGlobal},
		"file":           {NativeIDKind: record.NativeGlobal, Pointers: []record.MetaPointer{{Tool: "mcp:jira", Outcome: "ok", Kind: "file", Ref: "src/retry.go", Revision: "3f9c2e1"}}},
		"readme":         {NativeIDKind: record.NativeGlobal, Pointers: []record.MetaPointer{{Tool: "read", Outcome: "ok", Kind: "file", Ref: "README"}}},
		"issue":          {NativeIDKind: record.NativeGlobal, Pointers: []record.MetaPointer{{Tool: "mcp:jira", Outcome: "error", Kind: "issue", Ref: "TEAM-3632"}}},
		"repo":           {NativeIDKind: record.NativeGlobal, MachineOS: "darwin", Repo: &record.MetaRepo{ID: id, Remote: remote, CommitStart: "abcdef0", CommitEnd: strings.Repeat("a", 64)}, Counts: &record.MetaCounts{Requests: 1, ToolCalls: 2, ToolFailures: 1}},
		"file-boundary":  {NativeIDKind: record.NativeGlobal, Pointers: []record.MetaPointer{{Tool: strings.Repeat("a", 128), Outcome: "ok", Kind: "file", Ref: strings.Repeat("x", 1024), Revision: strings.Repeat("f", 64)}}},
		"issue-boundary": {NativeIDKind: record.NativeGlobal, Pointers: []record.MetaPointer{{Tool: "mcp:jira", Outcome: "error", Kind: "issue", Ref: strings.Repeat("A", 32) + "-" + strings.Repeat("1", 20)}}},
	}
	for _, os := range []string{"linux", "windows", "freebsd", "a" + strings.Repeat("0", 31)} {
		tests["os-"+os] = record.SessionMetaBody{NativeIDKind: record.NativeGlobal, MachineOS: os}
	}
	for _, ref := range []string{"https://example.com", "https://example.com/", "https://example.com/docs/", "http://[::1]:8080/docs/retry.go/", "https://example.com/" + strings.Repeat("a", 1024)} {
		tests[ref] = record.SessionMetaBody{NativeIDKind: record.NativeGlobal, Pointers: []record.MetaPointer{{Tool: "fetch", Outcome: "unknown", Kind: "url", Ref: ref}}}
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 0)
			signed, persisted := metadataCandidate(t, f, body)
			op, err := NewOperation(persisted.id, []SignedRecord{signed})
			if err != nil {
				t.Fatal(err)
			}
			restored, err := RestoreOperation(persisted.Bytes(), persisted.Digest())
			if err != nil || !bytes.Equal(op.Bytes(), persisted.Bytes()) || !bytes.Equal(restored.records[0].BodyJCS, signed.Record.BodyJCS) {
				t.Fatal("accepted bytes changed", err)
			}
			f.outbox.op = restored
			ack, err := f.client.Push(t.Context())
			if err != nil || len(ack.Results) != 1 || ack.Results[0].ID != signed.Record.ID || ack.Results[0].Receipt == nil || f.outbox.completes != 1 || f.outbox.ctlCursor != 2 || f.outbox.dataCursor != 3 {
				t.Fatal("valid metadata receipt boundary", err)
			}
		})
	}
}
