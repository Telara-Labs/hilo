//go:build darwin || linux

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/shim"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// Only installed authority is preprovisioned by this fixture. Store, facade,
// daemon, IPC and shim are the real implementation, with no mocked services.
type adapterWorld struct {
	t       *testing.T
	paths   ipc.Paths
	cfg     disclosure.Config
	key     ed25519.PrivateKey
	proof   disclosure.CredentialProof
	epoch   int64
	mu      sync.Mutex
	deny    bool
	backend *Backend
	ops     map[string]string
}

func newAdapterWorld(t *testing.T) *adapterWorld {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	p, err := ipc.Resolve(filepath.Join(base, "data"), filepath.Join(base, "run"))
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Prepare(); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32))
	cfg := disclosure.Config{OwnerGenesis: sig.KeyID(key.Public().(ed25519.PublicKey)), MachineID: "11111111-1111-4111-8111-111111111111", MaxReplyBytes: 20000}
	w := &adapterWorld{t: t, paths: p, cfg: cfg, key: key}
	st, err := store.Open(context.Background(), store.Options{Dir: p.Data, PinnedGenesisID: cfg.OwnerGenesis, LocalMachineID: cfg.MachineID})
	if err != nil {
		t.Fatal(err)
	}
	op, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Subject: sig.KeyRefOf(key.Public().(ed25519.PublicKey), record.RoleDevice, cfg.MachineID), Genesis: cfg.OwnerGenesis}, key.Public().(ed25519.PublicKey), cfg.MachineID, 1761150000000, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.Append(context.Background(), store.SignedRecord{HeaderJCS: op.Rec.HeaderJCS, BodyJCS: op.Rec.BodyJCS, Sigs: op.Sigs, AdvisoryID: op.Rec.ID}); err != nil {
		t.Fatal(err)
	}
	material, err := disclosure.PreloadRuntimeMaterial(bytes.Repeat([]byte{9}, 32), key)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := disclosure.New(context.Background(), st, cfg, material)
	material.Clear()
	if err != nil {
		t.Fatal(err)
	}
	admin, err := svc.Administration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	registered, err := admin.Register(context.Background(), disclosure.RegisterClient{AdminOpID: "adapter-register", ClientName: "Provisioned adapter test", ReadGrant: disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S}}, TaskWrites: disclosure.TaskWriteGrant{Repos: disclosure.AllLocalRepos(), AllowUnscoped: true, Actions: []disclosure.TaskMutation{disclosure.Create, disclosure.Checkpoint, disclosure.Pause, disclosure.Complete}}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := registered.Secret.Take()
	if err != nil {
		t.Fatal(err)
	}
	w.proof = disclosure.CredentialProof{CredentialID: registered.CredentialID, Token: token}
	w.epoch = registered.GrantEpoch
	if err = svc.Close(); err != nil {
		t.Fatal(err)
	}
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(w.key); clear(w.proof.Token) })
	return w
}
func (w *adapterWorld) Load(context.Context) (Runtime, error) {
	m, err := disclosure.PreloadRuntimeMaterial(bytes.Repeat([]byte{9}, 32), w.key)
	return Runtime{Config: w.cfg, Material: m, Credentials: w}, err
}
func (w *adapterWorld) Proof(context.Context, ipc.Hello) (disclosure.CredentialProof, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.deny {
		return disclosure.CredentialProof{}, errors.New("no installed identity")
	}
	return disclosure.CredentialProof{CredentialID: w.proof.CredentialID, Token: append([]byte(nil), w.proof.Token...)}, nil
}
func (w *adapterWorld) operation(label string) string {
	w.t.Helper()
	if label == "" {
		return ""
	}
	if w.ops == nil {
		w.ops = map[string]string{}
	}
	if op := w.ops[label]; op != "" {
		return op
	}
	proof, err := w.Proof(context.Background(), ipc.Hello{})
	if err != nil {
		w.t.Fatal(err)
	}
	c, err := w.backend.disclosure.service.Authenticate(context.Background(), proof)
	clear(proof.Token)
	if err != nil {
		w.t.Fatal(err)
	}
	defer c.Close()
	tokens, err := c.IssueOperationTokens(context.Background())
	if err != nil {
		w.t.Fatal(err)
	}
	for _, token := range tokens {
		used := false
		for _, prior := range w.ops {
			used = used || token == prior
		}
		if !used {
			w.ops[label] = token
			return token
		}
	}
	w.t.Fatal("test token pool exhausted")
	return ""
}

func (w *adapterWorld) start() { w.startWith(nil) }

func (w *adapterWorld) startWith(wrap func(*Backend) daemon.Backend) {
	w.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Config{Paths: w.paths, Ready: func() { close(ready) }, Open: func(ctx context.Context) (daemon.Backend, error) {
			b, err := Open(ctx, w.paths.Data, w)
			w.backend = b
			if err == nil && wrap != nil {
				return wrap(b), nil
			}
			return b, err
		}})
	}()
	select {
	case <-ready:
	case err := <-done:
		w.t.Fatal(err)
	case <-time.After(10 * time.Second):
		w.t.Fatal("daemon did not start")
	}
	w.t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				w.t.Error(err)
			}
		case <-time.After(10 * time.Second):
			w.t.Error("daemon did not stop")
		}
	})
}

type adapterSession struct {
	t      *testing.T
	world  *adapterWorld
	in     *io.PipeWriter
	out    *bufio.Reader
	next   int
	done   chan error
	cancel context.CancelFunc
}

func (w *adapterWorld) session() *adapterSession {
	w.t.Helper()
	input, write := io.Pipe()
	read, output := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- shim.Run(ctx, input, output, shim.Config{Paths: w.paths, Hello: ipc.Hello{Shim: "adapter-shim"}})
		output.Close()
	}()
	s := &adapterSession{t: w.t, world: w, in: write, out: bufio.NewReader(read), done: done, cancel: cancel}
	w.t.Cleanup(func() {
		cancel()
		write.Close()
		read.Close()
		input.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			w.t.Error("shim did not stop")
		}
	})
	return s
}
func (s *adapterSession) call(tool string, args any, op, handle string) Result {
	return s.callMeta(tool, args, Metadata{OpID: s.world.operation(op), Handle: handle})
}
func (s *adapterSession) callMeta(tool string, args any, meta Metadata) Result {
	s.t.Helper()
	s.next++
	rawMeta, _ := json.Marshal(meta)
	var wireMeta map[string]any
	_ = json.Unmarshal(rawMeta, &wireMeta)
	if meta.ProtocolVersion == daemon.LatestProtocolVersion {
		wireMeta["io.modelcontextprotocol/clientCapabilities"] = map[string]any{}
	}
	params := map[string]any{"name": tool, "arguments": args, "_meta": wireMeta}
	req := map[string]any{"jsonrpc": "2.0", "id": s.next, "method": "tools/call", "params": params}
	if err := json.NewEncoder(s.in).Encode(req); err != nil {
		s.t.Fatal(err)
	}
	line, err := s.out.ReadBytes('\n')
	if err != nil {
		s.t.Fatal(err)
	}
	var response struct {
		Error  *daemon.RPCError `json:"error"`
		Result Result           `json:"result"`
	}
	if err = json.Unmarshal(line, &response); err != nil {
		s.t.Fatal(err)
	}
	if response.Error != nil {
		s.t.Fatalf("RPC %v", response.Error)
	}
	return response.Result
}
func textOf(t *testing.T, r Result) string {
	t.Helper()
	if len(r.Content) != 1 || r.Content[0].Type != "text" {
		t.Fatal(r)
	}
	return r.Content[0].Text
}
func goodText(t *testing.T, r Result) string {
	t.Helper()
	text := textOf(t, r)
	if r.IsError {
		t.Fatal(text)
	}
	if !strings.HasPrefix(text, "call_ref ") {
		t.Fatalf("not kernel text %s", text)
	}
	return text
}
func (w *adapterWorld) count(query string, args ...any) int {
	w.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(w.paths.Data, "memory.sqlite")+"?mode=ro")
	if err != nil {
		w.t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err = db.QueryRow(query, args...).Scan(&n); err != nil {
		w.t.Fatal(err)
	}
	return n
}

func (w *adapterWorld) scalar(query string, args ...any) string {
	w.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(w.paths.Data, "memory.sqlite")+"?mode=ro")
	if err != nil {
		w.t.Fatal(err)
	}
	defer db.Close()
	var value string
	if err = db.QueryRow(query, args...).Scan(&value); err != nil {
		w.t.Fatal(err)
	}
	return value
}

var taskUUIDPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`)

var markerPattern = regexp.MustCompile(`([0-9a-f]{64})@([0-9a-f]{64})`)

func TestDisclosureSQLiteDaemonShimRoundTrips(t *testing.T) {
	w := newAdapterWorld(t)
	w.start()
	s := w.session()
	created := goodText(t, s.call("telara_task_create", map[string]any{"goal": "adapter orchard project", "name": "orchard"}, "create-orchard", "conversation"))
	task := taskUUIDPattern.FindString(created)
	if !record.IsUUIDv4(task) {
		t.Fatalf("missing released task UUID %s", created)
	}
	// Full text is byte-for-byte kernel release, with exposure already durable.
	if w.count("SELECT count(*) FROM render_body WHERE CAST(text AS TEXT)=?", created) == 0 {
		t.Fatal("adapter changed released kernel text")
	}
	if w.count("SELECT count(*) FROM operation") != 1 || w.count("SELECT count(*) FROM exposure") == 0 {
		t.Fatal("reply escaped without durable operation/exposure")
	}
	replay := goodText(t, s.call("telara_task_create", map[string]any{"goal": "adapter orchard project", "name": "orchard"}, "create-orchard", "conversation"))
	if !strings.Contains(replay, "orchard") || w.count("SELECT count(*) FROM operation") != 1 {
		t.Fatal("retry remutated")
	}
	conflict := s.call("telara_task_create", map[string]any{"goal": "changed candidate"}, "create-orchard", "conversation")
	if !conflict.IsError || textOf(t, conflict) != "op_conflict" || w.count("SELECT count(*) FROM operation") != 1 {
		t.Fatal(conflict)
	}
	checkpoint := goodText(t, s.call("telara_task_checkpoint", map[string]any{"task_id": task, "milestone": "orchard checkpoint", "next_steps": "finish"}, "checkpoint-orchard", "conversation"))
	marker := markerPattern.FindStringSubmatch(checkpoint)
	if len(marker) != 3 {
		t.Fatal(checkpoint)
	}
	resumed := goodText(t, s.call("telara_task_resume", map[string]any{"task_id": task}, "resume-orchard", "conversation"))
	if !strings.Contains(resumed, task) {
		t.Fatal("resume lost released task UUID", resumed)
	}
	goodText(t, s.call("telara_task_pause", map[string]any{"task_id": task, "resume_context": "orchard resume", "token_estimate": 10}, "pause-orchard", "conversation"))
	goodText(t, s.call("telara_task_complete", map[string]any{"task_id": task, "final_summary": "orchard completed", "token_estimate": 20}, "complete-orchard", "conversation"))
	listed := goodText(t, s.call("telara_task_list", map[string]any{"include_completed": true, "mode": "detail"}, "list-orchard", "conversation"))
	if !strings.Contains(listed, "orchard") || !strings.Contains(listed, task) {
		t.Fatal(listed)
	}
	exact := s.call("telara_task_list", map[string]any{"task_id": task}, "exact-orchard", "conversation")
	if !exact.IsError || textOf(t, exact) != "unsupported_argument" {
		t.Fatal(exact)
	}
	found := goodText(t, s.call("telara_knowledge_search", map[string]any{"query": "orchard", "resource_types": []string{"checkpoint", "task_summary"}}, "search-orchard", "conversation"))
	if !strings.Contains(found, "orchard") {
		t.Fatal(found)
	}

	// An explicitly empty MCP filter searches exactly the default local kinds.
	operationsBefore := w.count("SELECT count(*) FROM operation")
	for _, filter := range []map[string]any{
		{"query": "orchard"},
		{"query": "orchard", "resource_types": []string{}},
	} {
		text := goodText(t, s.call("telara_knowledge_search", filter, "default-kind-search", "conversation"))
		if !strings.Contains(text, "orchard") {
			t.Fatal("default search lost searchable checkpoint", text)
		}
	}
	if w.count("SELECT count(*) FROM operation") != operationsBefore+1 {
		t.Fatal("equivalent empty filter did not replay the default-filter operation")
	}
	contextArgs := map[string]any{"entity_id": marker[2], "entity_type": "checkpoint", "include_content": true}
	full := goodText(t, s.call("telara_get_context", contextArgs, "context-full", "conversation"))
	if !strings.Contains(full, "orchard checkpoint") {
		t.Fatal(full)
	}
	metadata := goodText(t, s.call("telara_get_context", map[string]any{"entity_id": marker[2], "entity_type": "checkpoint"}, "context-metadata", "conversation"))
	if strings.Contains(metadata, "orchard checkpoint") {
		t.Fatal("metadata disclosed body", metadata)
	}
	explicitMetadata := goodText(t, s.call("telara_get_context", map[string]any{"entity_id": marker[2], "entity_type": "checkpoint", "include_content": false}, "context-metadata", "conversation"))
	if strings.Fields(explicitMetadata)[1] != strings.Fields(metadata)[1] || strings.Contains(explicitMetadata, "orchard checkpoint") {
		t.Fatal("metadata default did not replay safely", explicitMetadata)
	}
	projectionConflict := s.call("telara_get_context", contextArgs, "context-metadata", "conversation")
	if !projectionConflict.IsError || textOf(t, projectionConflict) != "op_conflict" {
		t.Fatal("projection identity collapsed", projectionConflict)
	}
	wrong := s.call("telara_get_context", map[string]any{"entity_id": marker[2], "entity_type": "task", "include_content": true}, "context-wrong", "conversation")
	if !wrong.IsError || strings.Contains(textOf(t, wrong), "orchard checkpoint") {
		t.Fatal(wrong)
	}
	if got := w.count("SELECT count(*) FROM record WHERE json_extract(CAST(header AS TEXT),'$.type')='task'"); got != 1 {
		t.Fatalf("task count %d", got)
	}
	// Reconnect with different scope still cannot remutate supplied credential op.
	s2 := w.session()
	goodText(t, s2.call("telara_task_create", map[string]any{"goal": "adapter orchard project", "name": "orchard"}, "create-orchard", "different"))
	if w.count("SELECT count(*) FROM record WHERE json_extract(CAST(header AS TEXT),'$.type')='task'") != 1 {
		t.Fatal("reconnect duplicated")
	}
}

func TestDisclosureSQLiteFailClosedScopesAndAuthority(t *testing.T) {
	w := newAdapterWorld(t)
	w.start()
	s := w.session()
	for _, meta := range []Metadata{{OpID: "native", Handle: "explicit", Native: &Native{Client: "claude", ID: "native-1", Kind: record.NativeLocal, Origin: "local"}}, {OpID: "legacy", Legacy: "legacy-1"}, {OpID: "shim"}} {
		r := s.callMeta("telara_task_create", map[string]any{"goal": "must not persist"}, meta)
		if !r.IsError || textOf(t, r) != "scope_resolution_unsupported" {
			t.Fatal(r)
		}
	}
	if w.count("SELECT count(*) FROM operation") != 0 {
		t.Fatal("unsupported scope wrote outcome")
	}
	w.mu.Lock()
	w.deny = true
	w.mu.Unlock()
	r := s.call("telara_task_create", map[string]any{"goal": "must not persist"}, "", "conversation")
	if !r.IsError || textOf(t, r) != "identity_unavailable" || w.count("SELECT count(*) FROM operation") != 0 {
		t.Fatal(r)
	}
	w.mu.Lock()
	w.deny = false
	w.mu.Unlock()
	goodText(t, s.call("telara_task_create", map[string]any{"goal": "allowed"}, "allowed", "conversation"))
	admin, err := w.backend.disclosure.service.Administration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.RevokeCredential(context.Background(), "revoke-adapter", w.proof.CredentialID, w.epoch); err != nil {
		t.Fatal(err)
	}
	r = s.call("telara_task_create", map[string]any{"goal": "allowed"}, "allowed", "conversation")
	if !r.IsError || strings.Contains(textOf(t, r), "call_ref") {
		t.Fatal("revoked replay disclosed", r)
	}
	if w.count("SELECT count(*) FROM operation") != 1 {
		t.Fatal("revoked replay mutated")
	}
}

func TestDisclosureSQLiteFallbackAndUnidentifiedReplay(t *testing.T) {
	w := newAdapterWorld(t)
	w.start()
	s := w.session()
	args := map[string]any{"goal": "fallback stable handle"}
	first := goodText(t, s.call("telara_task_create", args, "", "identified"))
	s.next--
	second := goodText(t, s.call("telara_task_create", args, "", "identified"))
	if strings.Fields(first)[1] != strings.Fields(second)[1] || w.count("SELECT count(*) FROM operation") != 1 {
		t.Fatal("identified fallback retry remutated")
	}
	// Modern unidentified requests restore no operation identity from the process,
	// shim or wire ID. The inline protocol metadata includes required capabilities.
	modern := Metadata{ProtocolVersion: daemon.LatestProtocolVersion}
	goodText(t, s.callMeta("telara_task_create", map[string]any{"goal": "unidentified"}, modern))
	s.next--
	goodText(t, s.callMeta("telara_task_create", map[string]any{"goal": "unidentified"}, modern))
	if w.count("SELECT count(*) FROM operation") != 3 {
		t.Fatal("unidentified calls deduplicated")
	}
}

func TestDisclosureSQLiteReleaseRechecksCurrentAuthority(t *testing.T) {
	w := newAdapterWorld(t)
	backend, err := Open(context.Background(), w.paths.Data, w)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	svc := backend.disclosure.service
	proof, err := w.Proof(context.Background(), ipc.Hello{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := svc.Authenticate(context.Background(), proof)
	clear(proof.Token)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := c.Resolve(context.Background(), disclosure.IdentityInput{ConversationHandle: "release-fence"})
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := disclosure.DecodeCommand("local.create_task", []byte(`{"goal":"must remain unreleased"}`))
	if err != nil {
		t.Fatal(err)
	}
	reply, err := c.Execute(context.Background(), sc, disclosure.CallIdentity{JSONRPCID: []byte(`1`)}, cmd, disclosure.ByteBudget{MaxBytes: 4000})
	if err != nil {
		t.Fatal(err)
	}
	if w.count("SELECT count(*) FROM operation") != 1 || w.count("SELECT count(*) FROM exposure") == 0 {
		t.Fatal("Execute did not commit exposure")
	}
	admin, err := svc.Administration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.RevokeCredential(context.Background(), "revoke-before-release", w.proof.CredentialID, w.epoch); err != nil {
		t.Fatal(err)
	}
	if _, err = reply.Release(context.Background()); err == nil {
		t.Fatal("revoked text escaped release")
	}
}

func TestDisclosureSQLiteToolReplayIsolationAndProofBinding(t *testing.T) {
	w := newAdapterWorld(t)
	w.start()
	s := w.session()
	goodText(t, s.call("telara_task_create", map[string]any{"goal": "isolated"}, "public-tool-identity", "scope"))
	conflict := s.call("telara_task_list", map[string]any{}, "public-tool-identity", "scope")
	if !conflict.IsError || textOf(t, conflict) != "op_conflict" {
		t.Fatal("cross-tool replay", conflict)
	}
	// A changed installed proof cannot borrow a cached authenticated connection,
	// even if the transport, handle and claimed client remain identical.
	w.mu.Lock()
	w.proof.Token[0] ^= 1
	w.mu.Unlock()
	denied := s.call("telara_task_list", map[string]any{}, "", "scope")
	if !denied.IsError || textOf(t, denied) != "identity_unavailable" {
		t.Fatal(denied)
	}
	if w.count("SELECT count(*) FROM operation") != 1 {
		t.Fatal("failed proof mutated")
	}
}

func TestDisclosureSQLiteDirectCallLacksAuthenticatedTransport(t *testing.T) {
	w := newAdapterWorld(t)
	b, err := Open(context.Background(), w.paths.Data, w)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	r := b.disclosure.call(context.Background(), ipc.Hello{Client: "trusted-name"}, Metadata{Handle: "scope"}, daemon.Request{ID: json.RawMessage(`1`)}, "telara_task_create", json.RawMessage(`{"goal":"forgery"}`))
	if !r.IsError || textOf(t, r) != "identity_unavailable" || w.count("SELECT count(*) FROM operation") != 0 {
		t.Fatal(r)
	}
}

func TestDisclosureSQLiteCloseRetiresCachedHandles(t *testing.T) {
	w := newAdapterWorld(t)
	w.start()
	s := w.session()
	goodText(t, s.call("telara_task_list", map[string]any{}, "before-close", "conversation"))
	a := w.backend.disclosure
	a.mu.Lock()
	if len(a.connections) != 1 {
		a.mu.Unlock()
		t.Fatal("missing cached connection")
	}
	var connection *disclosure.Connection
	for _, cached := range a.connections {
		connection = cached.client
	}
	a.mu.Unlock()
	if err := w.backend.Close(); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	remaining := len(a.connections)
	a.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("shutdown retained %d cached connections", remaining)
	}
	if _, err := connection.Resolve(context.Background(), disclosure.IdentityInput{ConversationHandle: "after-close"}); err == nil {
		t.Fatal("retired handle remained usable")
	}
	if err := w.backend.Close(); err != nil {
		t.Fatal("close retry", err)
	}
	denied := s.call("telara_task_list", map[string]any{}, "", "conversation")
	if !denied.IsError || textOf(t, denied) != "store_unavailable" {
		t.Fatal(denied)
	}
}
