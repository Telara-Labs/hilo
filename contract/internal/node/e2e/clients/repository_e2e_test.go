//go:build e2e && darwin

package clients_test

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/TAP-Runtime/discover/redact"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

var nativeRepositoryCodex = flag.Bool("e2e-repository-codex", false, "Explicitly exercise owner repository enrollment and resume the same actual Codex session")

func repositoryResumeArgs(s clientSpec, native, prompt string) []string {
	args := clientArgs(s, prompt)
	for i, arg := range args {
		if arg == prompt {
			out := append([]string(nil), args[:i]...)
			out = append(out, "resume", native, prompt)
			return append(out, args[i+1:]...)
		}
	}
	return nil
}
func TestRepositoryCodexResumeArguments(t *testing.T) {
	spec := specFor("codex")
	args := repositoryResumeArgs(spec, "01990000-0000-4000-8000-000000000001", "fixture prompt")
	found := false
	for i, arg := range args {
		if arg == "resume" {
			found = i+2 < len(args) && args[i+1] == "01990000-0000-4000-8000-000000000001" && args[i+2] == "fixture prompt"
		}
	}
	if !found || len(args) == 0 || args[0] != "exec" {
		t.Fatal("same-session resume arguments missing")
	}
}

func TestRepositoryContextHelperRestrictedToShim(t *testing.T) {
	for _, mode := range []string{"managed-daemon", "hook", "sandbox-probe", "bootstrap"} {
		if err := helperMain([]string{mode, "--repository-context", strings.Repeat("a", 32)}); err != reasonHelperArguments {
			t.Fatalf("%s accepted shim-only selector: %v", mode, err)
		}
	}
	if err := helperMain([]string{"clients", "install", "--repository-context", strings.Repeat("a", 32)}); err != reasonHelperArguments {
		t.Fatalf("clients accepted shim-only selector: %v", err)
	}
}

func repositoryPhaseBSession(hooks []hookObservation, client, native string) bool {
	terminal := false
	for _, h := range hooks {
		if h.Phase != "B" || h.Client != client || !h.Result.Published {
			continue
		}
		if h.Session != native {
			return false
		}
		switch h.Event {
		case "SessionEnd", "Stop", "stop", "sessionEnd", "agent_end", "session_shutdown":
			terminal = true
		}
	}
	return terminal
}

func TestRepositoryPhaseBRequiresExactPublishedNativeSession(t *testing.T) {
	const native = "01990000-0000-4000-8000-000000000001"
	hook := func(phase, id, event string, published bool) hookObservation {
		return hookObservation{Phase: phase, Client: "codex", Session: id, Event: event, Result: clients.HookResult{Published: published}}
	}
	for _, test := range []struct {
		name  string
		hooks []hookObservation
		want  bool
	}{
		{"phase-A-only", []hookObservation{hook("A", native, "SessionEnd", true)}, false},
		{"unpublished-B", []hookObservation{hook("B", native, "SessionEnd", false)}, false},
		{"nonterminal-B", []hookObservation{hook("B", native, "SessionStart", true)}, false},
		{"new-native-B", []hookObservation{hook("A", native, "SessionEnd", true), hook("B", "01990000-0000-4000-8000-000000000002", "SessionEnd", true)}, false},
		{"extra-native-B", []hookObservation{hook("B", native, "SessionEnd", true), hook("B", "01990000-0000-4000-8000-000000000002", "SessionStart", true)}, false},
		{"same-native-B", []hookObservation{hook("A", native, "SessionEnd", true), hook("B", native, "Stop", true), hook("B", native, "SessionEnd", true)}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := repositoryPhaseBSession(test.hooks, "codex", native); got != test.want {
				t.Fatal("phase B native identity", got, test.want)
			}
		})
	}
}

// This uses real Codex, installed shim/daemon, protected native transcript
// capture, SQLite and a dedicated OS keychain. The test image exercises package
// integration; signed production CLI packaging and hosted sync are separate gates.
func TestRepositoryInstalledCodexSameSession(t *testing.T) {
	if !*nativeRepositoryCodex {
		t.Skip("supply -e2e-repository-codex for explicit native acceptance")
	}
	s := specFor("codex")
	if *dryRun || s.auth == nil || *s.auth == "" {
		t.Fatal("actual Codex auth and native execution required")
	}
	if *resultsDir == "" || validateResultsDir(*resultsDir) != nil {
		t.Fatal("existing canonical results directory required")
	}
	r := receipt{Client: "codex-repository", Mode: "native_repository_same_session", Verdict: "UNVERIFIED", Started: time.Now().UTC(), Version: "UNVERIFIED", Paths: map[string]string{}, Timings: map[string]float64{}, Checks: map[string]string{}, Cleanup: "not_needed"}
	var cfg installedConfig
	var installed *installation
	defer func() {
		if installed != nil {
			if err := installed.cleanup(); err != nil {
				r.Cleanup = "FAIL"
				t.Error(err)
			} else {
				r.Cleanup = "PASS"
			}
		}
		if cfg.Data != "" {
			r.Calls, r.Hooks = readEvidence(t, cfg.Data)
			r.Diagnostics = readDiagnostics(t, cfg.Data)
		}
		if cfg.Root != "" {
			if err := os.RemoveAll(cfg.Root); err != nil {
				r.Cleanup = "FAIL"
				t.Error(err)
			}
		}
		if t.Failed() {
			r.Verdict = "FAIL"
		} else {
			r.Verdict = "PASS"
		}
		r.Seconds = time.Since(r.Started).Seconds()
		if err := writeReceipt(*resultsDir, r); err != nil {
			t.Error(err)
		}
	}()
	parent := *tempParent
	if parent == "" {
		parent = os.TempDir()
	}
	parent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		t.Fatal(err)
	}
	realHome, err := os.UserHomeDir()
	if err != nil || parent == realHome || under(realHome, parent) {
		t.Fatal("isolated temporary parent required")
	}
	root, err := os.MkdirTemp(parent, "mr-")
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg = installedConfig{Root: root, Home: filepath.Join(root, "home"), Data: filepath.Join(root, "data"), Run: filepath.Join(root, "run"), Install: filepath.Join(root, "install"), Keychain: filepath.Join(root, "probe.keychain"), Client: "codex", Timeout: *childTimeout, Debug: *debugRun}
	cfg.ClientConfig = filepath.Join(cfg.Home, s.configRelative)
	for _, path := range []string{cfg.Home, cfg.ClientConfig, filepath.Join(cfg.Home, "tmp"), filepath.Join(cfg.Home, "work-a"), filepath.Join(cfg.Home, "work-b")} {
		if err = os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	r.Paths = map[string]string{"root": cfg.Root, "home": cfg.Home, "data": cfg.Data, "run": cfg.Run, "install": cfg.Install, "keychain": cfg.Keychain}
	if err = copyAuth(*s.auth, filepath.Join(cfg.ClientConfig, s.authName)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5**childTimeout)
	defer cancel()
	installed, err = setupInstallation(ctx, cfg)
	if err != nil {
		recordFailureCodes(t, &r, err)
		t.Fatal("native installation", err)
	}
	r.Paths["launchd_label"] = installed.label
	env := isolatedEnv(cfg.Home, cfg.ClientConfig, s)
	raw, err := run(ctx, cfg.Home, env, nil, installed.record.Executable, "clients", "install", "--client", "codex", "--home", cfg.Home, "--config-root", cfg.ClientConfig, "--state-dir", cfg.Data, "--executable", installed.record.Executable)
	if err != nil {
		t.Fatal(err)
	}
	var report clients.Report
	if json.Unmarshal(raw, &report) != nil || mergeReport(cfg, report) != nil {
		t.Fatal("native adapter registration")
	}
	binary := *s.executable
	if binary == "" {
		binary, err = exec.LookPath(s.binary)
		if err != nil {
			t.Fatal(err)
		}
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil || codeRoot(binary) == realHome || under(codeRoot(binary), realHome) {
		t.Fatal("dedicated installed Codex executable required")
	}
	r.Paths["client_binary"] = binary
	profile := filepath.Join(cfg.Root, "client.sb")
	if err = privateWrite(profile, []byte(clientProfile(realHome, binary, cfg))); err != nil {
		t.Fatal(err)
	}
	if err = privateWrite(filepath.Join(cfg.Root, "denied-read", "canary"), []byte("synthetic denied canary")); err != nil {
		t.Fatal(err)
	}
	canaryVault := isolatedVault{cfg: cfg, exe: installed.record.Executable}
	if err = canaryVault.Put(ctx, keychainCanaryHandle, keychainCanaryValue); err != nil {
		t.Fatal(err)
	}
	defer canaryVault.Delete(context.Background(), keychainCanaryHandle)
	if _, err = run(ctx, cfg.Home, env, nil, "/usr/bin/sandbox-exec", "-f", profile, installed.record.Executable, "sandbox-probe", "--data-dir", cfg.Data); err != nil {
		t.Fatal("native sandbox preflight", err)
	}
	clientEnv, err := isolatedClientEnv(cfg.Home, cfg.ClientConfig, s)
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(cfg.Home, "work-a")
	launch := func(args []string) ([]byte, error) {
		return run(ctx, project, clientEnv, nil, "/usr/bin/sandbox-exec", append([]string{"-f", profile, binary}, args...)...)
	}
	version, err := launch([]string{"--version"})
	if err != nil || len(version) > 512 {
		t.Fatal("isolated Codex version", err)
	}
	r.Version = strings.TrimSpace(string(version))
	// A real disposable Git repository establishes the exact owner's selected
	// project root; cwd/transcript/MCP arguments never enroll it by themselves.
	if _, err = run(ctx, project, env, nil, "/usr/bin/git", "init", "--quiet"); err != nil {
		t.Fatal(err)
	}
	remote := "example.invalid/owner/" + nonce()
	if _, err = run(ctx, project, env, nil, "/usr/bin/git", "remote", "add", "origin", "https://"+remote+".git"); err != nil {
		t.Fatal(err)
	}
	n := nonce()
	if err = setPhase(cfg, "A"); err != nil {
		t.Fatal(err)
	}
	promptA := "Reply with this synthetic text: CAPTURE_CANARY " + n + " " + canary + ". Do not call tools or read files. End this turn."
	if _, err = launch(clientArgs(s, promptA)); err != nil {
		recordFailureCodes(t, &r, err)
		t.Fatal("actual native initial session", err)
	}
	_, hooks := readEvidence(t, cfg.Data)
	native := terminalSession(hooks, "codex")
	if !record.IsUUID(native) {
		t.Fatal("actual native terminal session id absent")
	}
	if err = setPhase(cfg, "capture"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2100 * time.Millisecond)
	if _, err = syntheticCall(ctx, cfg, installed.record.Executable, "telara_task_list", map[string]any{"query": n, "mode": "detail"}); err != nil {
		t.Fatal(err)
	}
	capturedIDs, err := waitCaptured(ctx, cfg.Data, "codex", native, n)
	if err != nil {
		t.Fatal("original actual native capture", err)
	}
	r.SessionIDs = append(r.SessionIDs, capturedIDs...)
	paths, err := isolatedPaths(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, machine, err := store.InstalledIdentity(cfg.Data)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey, err := record.SessionKey("codex", "local", record.NativeGlobal, native, machine)
	if err != nil {
		t.Fatal(err)
	}
	response, err := daemon.Call(ctx, paths, "repository", "repository_inspect", struct{}{})
	if err != nil || response.Error != nil {
		t.Fatal("owner observation inspection", err)
	}
	var inspected store.RepositoryInspection
	if decodeControl(response.Result, &inspected) != nil {
		t.Fatal("owner observation response")
	}
	observation := ""
	for _, candidate := range inspected.Observations {
		if candidate.Session == sessionKey {
			observation = candidate.ID
			break
		}
	}
	if observation == "" {
		t.Fatal("signed current same-session observation unavailable")
	}
	response, err = daemon.Call(ctx, paths, "repository", "repository_enroll", map[string]string{"observation": observation, "project_root": project, "remote": remote})
	if err != nil || response.Error != nil {
		t.Fatal("explicit owner enrollment", err)
	}
	var enrolled disclosure.RepositoryContext
	if decodeControl(response.Result, &enrolled) != nil || enrolled.State != "active" {
		t.Fatal("native context enrollment failed")
	}
	// Vendor CLI performs its own config editing; no handwritten TOML merge.
	if _, err = run(ctx, project, clientEnv, nil, binary, "mcp", "remove", "telara-memory"); err != nil {
		t.Fatal(err)
	}
	if _, err = run(ctx, project, clientEnv, nil, binary, "mcp", "add", "telara-memory", "--", installed.record.Executable, "shim", "--data-dir", cfg.Data, "--repository-context", enrolled.ID); err != nil {
		t.Fatal(err)
	}
	if err = setPhase(cfg, "B"); err != nil {
		t.Fatal(err)
	}
	phaseBNonce := nonce()
	if phaseBNonce == n {
		t.Fatal("phase B nonce must be new")
	}
	promptB := "This is the same resumed session. Use telara-memory MCP and call telara_task_create exactly once with goal " + n + ". Then reply CAPTURE_CANARY " + phaseBNonce + " " + canary + " and end this turn. Do not read files or use other tools."
	if _, err = launch(repositoryResumeArgs(s, native, promptB)); err != nil {
		recordFailureCodes(t, &r, err)
		t.Fatal("actual same-session resumption", err)
	}
	calls, hooks := readEvidence(t, cfg.Data)
	if !repositoryPhaseBSession(hooks, "codex", native) || !hasCall(calls, "B", "telara_task_create", n) {
		t.Fatal("same actual session did not execute scoped MCP create")
	}
	if err = setPhase(cfg, "capture"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2100 * time.Millisecond)
	if _, err = syntheticCall(ctx, cfg, installed.record.Executable, "telara_task_list", map[string]any{"query": n, "mode": "detail"}); err != nil {
		t.Fatal(err)
	}
	repoID, err := record.RepoID(remote)
	if err != nil {
		t.Fatal(err)
	}
	if err = repositoryNativeEvidence(ctx, cfg.Data, sessionKey, native, repoID, remote, observation, n, phaseBNonce); err != nil {
		t.Fatal(err)
	}
	if err = captureACK(ctx, cfg.Data, "codex", 2); err != nil {
		t.Fatal(err)
	}
	response, err = daemon.Call(ctx, paths, "repository", "repository_revoke", map[string]string{"binding": enrolled.Binding})
	if err != nil || response.Error != nil {
		t.Fatal("owner retirement", err)
	}
	refused, err := repositoryScopedCall(ctx, cfg, installed.record.Executable, enrolled.ID)
	if err != nil || !responseError(refused) {
		t.Fatal("retired context fell back to default credential", err)
	}
	if err = repositoryRetirementEvidence(ctx, cfg.Data, observation, repoID); err != nil {
		t.Fatal(err)
	}
	r.Checks["native_same_session"] = "PASS actual Codex resume kept exact native session id"
	r.Checks["owner_repository_ingress"] = "PASS original signed observation enrolled explicitly; resumed native capture and actual MCP task carry exact repository identity"
	r.Checks["retirement"] = "PASS owner retirement and scoped installed MCP refusal; original unbound observation retained"
	r.Checks["boundary"] = "Package/native integration only; hosted sync and signed production CLI packaging remain separate"
}

func decodeControl(value any, dest any) error {
	raw, ok := value.(json.RawMessage)
	if !ok {
		return errors.New("invalid control response")
	}
	return json.Unmarshal(raw, dest)
}
func repositoryNativeEvidence(ctx context.Context, data, session, native, repo, remote, original, goal, phaseBNonce string) error {
	u := url.URL{Scheme: "file", Path: filepath.Join(data, "memory.sqlite"), RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, "SELECT r.id,r.header,b.body,r.sigs,r.owner,r.seq,r.state,r.sig_status FROM record r JOIN record_body b ON b.id=r.id ORDER BY r.seq")
	if err != nil {
		return err
	}
	defer rows.Close()
	type proof struct {
		rec                  *record.Record
		signatures           []record.Signature
		owner, state, status string
		seq                  int64
	}
	var proofs []proof
	owner, machine, err := store.InstalledIdentity(data)
	if err != nil {
		return err
	}
	keyring := sig.NewKeyring(owner)
	for rows.Next() {
		var id string
		var header, body, signatures []byte
		var p proof
		if rows.Scan(&id, &header, &body, &signatures, &p.owner, &p.seq, &p.state, &p.status) != nil {
			return errors.New("capture proof read failed")
		}
		rec, err := record.Parse(header, body, id)
		if err != nil {
			return err
		}
		if bytes.Contains(body, []byte(canary)) {
			return errors.New("raw capture canary persisted")
		}
		if err = json.Unmarshal(signatures, &p.signatures); err != nil {
			return errors.New("stored signature proof invalid")
		}
		p.rec = rec
		proofs = append(proofs, p)
		if b, ok := rec.Body.(*record.KeyOpBody); ok {
			if err = keyring.Add(&sig.KeyOp{Rec: rec, Body: b, Sigs: p.signatures, AdmittedSeq: p.seq}); err != nil {
				return errors.New("native keyring proof invalid")
			}
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	verified := map[string]*record.Record{}
	var sessions []*record.Record
	boundTask, localOriginal := false, false
	keyState := keyring.State()
	for _, p := range proofs {
		r := p.rec
		if p.state != "live" || p.status != "verified" || p.owner != owner || r.Header.Type == record.KindKeyOp {
			continue
		}
		result := sig.VerifyRecord(r, p.signatures, keyState, sig.Context{Route: record.RouteLocal, AdmittedSeq: p.seq})
		if result.Status != sig.StatusVerified || result.Owner != owner || r.Header.Author.MachineID != machine {
			return errors.New("native content signature proof invalid")
		}
		verified[r.ID] = r
		if r.ID == original {
			localOriginal = r.Header.Subj.RepoID == "" && !bytes.Contains(r.BodyJCS, []byte(phaseBNonce))
		}
		if r.Header.Subj.RepoID != repo {
			continue
		}
		if _, ok := r.Body.(*record.SessionBody); ok {
			sessions = append(sessions, r)
		}
		if b, ok := r.Body.(*record.TaskBody); ok && b.Goal == goal {
			boundTask = true
		}
	}
	boundSession := false
	for _, r := range sessions {
		if repositoryBoundSessionMarker(r, verified, session, native, repo, remote, phaseBNonce) {
			boundSession = true
		}
	}
	if !boundSession || !boundTask || !localOriginal {
		return errors.New("actual same-session repository evidence incomplete")
	}
	return nil
}

// Inputs are canonical records whose signatures and live admission state were
// verified above. The B-only assistant marker must belong to a chunk explicitly
// referenced by the bound A session; an unchanged recapture of A cannot pass.
func repositoryBoundSessionMarker(r *record.Record, verified map[string]*record.Record, session, native, repo, remote, nonce string) bool {
	if r == nil || nonce == "" {
		return false
	}
	b, ok := r.Body.(*record.SessionBody)
	if !ok || r.Header.Prov != record.ProvTranscript || r.Header.Subj.SessionKey != session || r.Header.Subj.RepoID != repo || b.NativeID != native || b.NativeIDKind != record.NativeGlobal || b.Repo == nil || b.Repo.ID != repo || b.Repo.Remote != remote {
		return false
	}
	for _, id := range b.Chunks {
		chunk := verified[id]
		if chunk == nil || chunk.Header.Prov != record.ProvTranscript || chunk.Header.Subj.SessionKey != session || chunk.Header.Subj.RepoID != repo || chunk.Header.Subj.Source != r.Header.Subj.Source {
			continue
		}
		body, ok := chunk.Body.(*record.ChunkBody)
		if !ok {
			continue
		}
		for _, event := range body.Events {
			if event.Kind == "assistant_text" && event.Text != nil && strings.Contains(event.Text.Body, "CAPTURE_CANARY "+nonce) && strings.Contains(event.Text.Body, redact.Redact(canary)) {
				return true
			}
		}
	}
	return false
}

func TestRepositoryPhaseBMarkerRequiresBoundASessionChunk(t *testing.T) {
	const session, native, repo, remote, phaseB = "session-A", "native-A", "repo-A", "example.invalid/owner/repo", "phase-B-only-nonce"
	fixture := func() (*record.Record, map[string]*record.Record) {
		h := record.Header{Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: session, Source: "source-A", RepoID: repo}}
		r := &record.Record{ID: "bound-A", Header: h, Body: &record.SessionBody{NativeID: native, NativeIDKind: record.NativeGlobal, Repo: &record.RepoRef{ID: repo, Remote: remote}, Chunks: []string{"chunk-B"}}}
		chunk := &record.Record{ID: "chunk-B", Header: h, Body: &record.ChunkBody{Events: []record.Event{{Kind: "assistant_text", Text: &record.Text{Body: "CAPTURE_CANARY " + phaseB + " " + redact.Redact(canary)}}}}}
		return r, map[string]*record.Record{chunk.ID: chunk}
	}
	for _, mode := range []string{"positive", "unchanged-A", "unreferenced-B", "new-native-B", "chunk-other-session", "chunk-other-repo", "chunk-other-source", "unverified-B", "prompt-only-B"} {
		t.Run(mode, func(t *testing.T) {
			r, verified := fixture()
			chunk := verified["chunk-B"]
			switch mode {
			case "unchanged-A":
				chunk.Body.(*record.ChunkBody).Events[0].Text.Body = "CAPTURE_CANARY phase-A-only " + redact.Redact(canary)
			case "unreferenced-B":
				r.Body.(*record.SessionBody).Chunks = []string{"chunk-A"}
			case "new-native-B":
				r.Body.(*record.SessionBody).NativeID = "native-B"
			case "chunk-other-session":
				chunk.Header.Subj.SessionKey = "session-B"
			case "chunk-other-repo":
				chunk.Header.Subj.RepoID = "repo-B"
			case "chunk-other-source":
				chunk.Header.Subj.Source = "source-B"
			case "unverified-B":
				delete(verified, chunk.ID)
			case "prompt-only-B":
				chunk.Body.(*record.ChunkBody).Events[0].Kind = "user_prompt"
			}
			if got := repositoryBoundSessionMarker(r, verified, session, native, repo, remote, phaseB); got != (mode == "positive") {
				t.Fatal("phase B marker association", mode, got)
			}
		})
	}
}
func repositoryScopedCall(ctx context.Context, cfg installedConfig, exe, selector string) ([]byte, error) {
	if verifyShimImage(cfg, exe) != nil {
		return nil, errors.New("installed shim unavailable")
	}
	cmd := command(ctx, cfg.Home, isolatedEnv(cfg.Home, cfg.ClientConfig, specFor("codex")), exe, "shim", "--data-dir", cfg.Data, "--repository-context", selector)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	defer func() { in.Close(); _ = cmd.Cancel(); _ = cmd.Wait() }()
	params, err := json.Marshal(map[string]any{"name": "telara_task_list", "arguments": map[string]any{"query": "retired", "mode": "detail"}, "_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": daemon.LatestProtocolVersion, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}})
	if err != nil {
		return nil, err
	}
	if err = ipc.WriteFrame(in, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params}); err != nil {
		return nil, err
	}
	return ipc.ReadFrame(bufio.NewReader(out))
}

func repositoryRetirementEvidence(ctx context.Context, data, original, repo string) error {
	u := url.URL{Scheme: "file", Path: filepath.Join(data, "memory.sqlite"), RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, "SELECT r.id,r.header,b.body,r.state FROM record r LEFT JOIN record_body b ON b.id=r.id")
	if err != nil {
		return err
	}
	defer rows.Close()
	localOriginal, retired := false, 0
	for rows.Next() {
		var id, state string
		var header, body []byte
		if err = rows.Scan(&id, &header, &body, &state); err != nil {
			return err
		}
		var h record.Header
		if err = json.Unmarshal(header, &h); err != nil {
			return err
		}
		if id == original {
			localOriginal = state == "live" && h.Subj.RepoID == "" && len(body) != 0
		}
		if h.Subj.RepoID == repo && !h.Type.IsControl() {
			if state == "live" || len(body) != 0 {
				return errors.New("retired bound content remained available")
			}
			retired++
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if !localOriginal || retired < 2 {
		return errors.New("retirement did not preserve original and retire bound session/task")
	}
	return nil
}
