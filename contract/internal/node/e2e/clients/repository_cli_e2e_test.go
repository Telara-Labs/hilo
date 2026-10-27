//go:build e2e && darwin

package clients_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Telara-Labs/TAP-Runtime/discover/redact"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

var repositoryCLIOptIn = flag.Bool("e2e-repository-product-cli", false, "Explicit actual product CLI/native Codex acceptance; requires an unoccupied owner service label")
var repositoryCLIBinary = flag.String("e2e-product-cli", "", "Canonical root-built product CLI executable; never a test helper")
var repositoryCLIBuildReceipt = flag.String("e2e-product-cli-build-receipt", "", "Private root-authenticated executable/source/compiler build receipt")
var repositoryCLIRetain = flag.Bool("e2e-retain-owned-profile", false, "Retain successful exact capture/task records for root hosted continuation; revoke/refusal/cleanup remain PENDING ROOT")
var repositoryCLIRemote = flag.String("e2e-repository-canonical-remote", "", "Exact owner-selected canonical no-scheme remote; required for retained same-record hosted continuation, never fetched")

type cliBuildReceipt struct {
	ExecutableSHA256     string `json:"executable_sha256"`
	SourceCommit         string `json:"source_commit"`
	SourceTree           string `json:"source_tree"`
	SourceManifestSHA256 string `json:"source_manifest_sha256"`
	GoVersion            string `json:"go_version"`
	CommandPath          string `json:"command_path"`
	InstallVersionLabel  string `json:"install_version_label"`
}

type cliCommandReceipt struct {
	Stage         string   `json:"stage"`
	Executable    string   `json:"executable"`
	Argv          []string `json:"argv_public_projection"`
	ExitCode      int      `json:"exit_code"`
	TimedOut      bool     `json:"timed_out"`
	OutputLimited bool     `json:"output_limited"`
	Seconds       float64  `json:"seconds"`
}

type cliAcceptanceReceipt struct {
	Mode                   string              `json:"mode"`
	Verdict                string              `json:"verdict"`
	Failure                string              `json:"failure,omitempty"`
	Cleanup                string              `json:"cleanup"`
	Revoke                 string              `json:"positive_binding_revoke"`
	Refusal                string              `json:"retired_context_refusal"`
	Started                time.Time           `json:"started"`
	Build                  cliBuildReceipt     `json:"operator_authenticated_build_receipt"`
	BuildReceiptSHA256     string              `json:"build_receipt_sha256"`
	ActualExecutableSHA256 string              `json:"actual_executable_sha256"`
	ActualGoVersion        string              `json:"actual_go_version"`
	ActualCommandPath      string              `json:"actual_command_path"`
	ActualModuleVersion    string              `json:"actual_module_version_not_release_version"`
	VersionEvidence        string              `json:"version_evidence"`
	Paths                  map[string]string   `json:"owned_paths,omitempty"`
	Commands               []cliCommandReceipt `json:"commands,omitempty"`
	Owner                  string              `json:"owner,omitempty"`
	Machine                string              `json:"machine,omitempty"`
	NativeSession          string              `json:"native_session,omitempty"`
	SessionKey             string              `json:"session_key,omitempty"`
	Observation            string              `json:"observation,omitempty"`
	Repo                   string              `json:"repo,omitempty"`
	CanonicalRemote        string              `json:"canonical_remote,omitempty"`
	RemoteSource           string              `json:"remote_source,omitempty"`
	Binding                string              `json:"binding,omitempty"`
	Context                string              `json:"context,omitempty"`
	Task                   string              `json:"task_id,omitempty"`
	RecordIDs              []string            `json:"capture_record_ids_verified_live_before_revoke,omitempty"`
	RecordState            string              `json:"capture_record_state_at_receipt,omitempty"`
	NativeHandles          []string            `json:"owned_native_handles,omitempty"`
	Checks                 map[string]string   `json:"checks"`
}

type cliAcceptanceRun struct {
	cfg       installedConfig
	source    string
	installed string
	digest    string
	env       []string
	r         *cliAcceptanceReceipt
}

// Only closed synthetic arguments and operator-selected paths enter this receipt.
// Vendor output and copied auth are parsed in memory and never logged or saved.
func (c *cliAcceptanceRun) command(ctx context.Context, stage, dir string, env []string, input []byte, executable string, args ...string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, *childTimeout)
	defer cancel()
	cmd := command(ctx, dir, env, executable, args...)
	var out, stderr cappedBuffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(input), &out, &stderr
	start := time.Now()
	err := cmd.Run()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	status := 0
	if cmd.ProcessState != nil {
		status = cmd.ProcessState.ExitCode()
	} else if err != nil {
		status = -1
	}
	projected := make([]string, len(args))
	for i, arg := range args {
		projected[i] = redact.Redact(arg)
	}
	c.r.Commands = append(c.r.Commands, cliCommandReceipt{Stage: stage, Executable: executable, Argv: projected, ExitCode: status, TimedOut: ctx.Err() != nil, OutputLimited: out.overflow || stderr.overflow, Seconds: time.Since(start).Seconds()})
	if out.overflow || stderr.overflow || err != nil {
		if out.overflow || stderr.overflow {
			err = errors.New("bounded_child_output_refused")
		}
		return out.Bytes(), stderr.Bytes(), err
	}
	return out.Bytes(), stderr.Bytes(), nil
}

func (c *cliAcceptanceRun) cli(ctx context.Context, stage string, args ...string) ([]byte, error) {
	if digest, err := cliImageDigest(c.source); err != nil || digest != c.digest {
		return nil, errors.New("product_image_changed")
	}
	raw, stderr, err := c.command(ctx, stage, c.cfg.Home, c.env, nil, c.source, args...)
	defer clear(stderr)
	if err != nil {
		clear(raw)
		return nil, errors.New("product_cli_command_failed")
	}
	if len(stderr) != 0 {
		clear(raw)
		return nil, errors.New("product_cli_unexpected_stderr")
	}
	return raw, nil
}

func cliImageDigest(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("invalid_product_image")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return "", errors.New("invalid_product_image")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", errors.New("invalid_product_image")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Mode().Perm()&0111 == 0 || st.Size() <= 0 || st.Size() > 256<<20 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return "", errors.New("invalid_product_image")
	}
	h := sha256.New()
	if n, err := io.Copy(h, io.LimitReader(f, (256<<20)+1)); err != nil || n != st.Size() {
		return "", errors.New("product_image_read_failed")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func cliReadBuildReceipt(path, executable string) (cliBuildReceipt, string, string, error) {
	var r cliBuildReceipt
	raw, err := privateRead(path, 16384)
	defer clear(raw)
	if err != nil || cliJSON(raw, &r) != nil {
		return r, "", "", errors.New("invalid_build_receipt")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || !cliHex(r.SourceCommit, 40) || !cliHex(r.SourceTree, 40) || !record.IsHex64(r.SourceManifestSHA256) || !record.IsHex64(r.ExecutableSHA256) || !strings.HasPrefix(r.CommandPath, "github.com/Telara-Labs/telara-memory/") || !strings.HasSuffix(r.CommandPath, "/cmd/telara-memory") || r.InstallVersionLabel == "" || len(r.InstallVersionLabel) > 128 || redact.Redact(r.InstallVersionLabel) != r.InstallVersionLabel || strings.ContainsAny(r.InstallVersionLabel, "\r\n\x00") {
		return r, "", "", errors.New("invalid_build_receipt")
	}
	actual, err := cliImageDigest(executable)
	if err != nil || actual != r.ExecutableSHA256 {
		return r, "", "", errors.New("product_image_receipt_mismatch")
	}
	info, err := buildinfo.ReadFile(executable)
	if err != nil || info.Path != r.CommandPath || info.GoVersion != r.GoVersion || !regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(info.GoVersion) {
		return r, "", "", errors.New("product_build_info_mismatch")
	}
	for _, setting := range info.Settings {
		if (setting.Key == "vcs.revision" && setting.Value != r.SourceCommit) || (setting.Key == "vcs.modified" && setting.Value != "false") {
			return r, "", "", errors.New("product_build_source_revision_mismatch")
		}
	}
	h := sha256.Sum256(raw)
	return r, hex.EncodeToString(h[:]), info.Main.Version, nil
}

func cliHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == size && hex.EncodeToString(decoded) == value
}

// Accept a strict subset of the product canonicalRepositoryRemote contract.
// A caller must supply its already-normalized authority, never a credentialed
// transport URL. Constructing the owned origin below does not contact it.
func cliRepositoryRemote(value string) (string, error) {
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "@?#%\\") || strings.HasSuffix(value, ".git") {
		return "", errors.New("invalid_canonical_repository_remote")
	}
	parts := strings.Split(value, "/")
	if len(parts) < 3 || parts[0] != strings.ToLower(parts[0]) || !regexp.MustCompile(`^[a-z0-9]+([.-][a-z0-9]+)*$`).MatchString(parts[0]) {
		return "", errors.New("invalid_canonical_repository_remote")
	}
	for _, part := range parts[1:] {
		if part == "." || part == ".." || !regexp.MustCompile(`^[A-Za-z0-9._-]+$`).MatchString(part) {
			return "", errors.New("invalid_canonical_repository_remote")
		}
	}
	u, err := url.Parse("https://" + value)
	if err != nil || u.User != nil || u.Host != parts[0] || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != "https://"+value {
		return "", errors.New("invalid_canonical_repository_remote")
	}
	return record.RepoID(value)
}

func (c *cliAcceptanceRun) requireAbsentService(ctx context.Context) error {
	uid := strconv.Itoa(os.Getuid())
	label := "dev.telara.memory"
	out, stderr, err := c.command(ctx, "service_absence_preflight", c.cfg.Home, c.env, nil, "/bin/launchctl", "print", "gui/"+uid+"/"+label)
	defer clear(out)
	defer clear(stderr)
	if err == nil {
		return errors.New("service_label_occupied_preserve_existing_profile")
	}
	last := c.r.Commands[len(c.r.Commands)-1]
	if last.TimedOut || last.OutputLimited {
		return errors.New("service_label_absence_unproven")
	}
	missing := "Could not find service \"" + label + "\" in domain for user gui: " + uid
	joined := strings.TrimSpace(string(append(append([]byte(nil), out...), stderr...)))
	if joined != missing && joined != "Bad request.\n"+missing {
		return errors.New("service_label_absence_unproven")
	}
	return nil
}

func cliJSON(raw []byte, dest any) error {
	if _, err := jcs.Canonicalize(raw); err != nil {
		return errors.New("invalid_cli_json")
	}
	return json.Unmarshal(raw, dest)
}

func cliInstallRecord(raw []byte) (install.Record, error) {
	var found install.Record
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var line struct {
			State  string         `json:"state"`
			Record install.Record `json:"record"`
		}
		if cliJSON(scanner.Bytes(), &line) != nil {
			return found, errors.New("invalid_install_response")
		}
		if line.Record.Schema != 0 {
			if found.Schema != 0 {
				return found, errors.New("duplicate_install_receipt")
			}
			found = line.Record
		}
	}
	if scanner.Err() != nil || found.Schema != 1 || !install.ValidExecutablePath(found) {
		return found, errors.New("missing_install_receipt")
	}
	return found, nil
}

func cliCodexEvents(raw []byte, goal string) (native, created, listed string, err error) {
	fail := func() (string, string, string, error) {
		return "", "", "", errors.New("native_codex_event_proof_invalid")
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 4<<20)
	threads, completed, creates, lists := 0, 0, 0, 0
	for scanner.Scan() {
		var event struct {
			Type   string `json:"type"`
			Thread string `json:"thread_id"`
			Item   struct {
				Type      string                     `json:"type"`
				Server    string                     `json:"server"`
				Tool      string                     `json:"tool"`
				Arguments map[string]json.RawMessage `json:"arguments"`
				Result    json.RawMessage            `json:"result"`
				Error     json.RawMessage            `json:"error"`
				Status    string                     `json:"status"`
			} `json:"item"`
		}
		if cliJSON(scanner.Bytes(), &event) != nil {
			return fail()
		}
		switch event.Type {
		case "thread.started":
			threads++
			if !record.IsUUID(event.Thread) {
				return fail()
			}
			native = event.Thread
		case "turn.completed":
			if threads != 1 || (goal != "" && (creates != 1 || lists != 1)) {
				return fail()
			}
			completed++
		case "turn.failed", "error":
			return fail()
		case "item.completed":
			if event.Item.Type != "mcp_tool_call" {
				continue
			}
			if threads != 1 || completed != 0 {
				return fail()
			}
			if event.Item.Server != "telara-memory" || event.Item.Status != "completed" || len(event.Item.Result) == 0 || (len(event.Item.Error) != 0 && string(event.Item.Error) != "null") {
				return fail()
			}
			wrapped, e := json.Marshal(map[string]any{"result": event.Item.Result})
			if e != nil {
				return fail()
			}
			id := responseTask(wrapped, goal)
			clear(wrapped)
			var argument string
			switch event.Item.Tool {
			case "telara_task_create":
				if creates != 0 || lists != 0 || json.Unmarshal(event.Item.Arguments["goal"], &argument) != nil || argument != goal || !record.IsUUIDv4(id) {
					return fail()
				}
				creates++
				created = id
			case "telara_task_list":
				if creates != 1 || lists != 0 || json.Unmarshal(event.Item.Arguments["query"], &argument) != nil || argument != goal || !record.IsUUIDv4(id) {
					return fail()
				}
				lists++
				listed = id
			default:
				return fail()
			}
		}
	}
	if scanner.Err() != nil || threads != 1 || completed != 1 || (goal == "" && (creates != 0 || lists != 0)) || (goal != "" && (creates != 1 || lists != 1 || created != listed)) {
		return fail()
	}
	return native, created, listed, nil
}

// This is a read-only invocation of the installed product stdio frontdoor,
// never an owner-control daemon connection or a synthetic attributed writer.
func (c *cliAcceptanceRun) readMCP(ctx context.Context, selector, query string) (response []byte, resultErr error) {
	if verifyShimImage(c.cfg, c.installed) != nil {
		return nil, errors.New("installed_cli_identity_changed")
	}
	ctx, cancel := context.WithTimeout(ctx, *childTimeout)
	defer cancel()
	args := []string{"shim", "--data-dir", c.cfg.Data, "--run-dir", c.cfg.Run}
	if selector != "" {
		args = append(args, "--repository-context", selector)
	}
	cmd := command(ctx, c.cfg.Home, c.env, c.installed, args...)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, errors.New("frontdoor_pipe_failed")
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, errors.New("frontdoor_pipe_failed")
	}
	var stderr cappedBuffer
	cmd.Stderr = &stderr
	started := time.Now()
	if cmd.Start() != nil {
		return nil, errors.New("frontdoor_start_failed")
	}
	defer func() {
		in.Close()
		_ = cmd.Cancel()
		_ = cmd.Wait()
		status := -1
		if cmd.ProcessState != nil {
			status = cmd.ProcessState.ExitCode()
		}
		c.r.Commands = append(c.r.Commands, cliCommandReceipt{Stage: "read_only_installed_frontdoor_then_owned_process_stop", Executable: c.installed, Argv: args, ExitCode: status, TimedOut: ctx.Err() != nil, OutputLimited: stderr.overflow, Seconds: time.Since(started).Seconds()})
		if stderr.overflow || ctx.Err() != nil {
			clear(response)
			response = nil
			resultErr = errors.New("frontdoor_capture_or_timeout_failed")
		}
		clear(stderr.Bytes())
	}()
	params, err := json.Marshal(map[string]any{"name": "telara_task_list", "arguments": map[string]any{"query": query, "mode": "detail"}, "_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": daemon.LatestProtocolVersion, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}})
	if err != nil {
		return nil, errors.New("frontdoor_request_failed")
	}
	if ipc.WriteFrame(in, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params}) != nil {
		return nil, errors.New("frontdoor_request_failed")
	}
	response, err = ipc.ReadFrame(bufio.NewReader(out))
	if err != nil {
		return nil, errors.New("frontdoor_response_failed")
	}
	return response, nil
}

func cliDB(ctx context.Context, data string) (*sql.DB, error) {
	if _, err := privateRead(filepath.Join(data, "installed-authority.json"), 16384); err != nil {
		return nil, errors.New("owned_profile_unavailable")
	}
	u := url.URL{Scheme: "file", Path: filepath.Join(data, "memory.sqlite"), RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// Signature and exact bound session/chunk association are checked by the
// unchanged repositoryNativeEvidence oracle before selecting these handoff IDs.
func cliHandoffIDs(ctx context.Context, data, repo, task, goal, binding string) ([]string, error) {
	db, err := cliDB(ctx, data)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, "SELECT r.id,r.header,b.body,rr.binding,r.state,r.sig_status FROM record r JOIN record_body b ON b.id=r.id JOIN repository_record rr ON rr.id=r.id ORDER BY r.id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	tasks, sessions := 0, 0
	for rows.Next() {
		var id, associated, state, status string
		var header, body []byte
		if rows.Scan(&id, &header, &body, &associated, &state, &status) != nil {
			return nil, errors.New("handoff_record_read_failed")
		}
		r, e := record.Parse(header, body, id)
		if e != nil || bytes.Contains(body, []byte(canary)) {
			return nil, errors.New("handoff_record_invalid")
		}
		if r.Header.Subj.RepoID != repo {
			continue
		}
		if associated != binding || state != "live" || status != "verified" {
			return nil, errors.New("handoff_record_not_live_bound_verified")
		}
		if b, ok := r.Body.(*record.TaskBody); ok && r.Header.Subj.TaskID == task {
			if r.Header.Prov != record.ProvMCPExplicit || b.Goal != goal {
				return nil, errors.New("actual_mcp_task_provenance_missing")
			}
			tasks++
		}
		if r.Header.Type == record.KindSession {
			sessions++
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil || tasks != 1 || sessions == 0 {
		return nil, errors.New("same_record_handoff_incomplete")
	}
	return ids, nil
}

func cliRetiredIDs(ctx context.Context, data string, ids []string) error {
	db, err := cliDB(ctx, data)
	if err != nil {
		return err
	}
	defer db.Close()
	if len(ids) == 0 {
		return errors.New("missing_bound_capture_ids")
	}
	for _, id := range ids {
		var state string
		var bodyRows int
		if db.QueryRowContext(ctx, "SELECT r.state,(SELECT count(*) FROM record_body b WHERE b.id=r.id) FROM record r WHERE r.id=?", id).Scan(&state, &bodyRows) != nil || state == "live" || bodyRows != 0 {
			return errors.New("bound_record_metadata_or_physical_body_retirement_incomplete")
		}
	}
	return nil
}

func cliNativeHandles(cfg installedConfig, installed, digest string, deletedOnly bool) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(cfg.Data, "custody-creator-*.json"))
	if err != nil {
		return nil, errors.New("owned_custody_receipts_unavailable")
	}
	var handles []string
	for _, path := range paths {
		raw, err := privateRead(path, 16384)
		if err != nil {
			return nil, errors.New("owned_custody_receipt_invalid")
		}
		var receipt struct {
			Version int    `json:"version"`
			Handle  string `json:"handle"`
			Image   string `json:"image"`
			Digest  string `json:"image_sha256"`
			Phase   string `json:"phase"`
		}
		if cliJSON(raw, &receipt) != nil || receipt.Version != 1 || !cliHex(receipt.Handle, 32) || filepath.Base(path) != "custody-creator-"+receipt.Handle+".json" || receipt.Image != installed || receipt.Digest != digest || (receipt.Phase != "bound" && receipt.Phase != "deleted") {
			return nil, errors.New("owned_custody_receipt_invalid")
		}
		if deletedOnly && receipt.Phase != "deleted" {
			return nil, errors.New("owned_native_creator_not_deleted")
		}
		handles = append(handles, receipt.Handle)
	}
	if len(handles) < 1 || len(handles) > 4 {
		return nil, errors.New("unexpected_owned_custody_inventory")
	}
	sort.Strings(handles)
	return handles, nil
}

func cliOwnedRoot(root string) error {
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || canonical != root || !filepath.IsAbs(root) {
		return errors.New("owned_root_identity_lost")
	}
	st, err := os.Lstat(root)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return errors.New("owned_root_identity_lost")
	}
	return nil
}

func cliRemoveAuthCopy(cfg installedConfig) error {
	path := filepath.Join(cfg.ClientConfig, "auth.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || parent != filepath.Dir(path) || !under(cfg.Root, path) {
		return errors.New("owned_auth_copy_path_unverified")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("owned_auth_copy_metadata_unavailable")
	}
	st, statErr := f.Stat()
	closed := f.Close()
	if statErr != nil || closed != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) || st.Size() > 1<<20 {
		return errors.New("owned_auth_copy_metadata_invalid")
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(st, current) || os.Remove(path) != nil {
		return errors.New("owned_auth_copy_cleanup_failed")
	}
	return nil
}

func cliRetiredRefusal(raw []byte) bool {
	var response struct {
		Error  any `json:"error"`
		Result struct {
			IsError bool                          `json:"isError"`
			Content []struct{ Type, Text string } `json:"content"`
		} `json:"result"`
	}
	return cliJSON(raw, &response) == nil && response.Error == nil && response.Result.IsError && len(response.Result.Content) == 1 && response.Result.Content[0].Type == "text" && response.Result.Content[0].Text == "identity_unavailable"
}

func (c *cliAcceptanceRun) cleanup(ctx context.Context, installedAttempted bool) error {
	if cliOwnedRoot(c.cfg.Root) != nil {
		return errors.New("cleanup_owned_root_unverified")
	}
	if cliRemoveAuthCopy(c.cfg) != nil {
		return errors.New("owned_auth_copy_cleanup_unverified")
	}
	if installedAttempted {
		// The actual CLI independently verifies the registration before manager
		// mutation. A changed/foreign same-label job is never booted out here.
		if _, err := os.Lstat(filepath.Join(c.cfg.Install, "install.json")); err == nil {
			raw, e := c.cli(ctx, "owned_client_uninstall", "clients", "uninstall", "--client", "codex", "--home", c.cfg.Home, "--config-root", c.cfg.ClientConfig, "--state-dir", c.cfg.Data, "--executable", c.installed)
			clear(raw)
			if e != nil {
				return errors.New("owned_client_uninstall_failed_resources_preserved")
			}
			raw, e = c.cli(ctx, "owned_product_uninstall", "uninstall", "--install-dir", c.cfg.Install)
			clear(raw)
			if e != nil {
				return errors.New("owned_product_uninstall_failed_resources_preserved")
			}
			if _, e = os.Lstat(filepath.Join(c.cfg.Install, "install.json")); !os.IsNotExist(e) {
				return errors.New("owned_product_uninstall_receipt_remains")
			}
			expectedImage := filepath.Join(c.cfg.Install, "bin", c.digest, "telara-memory")
			deleted, e := cliNativeHandles(c.cfg, expectedImage, c.digest, true)
			if e != nil {
				return errors.New("owned_native_cleanup_receipt_incomplete_resources_preserved")
			}
			for _, handle := range c.r.NativeHandles {
				index := sort.SearchStrings(deleted, handle)
				if index == len(deleted) || deleted[index] != handle {
					return errors.New("owned_native_cleanup_inventory_changed_resources_preserved")
				}
			}
			if c.requireAbsentService(ctx) != nil {
				return errors.New("owned_service_cleanup_absence_unproven_resources_preserved")
			}
			c.r.Checks["native_cleanup"] = "Actual CLI uninstall settled; every owned creator receipt deleted; exact service label absent"
		} else {
			// An interrupted install may have native creator evidence even before
			// install.json. Never delete that recovery metadata on an ambiguity.
			if paths, _ := filepath.Glob(filepath.Join(c.cfg.Data, "custody-creator-*.json")); len(paths) != 0 {
				return errors.New("partial_native_install_preserved")
			}
		}
	}
	if err := os.RemoveAll(c.cfg.Root); err != nil {
		return errors.New("owned_root_remove_failed")
	}
	if _, err := os.Lstat(c.cfg.Root); !os.IsNotExist(err) {
		return errors.New("owned_root_remains")
	}
	return nil
}

// This separate opt-in path executes the actual product command dispatcher.
// It never installs the Go test image or uses observedBackend/daemon.Call.
// An occupied default label is a hard refusal, including today's preserved
// hosted profile. Run only after root selects an isolated execution context.
func TestRepositoryCLIInstalledCodexSameSession(t *testing.T) {
	if !*repositoryCLIOptIn {
		t.Skip("explicit -e2e-repository-product-cli required")
	}
	r := cliAcceptanceReceipt{Mode: "actual_product_cli_codex_same_session", Verdict: "UNVERIFIED", Cleanup: "NOT_NEEDED", Revoke: "NOT_RUN", Refusal: "NOT_RUN", Started: time.Now().UTC(), Checks: map[string]string{}, VersionEvidence: "InstallVersionLabel is operator supplied, not verified binary version; executable SHA/build-info and root build receipt are separate evidence"}
	c := cliAcceptanceRun{r: &r, source: *repositoryCLIBinary}
	installedAttempted, captureComplete := false, false
	defer func() {
		if c.cfg.Root != "" {
			if *repositoryCLIRetain && captureComplete && !t.Failed() {
				// Auth copies never survive the retained profile handoff.
				auth := filepath.Join(c.cfg.ClientConfig, "auth.json")
				if err := cliRemoveAuthCopy(c.cfg); err != nil {
					r.Cleanup = "FAIL_RESOURCES_PRESERVED"
					t.Error("retained_auth_copy_cleanup_failed")
				} else if _, err = os.Lstat(auth); !os.IsNotExist(err) || cliOwnedRoot(c.cfg.Root) != nil {
					r.Cleanup = "FAIL_RESOURCES_PRESERVED"
					t.Error("retained_profile_ownership_or_auth_cleanup_failed")
				} else {
					r.Cleanup = "RETAINED_PENDING_ROOT_HOSTED_AND_FINAL_CLEANUP"
					r.Revoke = "PENDING_ROOT_AFTER_SAME_RECORD_HOSTED_PROOF"
					r.Refusal = "PENDING_ROOT_AFTER_SAME_RECORD_HOSTED_PROOF"
					r.Checks["handoff"] = "Exact live record IDs retained; no hosted or cleanup PASS claim"
				}
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 2**childTimeout)
				err := c.cleanup(ctx, installedAttempted)
				cancel()
				if err != nil {
					r.Cleanup = "FAIL_RESOURCES_PRESERVED"
					t.Error("owned_cli_cleanup_failed")
				} else {
					r.Cleanup = "PASS_OWNED_PROFILE_REMOVED_BY_CLI_THEN_EXACT_ROOT_REMOVED"
				}
			}
		}
		if t.Failed() {
			r.Verdict = "FAIL"
			if !installedAttempted && r.Cleanup != "FAIL_RESOURCES_PRESERVED" {
				r.Verdict = "BLOCKED_PREFLIGHT"
			}
		} else {
			r.Verdict = "PASS_ACTUAL_CLI_CAPTURE_ONLY"
		}
		if *resultsDir != "" && validateResultsDir(*resultsDir) == nil && cliOwnedRoot(*resultsDir) == nil {
			raw, err := json.MarshalIndent(r, "", "  ")
			if err != nil || privateWrite(filepath.Join(*resultsDir, "repository-product-cli-"+nonce()+".json"), append(raw, '\n')) != nil {
				t.Error("safe_cli_receipt_write_failed")
			}
		}
	}()
	fail := func(stage string) { r.Failure = stage; t.Fatal(stage) }
	s := specFor("codex")
	if *dryRun || *rawChildOutput != "" || *resultsDir == "" || validateResultsDir(*resultsDir) != nil || cliOwnedRoot(*resultsDir) != nil || s.auth == nil || *s.auth == "" || s.executable == nil || *s.executable == "" || *repositoryCLIBinary == "" || *repositoryCLIBuildReceipt == "" || os.Getuid() != os.Geteuid() {
		fail("explicit_private_cli_vendor_auth_and_receipt_inputs_required")
	}
	remote := *repositoryCLIRemote
	r.RemoteSource = "EXPLICIT_OWNER_SELECTED_CANONICAL_REMOTE"
	if remote == "" {
		if *repositoryCLIRetain {
			fail("retained_handoff_requires_explicit_canonical_repository_remote")
		}
		remote = "example.invalid/owner/" + nonce()
		r.RemoteSource = "SYNTHETIC_COMPLETE_LOCAL_LIFECYCLE_ONLY"
	}
	remoteID, err := cliRepositoryRemote(remote)
	if err != nil {
		fail("explicit_canonical_repository_remote_invalid")
	}
	r.CanonicalRemote, r.Repo = remote, remoteID
	build, receiptHash, moduleVersion, err := cliReadBuildReceipt(*repositoryCLIBuildReceipt, c.source)
	if err != nil {
		fail("actual_product_build_receipt_validation_failed")
	}
	r.Build, r.BuildReceiptSHA256, r.ActualExecutableSHA256, r.ActualGoVersion, r.ActualCommandPath, r.ActualModuleVersion = build, receiptHash, build.ExecutableSHA256, build.GoVersion, build.CommandPath, moduleVersion
	c.digest = build.ExecutableSHA256
	binary, err := filepath.EvalSymlinks(*s.executable)
	if err != nil || !filepath.IsAbs(binary) {
		fail("explicit_vendor_binary_invalid")
	}
	realHome, err := os.UserHomeDir()
	if err != nil || codeRoot(binary) == realHome || under(codeRoot(binary), realHome) {
		fail("vendor_code_exception_too_broad")
	}
	parent := *tempParent
	if parent == "" {
		fail("explicit_private_short_temporary_parent_required")
	}
	canonical, err := filepath.EvalSymlinks(parent)
	if err != nil || canonical != parent || parent == realHome || under(realHome, parent) || cliOwnedRoot(parent) != nil {
		fail("temporary_parent_not_isolated")
	}
	root, err := os.MkdirTemp(parent, "mc-")
	if err != nil {
		fail("owned_temporary_root_creation_failed")
	}
	c.cfg = installedConfig{Root: root, Home: filepath.Join(root, "home"), Data: filepath.Join(root, "data"), Run: filepath.Join(root, "run"), Client: "codex"}
	c.cfg.Keychain = filepath.Join(root, "unused-sandbox-denial.keychain")
	c.cfg.ClientConfig = filepath.Join(c.cfg.Home, ".codex")
	c.cfg.Install = filepath.Join(c.cfg.Home, "Library", "Application Support", "telara-memory-install")
	for _, path := range []string{c.cfg.Home, c.cfg.ClientConfig, filepath.Join(c.cfg.Home, "tmp"), filepath.Join(c.cfg.Home, "project")} {
		if os.MkdirAll(path, 0700) != nil {
			fail("owned_layout_creation_failed")
		}
	}
	if cliOwnedRoot(root) != nil {
		fail("owned_root_verification_failed")
	}
	if _, err = isolatedPaths(c.cfg); err != nil {
		fail("private_unix_socket_paths_too_long")
	}
	c.env = isolatedEnv(c.cfg.Home, c.cfg.ClientConfig, s)
	r.Paths = map[string]string{"root": root, "home": c.cfg.Home, "data": c.cfg.Data, "run": c.cfg.Run, "install": c.cfg.Install, "client_config": c.cfg.ClientConfig, "launchd_label": "dev.telara.memory"}
	ctx, cancel := context.WithTimeout(context.Background(), 10**childTimeout)
	defer cancel()
	// This guard precedes auth copying, native custody and install mutation.
	if err = c.requireAbsentService(ctx); err != nil {
		fail(err.Error())
	}
	if copyAuth(*s.auth, filepath.Join(c.cfg.ClientConfig, "auth.json")) != nil {
		fail("explicit_auth_copy_failed")
	}
	installedAttempted = true
	raw, err := c.cli(ctx, "product_install", "install", "--source", c.source, "--sha256", c.digest, "--version", build.InstallVersionLabel, "--data-dir", c.cfg.Data, "--run-dir", c.cfg.Run, "--install-dir", c.cfg.Install)
	if err != nil {
		fail("actual_product_install_failed")
	}
	installation, err := cliInstallRecord(raw)
	clear(raw)
	if err != nil || installation.Home != c.cfg.Home || installation.Dir != c.cfg.Install || installation.DataDir != c.cfg.Data || installation.RunDir != c.cfg.Run || installation.SHA256 != c.digest || installation.Version != build.InstallVersionLabel || installation.Label != "dev.telara.memory" || installation.UserID != strconv.Itoa(os.Getuid()) || verifyShimImage(c.cfg, installation.Executable) != nil {
		fail("actual_installed_receipt_mismatch")
	}
	c.installed = installation.Executable
	if digest, err := cliImageDigest(c.installed); err != nil || digest != c.digest {
		fail("actual_installed_image_mismatch")
	}
	raw, err = c.cli(ctx, "product_status", "status", "--install-dir", c.cfg.Install)
	if err != nil {
		fail("actual_installed_daemon_unavailable")
	}
	statusRecord, err := cliInstallRecord(raw)
	clear(raw)
	if err != nil || statusRecord != installation {
		fail("actual_status_receipt_changed")
	}
	raw, err = c.cli(ctx, "product_clients_install", "clients", "install", "--client", "codex", "--home", c.cfg.Home, "--config-root", c.cfg.ClientConfig, "--state-dir", c.cfg.Data, "--executable", c.installed)
	var report clients.Report
	if err != nil || cliJSON(raw, &report) != nil || report.Client != clients.Codex || mergeReport(c.cfg, report) != nil {
		clear(raw)
		fail("actual_product_client_plan_failed")
	}
	clear(raw)
	raw, err = c.cli(ctx, "product_clients_status", "clients", "status", "--client", "codex", "--home", c.cfg.Home, "--config-root", c.cfg.ClientConfig, "--state-dir", c.cfg.Data, "--executable", c.installed)
	clear(raw)
	if err != nil {
		fail("actual_product_client_status_failed")
	}
	project := filepath.Join(c.cfg.Home, "project")
	profile := filepath.Join(root, "client.sb")
	// The public CLI's default install lives below its selected home. Retain
	// the existing client sandbox and further deny writes to product control
	// paths inside that home; the vendor may edit only its disposable settings.
	quote := func(path string) string { raw, _ := json.Marshal(path); return string(raw) }
	profileText := clientProfile(realHome, binary, c.cfg) + "(deny file-write* (subpath " + quote(c.cfg.Install) + ") (subpath " + quote(filepath.Join(c.cfg.Home, "Library", "LaunchAgents")) + "))\n"
	if privateWrite(profile, []byte(profileText)) != nil {
		fail("mandatory_vendor_sandbox_profile_failed")
	}
	denied := filepath.Join(root, "denied-read", "canary")
	if privateWrite(denied, []byte("owned synthetic denied read")) != nil {
		fail("owned_sandbox_canary_failed")
	}
	out, stderr, probeErr := c.command(ctx, "sandbox_owned_read_denied", project, c.env, nil, "/usr/bin/sandbox-exec", "-f", profile, "/bin/cat", denied)
	clear(out)
	clear(stderr)
	if probeErr == nil {
		fail("mandatory_sandbox_read_denial_missing")
	}
	out, stderr, probeErr = c.command(ctx, "sandbox_owned_write_denied", project, c.env, nil, "/usr/bin/sandbox-exec", "-f", profile, "/usr/bin/touch", filepath.Join(root, "denied-write"))
	clear(out)
	clear(stderr)
	if probeErr == nil {
		fail("mandatory_sandbox_write_denial_missing")
	}
	for _, protected := range []string{c.cfg.Install, filepath.Join(c.cfg.Home, "Library", "LaunchAgents")} {
		out, stderr, probeErr = c.command(ctx, "sandbox_owned_install_control_write_denied", project, c.env, nil, "/usr/bin/sandbox-exec", "-f", profile, "/usr/bin/touch", filepath.Join(protected, "denied-synthetic-write"))
		clear(out)
		clear(stderr)
		if probeErr == nil {
			fail("mandatory_sandbox_install_control_write_denial_missing")
		}
	}
	clientEnv, err := isolatedClientEnv(c.cfg.Home, c.cfg.ClientConfig, s)
	if err != nil {
		fail("isolated_vendor_environment_failed")
	}
	launch := func(stage string, args []string) ([]byte, error) {
		out, stderr, err := c.command(ctx, stage, project, clientEnv, nil, "/usr/bin/sandbox-exec", append([]string{"-f", profile, binary}, args...)...)
		clear(stderr)
		if err != nil {
			clear(out)
			return nil, errors.New("actual_vendor_execution_failed")
		}
		return out, nil
	}
	out, err = launch("actual_vendor_version", []string{"--version"})
	version := strings.TrimSpace(string(out))
	clear(out)
	if err != nil || !regexp.MustCompile(`^codex-cli [0-9][A-Za-z0-9.+_-]{0,63}$`).MatchString(version) {
		fail("actual_vendor_version_unverified")
	}
	r.Checks["vendor_version"] = version
	originURL := "https://" + remote + ".git"
	for _, args := range [][]string{{"init", "--quiet"}, {"remote", "add", "origin", originURL}} {
		out, stderr, err = c.command(ctx, "owned_git_repository_setup", project, c.env, nil, "/usr/bin/git", args...)
		clear(out)
		clear(stderr)
		if err != nil {
			fail("owned_git_repository_setup_failed")
		}
	}
	out, stderr, err = c.command(ctx, "owned_git_remote_read", project, c.env, nil, "/usr/bin/git", "remote", "get-url", "origin")
	clear(stderr)
	actualOrigin := string(out)
	clear(out)
	if err != nil || actualOrigin != originURL+"\n" {
		fail("owned_git_remote_invalid")
	}
	goal, phaseB := nonce(), nonce()
	promptA := "Reply CAPTURE_CANARY " + goal + " " + canary + ". Do not call tools or read files. End this turn."
	out, err = launch("actual_vendor_phase_a", clientArgs(s, promptA))
	if err != nil {
		fail("actual_native_phase_a_failed")
	}
	native, _, _, err := cliCodexEvents(out, "")
	clear(out)
	if err != nil {
		fail("actual_phase_a_native_identity_missing")
	}
	r.NativeSession = native
	// Native hook signals can still be settling after the vendor exits. Reading
	// through the actual installed MCP frontdoor drains them synchronously.
	time.Sleep(2100 * time.Millisecond)
	raw, err = c.readMCP(ctx, "", goal)
	clear(raw)
	if err != nil {
		fail("actual_cli_capture_drain_failed")
	}
	if _, err = waitCaptured(ctx, c.cfg.Data, "codex", native, goal); err != nil {
		fail("actual_unbound_native_capture_missing")
	}
	owner, machine, err := store.InstalledIdentity(c.cfg.Data)
	if err != nil || !record.IsKeyID(owner) || !record.IsUUIDv4(machine) {
		fail("actual_installed_identity_missing")
	}
	session, err := record.SessionKey("codex", "local", record.NativeGlobal, native, machine)
	if err != nil {
		fail("actual_native_session_key_invalid")
	}
	r.Owner, r.Machine, r.SessionKey = owner, machine, session
	raw, err = c.cli(ctx, "owner_repository_inspect", "repository", "inspect", "--install-dir", c.cfg.Install)
	var inspected store.RepositoryInspection
	if err != nil || cliJSON(raw, &inspected) != nil {
		clear(raw)
		fail("actual_owner_cli_inspect_failed")
	}
	clear(raw)
	for _, observation := range inspected.Observations {
		if observation.Session == session {
			if r.Observation != "" {
				fail("actual_session_observation_ambiguous")
			}
			r.Observation = observation.ID
		}
	}
	if !record.IsHex64(r.Observation) {
		fail("actual_current_signed_observation_missing")
	}
	raw, err = c.cli(ctx, "owner_repository_enroll", "repository", "enroll", "--install-dir", c.cfg.Install, "--observation", r.Observation, "--project-root", project, "--remote", remote)
	var enrolled disclosure.RepositoryContext
	if err != nil || cliJSON(raw, &enrolled) != nil || enrolled.State != "active" || !cliHex(enrolled.ID, 32) || !record.IsHex64(enrolled.Binding) {
		clear(raw)
		fail("actual_owner_cli_enroll_failed")
	}
	clear(raw)
	r.Binding, r.Context = enrolled.Binding, enrolled.ID
	actualID, err := record.RepoID(remote)
	if err != nil || actualID != r.Repo {
		fail("owned_repository_id_invalid")
	}
	// The vendor edits its own isolated TOML. No generic shared config merger.
	for _, args := range [][]string{{"mcp", "remove", "telara-memory"}, {"mcp", "add", "telara-memory", "--", c.installed, "shim", "--data-dir", c.cfg.Data, "--run-dir", c.cfg.Run, "--repository-context", enrolled.ID}} {
		out, err = launch("vendor_scoped_mcp_configuration", args)
		clear(out)
		if err != nil {
			fail("vendor_scoped_mcp_configuration_failed")
		}
	}
	promptB := "Resume this same session. Use only telara-memory MCP. Call telara_task_create exactly once with goal " + goal + ". Then call telara_task_list with query " + goal + " and mode detail to read back that exact task. Finally reply CAPTURE_CANARY " + phaseB + " " + canary + " and end this turn. Do not read files or use other tools."
	out, err = launch("actual_vendor_same_session_phase_b", repositoryResumeArgs(s, native, promptB))
	if err != nil {
		fail("actual_native_resume_failed")
	}
	resumed, created, listed, err := cliCodexEvents(out, goal)
	clear(out)
	if err != nil || resumed != native || created != listed {
		fail("actual_same_thread_mcp_create_readback_missing")
	}
	r.Task = created
	time.Sleep(2100 * time.Millisecond)
	raw, err = c.readMCP(ctx, enrolled.ID, goal)
	readBack := responseTask(raw, goal)
	clear(raw)
	if err != nil || readBack != created {
		fail("actual_bound_native_capture_drain_failed")
	}
	if err = repositoryNativeEvidence(ctx, c.cfg.Data, session, native, r.Repo, remote, r.Observation, goal, phaseB); err != nil {
		fail("actual_signed_same_session_capture_task_proof_failed")
	}
	if err = captureACK(ctx, c.cfg.Data, "codex", 2); err != nil {
		fail("actual_capture_durable_ack_missing")
	}
	r.RecordIDs, err = cliHandoffIDs(ctx, c.cfg.Data, r.Repo, created, goal, enrolled.Binding)
	if err != nil {
		fail("actual_signed_live_same_record_handoff_failed")
	}
	r.RecordState = "VERIFIED_LIVE_CAPTURE"
	r.NativeHandles, err = cliNativeHandles(c.cfg, c.installed, c.digest, false)
	if err != nil {
		fail("exact_owned_native_creator_evidence_missing")
	}
	r.Checks["actual_product_dispatch"] = "PASS real CLI install/client/repository commands and installed daemon/shim/native custody"
	r.Checks["same_record_capture"] = "PASS same native thread, successful actual MCP create/read-back, signed bound B-marker session/chunk and task, original unbound observation preserved, durable capture ACK"
	r.Checks["sandbox"] = "Existing mandatory vendor sandbox retained, synthetic owned file read/write denial observed; vendor securityd access remains denied"
	r.Checks["hosted"] = "PENDING ROOT; no hosted, sync, signed release or publication proof"
	if *repositoryCLIRetain {
		raw, err = c.cli(ctx, "retained_current_binding_inspect", "repository", "inspect", "--install-dir", c.cfg.Install)
		var current store.RepositoryInspection
		if err != nil || cliJSON(raw, &current) != nil {
			clear(raw)
			fail("retained_binding_currentness_unverified")
		}
		clear(raw)
		active := false
		for _, binding := range current.Bindings {
			if binding.ID == enrolled.Binding && binding.State == "active" && binding.Repo == r.Repo && binding.Session == session {
				active = true
			}
		}
		if !active {
			fail("retained_binding_not_active")
		}
		r.RecordState = "LIVE_RETAINED_FOR_ROOT_SAME_RECORD_HOSTED_PROOF"
	} else {
		raw, err = c.cli(ctx, "owner_repository_revoke", "repository", "revoke", "--install-dir", c.cfg.Install, "--binding", enrolled.Binding)
		clear(raw)
		if err != nil {
			fail("actual_owner_cli_revoke_failed")
		}
		refused, err := c.readMCP(ctx, enrolled.ID, goal)
		if err != nil || !cliRetiredRefusal(refused) {
			clear(refused)
			fail("actual_retired_context_not_refused")
		}
		clear(refused)
		if repositoryRetirementEvidence(ctx, c.cfg.Data, r.Observation, r.Repo) != nil {
			fail("actual_owner_cli_retirement_incomplete")
		}
		if cliRetiredIDs(ctx, c.cfg.Data, r.RecordIDs) != nil {
			fail("actual_owner_cli_physical_body_retirement_incomplete")
		}
		r.RecordState = "RETIRED_BODY_ROWS_ABSENT_ORIGINAL_UNBOUND_OBSERVATION_LIVE"
		r.Revoke, r.Refusal = "PASS_ACTUAL_OWNER_CLI", "PASS_ACTUAL_INSTALLED_SHIM_NO_FALLBACK"
	}
	captureComplete = true
}

func TestRepositoryCLIEventProofRejectsEchoesRetriesAndCrossThread(t *testing.T) {
	const native = "01990000-0000-4000-8000-000000000001"
	const task = "01990000-0000-4000-8000-000000000002"
	const goal = "synthetic-cli-goal"
	call := func(tool string) map[string]any {
		args := map[string]any{"goal": goal}
		if tool == "telara_task_list" {
			args = map[string]any{"query": goal}
		}
		return map[string]any{"type": "item.completed", "item": map[string]any{"type": "mcp_tool_call", "server": "telara-memory", "tool": tool, "arguments": args, "status": "completed", "error": nil, "result": map[string]any{"isError": false, "content": []any{map[string]any{"type": "text", "text": "task_id " + task + " goal " + goal}}}}}
	}
	for _, mode := range []string{"positive", "echo-only", "duplicate-create", "list-before-create", "foreign-server", "failed-result", "other-goal", "second-thread", "after-completion"} {
		t.Run(mode, func(t *testing.T) {
			created, listed := call("telara_task_create"), call("telara_task_list")
			events := []map[string]any{{"type": "thread.started", "thread_id": native}, created, listed, {"type": "turn.completed"}}
			switch mode {
			case "echo-only":
				created["item"].(map[string]any)["type"] = "agent_message"
			case "duplicate-create":
				events = append(events[:2], append([]map[string]any{created}, events[2:]...)...)
			case "list-before-create":
				events[1], events[2] = events[2], events[1]
			case "foreign-server":
				created["item"].(map[string]any)["server"] = "hosted"
			case "failed-result":
				created["item"].(map[string]any)["result"].(map[string]any)["isError"] = true
			case "other-goal":
				created["item"].(map[string]any)["arguments"] = map[string]any{"goal": "other"}
			case "second-thread":
				events = append(events, map[string]any{"type": "thread.started", "thread_id": "01990000-0000-4000-8000-000000000003"})
			case "after-completion":
				events = append(events[:1], append([]map[string]any{{"type": "turn.completed"}}, events[1:3]...)...)
			}
			var raw bytes.Buffer
			for _, event := range events {
				b, _ := json.Marshal(event)
				raw.Write(b)
				raw.WriteByte('\n')
			}
			n, id, readBack, err := cliCodexEvents(raw.Bytes(), goal)
			if mode == "positive" {
				if err != nil || n != native || id != task || readBack != task {
					t.Fatal("actual event fixture rejected")
				}
			} else if err == nil {
				t.Fatal("unproven native MCP evidence accepted")
			}
		})
	}
}

func TestRepositoryCLIRetiredRefusalRequiresExactProductReason(t *testing.T) {
	for _, mode := range []string{"retired", "generic-rpc-error", "malformed", "successful-empty", "other-reason"} {
		raw := []byte(`{"result":{"isError":true,"content":[{"type":"text","text":"identity_unavailable"}]}}`)
		switch mode {
		case "generic-rpc-error":
			raw = []byte(`{"error":{"message":"invalid_arguments"}}`)
		case "malformed":
			raw = []byte(`not json`)
		case "successful-empty":
			raw = []byte(`{"result":{"isError":false,"content":[]}}`)
		case "other-reason":
			raw = []byte(`{"result":{"isError":true,"content":[{"type":"text","text":"invalid_arguments"}]}}`)
		}
		if cliRetiredRefusal(raw) != (mode == "retired") {
			t.Fatal("retirement refusal reason boundary changed", mode)
		}
	}
}

func TestRepositoryCLICanonicalRemoteRequiresExactOwnerAuthority(t *testing.T) {
	// Public metadata projected by root from the existing governed fixture.
	// No credential receipt or hosted configuration is read by this test.
	const canonical = "github.com/Telara-Labs/teng-3657-hosted-acceptance-465d5a2d-cdb2-49f5-8f0e-b15cc906e643"
	const expected = "r1:a651b67a04d4ec1a27a439cab9faf5a833c5bd700a6d87b076dff8832b258b8e"
	if actual, err := cliRepositoryRemote(canonical); err != nil || actual != expected {
		t.Fatal("standing fixture canonical identity mismatch")
	}
	for _, value := range []string{"", "https://" + canonical, "https://user:credential@" + canonical, "git@github.com:Telara-Labs/repo.git", canonical + ".git", canonical + "/", canonical + "?query=1", canonical + "#fragment", canonical + "?", "GitHub.com/Telara-Labs/repo", "github.com/Telara-Labs/%72epo", "github.com/Telara-Labs/../repo", "github.com//repo", "github.com:443/Telara-Labs/repo", "github.com/Telara-Labs/repo\n", "github.com/Telara-Labs\\repo"} {
		if _, err := cliRepositoryRemote(value); err == nil {
			t.Fatal("noncanonical remote accepted")
		}
	}
}
