//go:build e2e && darwin

package clients_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
)

var debugRun = flag.Bool("e2e-debug", false, "Record allowlisted peer proof diagnostics without credentials or request bodies")
var dryRun = flag.Bool("e2e-dry-run", false, "Exercise native node lifecycle with synthetic MCP sessions and hook input; never launch clients")
var childTimeout = flag.Duration("e2e-child-timeout", 90*time.Second, "Deadline for every child process")
var rawChildOutput = flag.String("e2e-raw-child-output", "", "Operator-only: existing private directory that receives raw child output files for debugging")
var resultsDir = flag.String("e2e-results-dir", "", "Existing status directory for private JSON receipts; required for lifecycle tests")
var prebuiltNativeHelper = flag.String("e2e-native-helper", "", "Explicit CI-built private native utility")
var prebuiltNativeHelperSHA = flag.String("e2e-native-helper-sha256", "", "Authenticated CI artifact SHA256 for native utility")

var tempParent = flag.String("e2e-temp-parent", "", "Optional existing private temporary parent; paths must stay short enough for a macOS Unix socket")

type clientSpec struct {
	name, binary, configVariable, configRelative, authName string
	auth, executable, model                                *string
}

var specs = []clientSpec{
	{"claude", "claude", "CLAUDE_CONFIG_DIR", ".claude", ".credentials.json", flag.String("e2e-claude-auth", "", "Operator-supplied Claude credentials JSON"), flag.String("e2e-claude-bin", "", "Explicit installed Claude executable"), flag.String("e2e-claude-model", "", "Optional Claude model")},
	{"codex", "codex", "CODEX_HOME", ".codex", "auth.json", flag.String("e2e-codex-auth", "", "Operator-supplied Codex auth JSON"), flag.String("e2e-codex-bin", "", "Explicit installed Codex executable"), flag.String("e2e-codex-model", "", "Optional Codex model")},
	{"cursor", "cursor-agent", "CURSOR_CONFIG_DIR", ".cursor", "auth.json", flag.String("e2e-cursor-auth", "", "Operator-supplied Cursor auth JSON"), flag.String("e2e-cursor-bin", "", "Explicit installed Cursor executable"), flag.String("e2e-cursor-model", "", "Optional Cursor model")},
	{"pi", "pi", "PI_CODING_AGENT_DIR", ".pi/agent", "auth.json", flag.String("e2e-pi-auth", "", "Operator-supplied Pi auth JSON"), flag.String("e2e-pi-bin", "", "Explicit installed Pi executable"), flag.String("e2e-pi-model", "", "Optional Pi model")},
}

type observation struct {
	At        time.Time       `json:"at"`
	Phase     string          `json:"phase"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	Response  json.RawMessage `json:"response"`
	Success   bool            `json:"success"`
}
type hookObservation struct {
	At                            time.Time
	Phase, Client, Event, Session string
	Result                        clients.HookResult
}
type receipt struct {
	Client       string             `json:"client"`
	Mode         string             `json:"mode"`
	Verdict      string             `json:"verdict"`
	Started      time.Time          `json:"started"`
	Seconds      float64            `json:"seconds"`
	Version      string             `json:"version"`
	Paths        map[string]string  `json:"isolated_paths"`
	Timings      map[string]float64 `json:"timings_seconds"`
	Calls        []observation      `json:"observed_calls"`
	Hooks        []hookObservation  `json:"observed_hooks"`
	SessionIDs   []string           `json:"session_record_ids"`
	Checks       map[string]string  `json:"checks"`
	Failure      string             `json:"failure,omitempty"`
	Cleanup      string             `json:"cleanup"`
	Diagnostics  []proofDiagnostic  `json:"proof_diagnostics,omitempty"`
	FailureCodes []string           `json:"failure_reason_codes,omitempty"`
}

func nonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "clientprobe" + hex.EncodeToString(b[:])
}

func under(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func privateWrite(path string, data []byte) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("private destination must be absolute and clean")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || parent != filepath.Dir(path) {
		return errors.New("private destination has symlinked parent")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	return errors.Join(werr, f.Close())
}

func privateRead(path string, limit int64) ([]byte, error) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || parent != filepath.Dir(path) {
		return nil, errors.New("private input has symlinked parent")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > limit || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return nil, errors.New("invalid private input")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		clear(b)
		return nil, errors.New("private input exceeds bound")
	}
	return b, nil
}

// Only the operator's explicit input is read. No discovery, credential lookup,
// symlinks, execution, or interpolation is permitted in this path.
func copyAuth(source, dest string) error {
	if !filepath.IsAbs(source) || filepath.Clean(source) != source {
		return errors.New("auth source must be an absolute clean path")
	}
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil || resolved != source {
		return errors.New("auth source must have no symlink components")
	}
	f, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("cannot open operator auth file")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 1<<20 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return errors.New("auth input must be a private regular file under 1 MiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	defer clear(b)
	if err != nil || len(b) > 1<<20 || !json.Valid(b) || !bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		return errors.New("auth input must be a JSON object under 1 MiB")
	}
	return privateWrite(dest, b)
}

// An allowlist prevents inherited tokens, client homes, shell startup hooks,
// SDK overrides and nested-session settings from entering disposable clients.
func isolatedEnv(home, config string, s clientSpec) []string {
	env := []string{"PATH=/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + home,
		"TMPDIR=" + filepath.Join(home, "tmp"), "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"XDG_CACHE_HOME=" + filepath.Join(home, ".cache"), "XDG_DATA_HOME=" + filepath.Join(home, ".local/share"),
		s.configVariable + "=" + config, "LANG=en_US.UTF-8"}
	// Luis approved this existing Cursor vendor option for the disposable test
	// only. The real native keychain remains denied by the sandbox.
	if s.name == "cursor" {
		env = append(env, "AGENT_CLI_CREDENTIAL_STORE=file")
	}
	return env
}

// Only the disposable Cursor client receives the operator-approved vendor API
// key setting. Installed node/helper processes keep the ordinary isolated env.
func isolatedClientEnv(home, config string, s clientSpec) ([]string, error) {
	env := isolatedEnv(home, config, s)
	if s.name != "cursor" {
		return env, nil
	}
	raw, err := privateRead(filepath.Join(config, "auth.json"), 1<<20)
	if err != nil {
		return nil, errors.New("explicit Cursor auth file unavailable")
	}
	defer clear(raw)
	var auth struct {
		APIKey string `json:"apiKey"`
	}
	if json.Unmarshal(raw, &auth) != nil {
		return nil, errors.New("explicit Cursor auth file invalid")
	}
	if auth.APIKey == "" {
		return env, nil
	}
	if len(auth.APIKey) < 16 || len(auth.APIKey) > 4096 || strings.ContainsAny(auth.APIKey, " \t\r\n\x00") {
		return nil, errors.New("explicit Cursor API key invalid")
	}
	return append(env, "CURSOR_API_KEY="+auth.APIKey), nil
}

type cappedBuffer struct {
	buffer   bytes.Buffer
	overflow bool
}

// Keep the buffer named. Embedding bytes.Buffer would promote ReadFrom and let
// os/exec's io.Copy bypass Write and its output cap.
func (b *cappedBuffer) Len() int      { return b.buffer.Len() }
func (b *cappedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len()+n > 8<<20 {
		b.overflow = true
	}
	if left := (8 << 20) - b.Len(); left > 0 {
		if len(p) > left {
			p = p[:left]
		}
		_, _ = b.buffer.Write(p)
	}
	return n, nil
}

func command(ctx context.Context, dir string, env []string, exe string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir, cmd.Env = dir, env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	return cmd
}

func run(ctx context.Context, dir string, env []string, input []byte, exe string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, *childTimeout)
	defer cancel()
	cmd := command(ctx, dir, env, exe, args...)
	var out, diagnostic cappedBuffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(input), &out, &diagnostic
	err := cmd.Run()
	// Kill descendants even after a successful parent exit (MCP/hook children).
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	if *rawChildOutput != "" {
		// Operator-only debugging on the operator's own machine: raw child output
		// can contain anything the client printed, so it goes to a private file
		// in an operator-chosen directory and never into receipts or logs.
		name := fmt.Sprintf("%s-%d.out", filepath.Base(exe), time.Now().UnixNano())
		_ = os.WriteFile(filepath.Join(*rawChildOutput, name), append(append(append([]byte(nil), out.Bytes()...), "\n--- stderr ---\n"...), diagnostic.Bytes()...), 0600)
	}
	codes := childFailureCodes(exe, diagnostic.Bytes())
	clear(diagnostic.Bytes())
	if out.overflow || diagnostic.overflow {
		clear(out.Bytes())
		return nil, &childFailure{Codes: append(codes, string(reasonChildOutputLimit)), Debug: *debugRun, TimedOut: ctx.Err() != nil}
	}
	if err != nil {
		clear(out.Bytes())
		return nil, &childFailure{Codes: codes, Debug: *debugRun, TimedOut: ctx.Err() != nil}
	}
	return out.Bytes(), nil
}

func clientArgs(s clientSpec, prompt string) []string {
	var args []string
	switch s.name {
	case "claude":
		args = []string{"-p", "--output-format", "stream-json", "--verbose", "--max-turns", "6", "--allowedTools", "mcp__telara-memory__telara_task_create,mcp__telara-memory__telara_task_list", "--tools", "", prompt}
	case "codex":
		// Account-level apps (a hosted Telara connector among them) expose tools
		// with the same names; the run must exercise only the local node.
		args = []string{"exec", "--json", "--skip-git-repo-check", "--sandbox", "read-only", "-c", "features.apps=false",
			// The isolated config holds only the hooks the adapter just wrote, which
			// is the vetted-automation case Codex documents for this flag.
			"--dangerously-bypass-hook-trust",
			// Headless exec refuses unapproved MCP calls; approve only this server's two tools.
			"-c", `mcp_servers.telara-memory.default_tools_approval_mode="approve"`,
			"-c", `mcp_servers.telara-memory.enabled_tools=["telara_task_create","telara_task_list"]`, prompt}
	case "cursor":
		// Only disposable synthetic workspaces are passed by this harness.
		args = []string{"--print", "--trust", "--approve-mcps", "--output-format", "stream-json", prompt}
	case "pi":
		args = []string{"--print", "--mode", "json", prompt}
	}
	if s.model != nil && *s.model != "" {
		args = append(args, "--model", *s.model)
	}
	return args
}

// sandbox-exec is mandatory for native clients. HOME alone cannot redirect
// Security.framework, nor does it restrict a client's accidental absolute path.
func codeRoot(binary string) string {
	if i := strings.Index(binary, "/node_modules/"); i >= 0 {
		return binary[:i+len("/node_modules")]
	}
	return filepath.Dir(binary)
}

// Permit traversal/stat of install ancestors without granting directory listings
// or file contents elsewhere in the real home. Full reads cover only codeRoot.
func installationMetadata(realHome, code string) string {
	var rules strings.Builder
	for p := filepath.Dir(code); p == realHome || under(realHome, p); p = filepath.Dir(p) {
		b, _ := json.Marshal(p)
		fmt.Fprintf(&rules, "(allow file-read-metadata (literal %s))\n", b)
		if p == realHome {
			break
		}
	}
	return rules.String()
}
func clientProfile(realHome, binary string, cfg installedConfig) string {
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	return "(version 1)\n(allow default)\n" +
		"(deny file-read* file-write* (subpath " + q(realHome) + ") (subpath " + q(filepath.Join(cfg.Root, "denied-read")) + "))\n" +
		"(allow file-read* file-map-executable (subpath " + q(codeRoot(binary)) + "))\n" +
		installationMetadata(realHome, codeRoot(binary)) +
		"(allow file-read* file-map-executable (subpath \"/System/Library\") (subpath \"/usr/lib\") (subpath \"/Library/Apple/System/Library\") (subpath \"/opt/homebrew\"))\n" +
		"(allow file-read* file-map-executable (subpath " + q(cfg.Install) + "))\n" +
		"(allow process-exec process-fork)\n" +
		"(allow network*)\n" +
		"(deny file-write* (subpath " + q(cfg.Root) + "))\n" +
		"(allow file-read* file-write* (subpath " + q(cfg.Home) + "))\n" +
		"(allow file-read* file-write* (subpath " + q(cfg.ClientConfig) + ") (subpath " + q(filepath.Join(cfg.Home, "tmp")) + "))\n" +
		"(allow file-write* (subpath " + q(filepath.Join(cfg.Data, "spool")) + "))\n" +
		"(allow file-write* (regex " + q("^"+regexp.QuoteMeta(filepath.Join(cfg.Data, "observations", "hook-"))+"[a-z0-9]+[.]json$") + "))\n" +
		// Login keychain items stay hidden because the real home is read-denied.
		// SecurityServer must stay reachable: clients need it for TLS trust.
		"(deny mach-lookup (global-name \"com.apple.securityd\") (global-name \"com.apple.secd\") (global-name \"com.apple.security.agent\"))\n" +
		"(deny file-read* file-write* (subpath \"/Library/Keychains\"))\n" +
		// A file-based keychain the process can read is opened in process; the
		// isolated custody keychain lives under the root, outside the real home.
		"(deny file-read* file-write* (literal " + q(cfg.Keychain) + ") (literal " + q(cfg.Keychain+"-db") + "))\n"
}

func validateResultsDir(dir string) error {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != dir {
		return errors.New("results directory must be existing, absolute and canonical")
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() || !filepath.IsAbs(dir) {
		return errors.New("invalid results directory")
	}
	if st.Mode().Perm()&0022 != 0 {
		return errors.New("results directory must not be writable by other users")
	}
	return nil
}
func writeReceipt(dir string, r receipt) error {
	if err := validateResultsDir(dir); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return privateWrite(filepath.Join(dir, "clients-e2e-"+r.Client+"-"+nonce()+".json"), append(b, '\n'))
}

func TestInstalledClients(t *testing.T) {
	if *childTimeout <= 0 || *childTimeout > 5*time.Minute {
		t.Fatal("child timeout must be positive and at most 5m")
	}
	for _, s := range specs {
		t.Run(s.name, func(t *testing.T) { runClient(t, s) })
	}
}
