package clients

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/Telara-Labs/TAP-Runtime/discover/redact"
)

type Client string

const (
	Claude     Client = "claude"
	Codex      Client = "codex"
	Cursor     Client = "cursor"
	Pi         Client = "pi"
	ServerName        = "telara-memory"
)

var (
	ErrOptions   = errors.New("invalid_client_options")
	ErrUnsafe    = errors.New("unsafe_client_path")
	ErrConflict  = errors.New("client_entry_conflict")
	ErrMalformed = errors.New("malformed_client_config")
	ErrBusy      = errors.New("client_install_busy")
)

// Options uses absolute paths, never shell fragments. GOOS enables foreign-OS
// previews; mutation requires the running OS. Home is the client's user home.
// ConfigRoot optionally selects an existing vendor-supported user config root
// (Claude .claude directory, Codex home, Cursor .cursor, or Pi agent directory).
// No option changes project settings, managed policy, or hook trust.
type Options struct {
	Client     Client
	Home       string
	GOOS       string
	ConfigRoot string
	Executable string
	StateDir   string
	Print      bool
}

type Location struct {
	MCP         string
	Hooks       string
	Transcripts string
	Extension   string
}

// Change contains only our snippet. It never returns unrelated config bytes,
// which may contain credentials. Manual snippets must be merged by the user.
type Change struct {
	Path    string
	Format  string
	Snippet string
	Action  string
	Reason  string
}

type Report struct {
	Client       Client
	Location     Location
	Installation Detection
	Changes      []Change
	MCP          string
	Capture      string
	Gaps         []string
	CaptureGaps  []CaptureGap
}

func validClient(c Client) bool { return c == Claude || c == Codex || c == Cursor || c == Pi }
func safePath(s string) bool {
	if s == "" || len(s) > 4096 || redact.Redact(s) != s || strings.ContainsAny(s, "$`%!\"'\n\r\x00<>|&;(){}") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

func joinOS(platform, base string, parts ...string) string {
	sep := "/"
	if platform == "windows" {
		sep = `\`
	}
	return strings.TrimRight(base, `/\`) + sep + strings.Join(parts, sep)
}
func absoluteOS(platform, p string) bool {
	if !safePath(p) {
		return false
	}
	if platform == "windows" {
		if len(p) < 3 || p[1:3] != `:\` || !((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) || strings.Contains(p[2:], ":") {
			return false
		}
	} else if !strings.HasPrefix(p, "/") || strings.Contains(p, `\`) {
		return false
	}
	for _, part := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func resolve(o Options) (Options, Location, error) {
	if !validClient(o.Client) {
		return o, Location{}, ErrOptions
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	if o.GOOS != "darwin" && o.GOOS != "linux" && o.GOOS != "windows" {
		return o, Location{}, ErrOptions
	}
	if o.Home == "" {
		o.Home, _ = os.UserHomeDir()
		if o.ConfigRoot == "" && o.GOOS == runtime.GOOS {
			switch o.Client {
			case Claude:
				o.ConfigRoot = os.Getenv("CLAUDE_CONFIG_DIR")
			case Codex:
				o.ConfigRoot = os.Getenv("CODEX_HOME")
			case Pi:
				o.ConfigRoot = os.Getenv("PI_CODING_AGENT_DIR")
			}
		}
	}
	if !absoluteOS(o.GOOS, o.Home) {
		return o, Location{}, ErrOptions
	}
	customRoot := o.ConfigRoot != ""
	root := o.ConfigRoot
	if root == "" {
		switch o.Client {
		case Claude:
			root = joinOS(o.GOOS, o.Home, ".claude")
		case Codex:
			root = joinOS(o.GOOS, o.Home, ".codex")
		case Cursor:
			root = joinOS(o.GOOS, o.Home, ".cursor")
		case Pi:
			root = joinOS(o.GOOS, o.Home, ".pi", "agent")
		}
	}
	if !absoluteOS(o.GOOS, root) {
		return o, Location{}, ErrOptions
	}
	o.ConfigRoot = root
	l := Location{MCP: joinOS(o.GOOS, root, "mcp.json"), Hooks: joinOS(o.GOOS, root, "hooks.json")}
	switch o.Client {
	case Claude:
		l.MCP = joinOS(o.GOOS, o.Home, ".claude.json")
		if customRoot {
			l.MCP = joinOS(o.GOOS, root, ".claude.json")
		}
		l.Hooks = joinOS(o.GOOS, root, "settings.json")
		l.Transcripts = joinOS(o.GOOS, root, "projects")
	case Codex:
		l.MCP = joinOS(o.GOOS, root, "config.toml")
		l.Transcripts = joinOS(o.GOOS, root, "sessions")
	case Cursor:
		l.Transcripts = joinOS(o.GOOS, root, "projects")
	case Pi:
		l.Transcripts = joinOS(o.GOOS, root, "sessions")
		l.Extension = joinOS(o.GOOS, root, "extensions", "telara-memory.js")
		l.Hooks = l.Extension
	}
	return o, l, nil
}

// Locations is pure for explicit Home/GOOS, including Windows paths on Unix.
func Locations(o Options) (Location, error) { _, l, e := resolve(o); return l, e }

func shimArgs(o Options) []string { return []string{"shim", "--data-dir", o.StateDir} }
func hookArgs(o Options) []string {
	return []string{"hook", "--client", string(o.Client), "--home", o.Home, "--state-dir", o.StateDir, "--config-root", o.ConfigRoot}
}
func quoted(s string) string { b, _ := json.Marshal(s); return string(b) }
func command(o Options) string {
	a := append([]string{o.Executable}, hookArgs(o)...)
	for i, s := range a {
		a[i] = "'" + s + "'"
	}
	cmd := strings.Join(a, " ")
	if o.GOOS == "windows" {
		// Cursor documents PowerShell hooks. Codex's commandWindows accepts
		// a launch string; explicitly select PowerShell with literal arguments.
		if o.Client == Cursor {
			return "& " + cmd
		}
		return `powershell.exe -NoProfile -NonInteractive -Command "& ` + cmd + `"`
	}
	return cmd
}

func plan(o Options, l Location) []Change {
	entry := map[string]any{"command": o.Executable, "args": shimArgs(o)}
	var mcp string
	format := "json"
	if o.Client == Codex {
		format = "toml"
		args, _ := json.Marshal(shimArgs(o))
		mcp = "[mcp_servers.\"telara-memory\"]\ncommand = " + quoted(o.Executable) + "\nargs = " + string(args) + "\n"
	} else {
		b, _ := json.MarshalIndent(map[string]any{"mcpServers": map[string]any{ServerName: entry}}, "", "  ")
		mcp = string(b) + "\n"
	}
	c := Change{Path: l.MCP, Format: format, Snippet: mcp, Action: "manual_merge", Reason: "shared_config_transaction_unverified"}
	if o.Client == Pi {
		return []Change{{Path: l.Extension, Format: "javascript", Snippet: piExtension(o), Action: "create_owned", Reason: "vendor_user_extension"}}
	}
	hooks := map[string]any{}
	events := []string{"SessionStart", "UserPromptSubmit", "Stop", "SessionEnd"}
	if o.Client == Cursor {
		events = []string{"sessionStart", "afterAgentResponse", "stop", "sessionEnd"}
	}
	for _, event := range events {
		h := map[string]any{"command": command(o), "timeout": 1}
		if o.Client == Claude {
			h["command"] = o.Executable
			h["args"] = hookArgs(o)
		}
		if o.Client != Cursor {
			h["type"] = "command"
			hooks[event] = []any{map[string]any{"hooks": []any{h}}}
		} else {
			hooks[event] = []any{h}
		}
	}
	body := map[string]any{"hooks": hooks}
	if o.Client == Cursor {
		body["version"] = 1
	}
	b, _ := json.MarshalIndent(body, "", "  ")
	return []Change{c, {Path: l.Hooks, Format: "json", Snippet: string(b) + "\n", Action: "manual_merge", Reason: "shared_config_transaction_unverified"}}
}

func report(o Options, l Location) Report {
	r := Report{Client: o.Client, Location: l, MCP: "manual_pending", Capture: "transcript_only_hook_pending", Gaps: []string{"shared_config_transaction_unverified", "daemon_capture_not_verified"}}
	r.CaptureGaps = captureGaps(o.Client)
	if o.GOOS == runtime.GOOS {
		r.Installation = detect(o)
		if r.Installation.State == "not_found" {
			r.Gaps = append(r.Gaps, "client_not_found")
		}
	} else {
		r.Installation = Detection{State: "foreign_os_unverified"}
	}
	if o.Client == Codex {
		r.Gaps = append(r.Gaps, "toml_existing_config_validation_unverified")
		r.Gaps = append(r.Gaps, "hook_trust_review_required")
	}
	if o.Client == Cursor {
		r.Gaps = append(r.Gaps, "installed_hook_dispatch_unverified", "prompt_hook_unverified", "assistant_decoder_unverified")
	}
	if o.Client == Pi {
		r.Gaps = append(r.Gaps, "pi_extension_runtime_unverified")
	}
	return r
}

func validateInstall(o Options) bool {
	return absoluteOS(o.GOOS, o.Executable) && absoluteOS(o.GOOS, o.StateDir)
}

// Install returns reviewable snippets for shared settings and safely refuses to
// write them, even with Print=false. Pi alone creates a distinct owned extension.
func Install(ctx context.Context, o Options) (Report, error) {
	o, l, e := resolve(o)
	if e != nil {
		return Report{}, e
	}
	r := report(o, l)
	if !validateInstall(o) {
		return r, ErrOptions
	}
	if e = ctx.Err(); e != nil {
		return r, e
	}
	r.Changes = plan(o, l)
	if o.GOOS != runtime.GOOS {
		if !o.Print {
			return r, ErrOptions
		}
		return r, nil
	}
	if e = inspectShared(o, l, true); e != nil {
		return r, e
	}
	if o.Client == Pi {
		// The extension registers MCP in memory. mcp.json is never written.
		if !o.Print {
			if e = installPi(ctx, o, l); e != nil {
				return r, e
			}
			r.MCP = "extension_installed_registration_unverified"
			r.Capture = "extension_installed_dispatch_unverified"
		}
	}
	return r, nil
}

// Uninstall never rewinds a shared file over later unrelated edits. Since this
// package cannot mutate shared files, their exact original bytes are preserved.
func Uninstall(ctx context.Context, o Options) (Report, error) {
	o, l, e := resolve(o)
	if e != nil {
		return Report{}, e
	}
	r := report(o, l)
	if e = ctx.Err(); e != nil {
		return r, e
	}
	if o.GOOS != runtime.GOOS {
		return r, ErrOptions
	}
	if o.Client == Pi {
		if !o.Print {
			e = uninstallPi(ctx, o, l)
		}
		r.MCP = "extension_removed_or_absent"
		r.Capture = "hook_removed_or_absent"
		if e != nil {
			r.MCP = "uninstall_refused"
			r.Capture = "unchanged_or_recovery_pending"
		}
		if o.Print {
			r.MCP = "uninstall_preview"
			r.Changes = []Change{{Path: l.Extension, Action: "remove_owned_if_unchanged"}}
		}
		return r, e
	}
	r.Changes = []Change{{Path: l.MCP, Action: "manual_remove_our_entry", Reason: "shared_config_transaction_unverified"}, {Path: l.Hooks, Action: "manual_remove_our_hooks", Reason: "shared_config_transaction_unverified"}}
	return r, inspectShared(o, l, false)
}

// Status reports source/config presence separately from installed-client proof.
// It never starts clients or a daemon, and never marks content captured.
func Status(ctx context.Context, o Options) (Report, error) {
	o, l, e := resolve(o)
	if e != nil {
		return Report{}, e
	}
	r := report(o, l)
	if e = ctx.Err(); e != nil {
		return r, e
	}
	if o.GOOS != runtime.GOOS {
		return r, nil
	}
	if e = inspectShared(o, l, false); e != nil {
		return r, e
	}
	if o.Client == Pi {
		return piStatus(o, l, r)
	}
	if o.Client != Codex {
		if b, e := readOptional(l.MCP); e == nil && b != nil {
			var obj struct {
				Servers map[string]json.RawMessage `json:"mcpServers"`
			}
			_ = json.Unmarshal(b, &obj)
			if _, ok := obj.Servers[ServerName]; ok {
				r.MCP = "entry_present_runtime_unverified"
			}
		}
	}
	return r, nil
}

func readOptional(path string) ([]byte, error) {
	d, e := openDir(filepath.Dir(path), false, false)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer d.close()
	b, e := d.read(filepath.Base(path), 1<<20)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	return b, e
}

func inspectShared(o Options, l Location, conflicts bool) error {
	paths := []string{l.MCP, l.Hooks}
	if o.Client == Pi {
		paths = paths[:1]
	}
	for _, p := range paths {
		b, e := readOptional(p)
		if e != nil {
			return e
		}
		if b == nil {
			continue
		}
		if o.Client == Codex && p == l.MCP {
			// No TOML dependency is available in this module. Never parse/merge a
			// partial grammar. The vendor validates a manual snippet; existing
			// TOML status remains unknown rather than falsely accepted.
			continue
		}
		if !validObject(b) {
			return ErrMalformed
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(b, &obj)
		key := "mcpServers"
		if p == l.Hooks {
			key = "hooks"
		}
		if raw, ok := obj[key]; ok && !validObject(raw) {
			return ErrMalformed
		}
		if p == l.MCP && conflicts {
			var servers map[string]json.RawMessage
			_ = json.Unmarshal(obj["mcpServers"], &servers)
			if _, ok := servers[ServerName]; ok {
				return ErrConflict
			}
			if o.Client == Pi {
				if _, ok := servers["telara_memory"]; ok {
					return ErrConflict
				}
			}
		}
	}
	return nil
}

func validObject(b []byte) bool {
	// The canonicalizer rejects duplicate keys, invalid UTF-8 and trailing data.
	return strictObject(b)
}
