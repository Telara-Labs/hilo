package clients

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Telara-Labs/TAP-Runtime/discover/redact"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

const maxHookInput = 1 << 20

var nativeID = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,128}$`)
var versionID = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}(\.[0-9]{1,8})?([a-zA-Z0-9_.-]{0,24})$`)

func strictObject(b []byte) bool {
	if _, e := jcs.Canonicalize(b); e != nil {
		return false
	}
	var m map[string]json.RawMessage
	return json.Unmarshal(b, &m) == nil && m != nil
}
func identity(s string) bool { return nativeID.MatchString(s) && redact.Redact(s) == s }
func cleanHint(s string) bool {
	return safePath(s) && filepath.IsAbs(s) && filepath.Clean(s) == s && redact.Redact(s) == s
}
func events(c Client) map[string]bool {
	s := []string{"SessionStart", "UserPromptSubmit", "Stop", "SessionEnd"}
	if c == Cursor {
		s = []string{"sessionStart", "afterAgentResponse", "stop", "sessionEnd"}
	}
	if c == Pi {
		s = []string{"session_start", "agent_end", "session_shutdown"}
	}
	m := map[string]bool{}
	for _, x := range s {
		m[x] = true
	}
	return m
}
func enumMap(s ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range s {
		m[x] = true
	}
	return m
}

// HookRules returns the same finite validation contract the spool consumer needs.
// A transcript path is an untrusted hint, never authorization to open a source.
func HookRules(o Options) (transport.HookRules, error) {
	o, l, e := resolve(o)
	if e != nil {
		return transport.HookRules{}, e
	}
	r := transport.HookRules{Client: string(o.Client), TranscriptRoot: l.Transcripts, Events: events(o.Client),
		ValidateNativeSession: identity, ValidatePromptID: identity, ValidateVersion: func(s string) bool { return versionID.MatchString(s) },
		ValidateCwd: cleanHint, ValidateTranscriptPath: cleanHint, ValidateArgv0: func(s string) bool { return processName(s) == s }}
	switch o.Client {
	case Claude:
		r.Sources = enumMap("startup", "resume", "clear", "compact")
		r.Reasons = enumMap("clear", "logout", "prompt_input_exit", "bypass_permissions_disabled", "other")
	case Codex:
		r.Sources = enumMap("startup", "resume", "clear", "compact", "fork")
		r.Reasons = enumMap("other")
	case Cursor:
		r.Reasons = enumMap("completed", "aborted", "error", "window_close", "user_close")
		r.Statuses = enumMap("completed", "aborted", "error")
	}
	return r, nil
}

type HookResult struct {
	Published bool
	// PublicationUnknown means the deadline won while OS work could still be
	// in flight. Published=false alone must not be interpreted as absence.
	PublicationUnknown     bool
	Code                   string
	AncestryComplete       bool
	TranscriptHintVerified bool
}

// RunHook is fail-open toward the client and fail-closed toward persistence.
// It returns codes only, never raw input or filesystem errors. The caller must
// always exit 0 with empty output, even when Published=false. No daemon is needed.
// The complete callback has a 150ms bound, including filesystem work. OS calls
// cannot be cancelled in Go; a timed-out worker may finish later. Publication is
// checked against the deadline immediately before rename, but an in-flight rename
// has an unknown outcome on timeout. Pi also bounds and kills the hook process.
func RunHook(ctx context.Context, o Options, in io.Reader) HookResult {
	return runHookBounded(ctx, o, in, writeSpool)
}

// The writer parameter allows a stalled filesystem regression without a service
// mock or a mutable global seam.
func runHookBounded(ctx context.Context, o Options, in io.Reader, spool func(context.Context, Options, []byte) error) HookResult {
	if in == nil {
		return HookResult{Code: "invalid_input"}
	}
	ctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	defer func() {
		// A worker timeout and ctx.Done can become ready together. Close on
		// either return path, without allowing a blocking Close to delay it.
		if ctx.Err() != nil {
			if c, ok := in.(io.Closer); ok {
				go func() { _ = c.Close() }()
			}
		}
	}()
	if ctx.Err() != nil {
		return HookResult{Code: "hook_timeout"}
	}
	result := make(chan HookResult, 1)
	go func() { result <- runHook(ctx, o, in, spool) }()
	select {
	case r := <-result:
		return r
	case <-ctx.Done():
		return HookResult{Code: "hook_timeout", PublicationUnknown: true}
	}
}

func runHook(ctx context.Context, o Options, in io.Reader, spool func(context.Context, Options, []byte) error) HookResult {
	o, l, e := resolve(o)
	if e != nil || o.GOOS != runtime.GOOS || !absoluteOS(o.GOOS, o.StateDir) {
		return HookResult{Code: "invalid_options"}
	}
	type input struct {
		b []byte
		e error
	}
	ch := make(chan input, 1)
	go func() { b, e := io.ReadAll(io.LimitReader(in, maxHookInput+1)); ch <- input{b, e} }()
	var b []byte
	select {
	case r := <-ch:
		if r.e != nil || len(r.b) > maxHookInput {
			return HookResult{Code: "input_bound"}
		}
		b = r.b
	case <-ctx.Done():
		return HookResult{Code: "hook_timeout"}
	}
	if !strictObject(b) {
		return HookResult{Code: "invalid_input"}
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(b, &raw)
	value := func(k string) string {
		var s string
		if json.Unmarshal(raw[k], &s) != nil {
			return ""
		}
		return s
	}
	h := transport.HookSignal{V: 3, At: time.Now().UnixMilli(), Client: string(o.Client), Event: value("hook_event_name"), NativeSession: value("session_id"), TranscriptPath: value("transcript_path"), Cwd: value("cwd"), HookPID: os.Getpid()}
	if o.Client == Cursor {
		if h.NativeSession == "" {
			h.NativeSession = value("conversation_id")
		}
		h.PromptID = value("generation_id")
		h.ClientVersion = value("cursor_version")
		// Multiroot input cannot be collapsed to a guessed session cwd.
		if h.Cwd == "" {
			var roots []string
			if json.Unmarshal(raw["workspace_roots"], &roots) == nil && len(roots) == 1 {
				h.Cwd = roots[0]
			}
		}
	}
	if o.Client == Codex {
		h.PromptID = value("turn_id")
	}
	// Missing identity cannot become an apparently useful persisted observation.
	if !identity(h.NativeSession) {
		return HookResult{Code: "identity_unavailable"}
	}
	rules, _ := HookRules(o)
	for key, dst := range map[string]*string{"source": &h.Source, "reason": &h.Reason, "status": &h.Status} {
		v := value(key)
		allowed := map[string]map[string]bool{"source": rules.Sources, "reason": rules.Reasons, "status": rules.Statuses}[key]
		if allowed[v] {
			*dst = v
		}
	}
	// The accessor does not open transcripts. Existing hints must pass a pinned
	// no-follow read-only open under the vendor root before even the path persists.
	pathVerified := false
	if h.TranscriptPath != "" {
		if !cleanHint(h.TranscriptPath) || !under(l.Transcripts, h.TranscriptPath) {
			return HookResult{Code: "unsafe_transcript"}
		}
		if e = checkSource(h.TranscriptPath); errors.Is(e, os.ErrNotExist) {
			// Native SessionStart may precede transcript creation. Keep the
			// validated native identity without retaining an unverified path.
			h.TranscriptPath = ""
		} else if e != nil {
			return HookResult{Code: "unsafe_transcript"}
		} else {
			pathVerified = true
		}
	}
	h.Ancestry, e = ancestry(os.Getppid())
	complete := e == nil
	encoded, _ := json.Marshal(h)
	if _, e = transport.ParseHook(encoded, rules); e != nil {
		return HookResult{Code: "invalid_hint"}
	}
	if e = ctx.Err(); e != nil {
		return HookResult{Code: "hook_timeout"}
	}
	if e = spool(ctx, o, encoded); e != nil {
		return HookResult{Code: "spool_unavailable", AncestryComplete: complete}
	}
	code := "published"
	if !complete {
		code = "published_ancestry_incomplete"
	}
	return HookResult{Published: true, Code: code, AncestryComplete: complete, TranscriptHintVerified: pathVerified}
}

func under(root, p string) bool {
	rel, e := filepath.Rel(root, p)
	return e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "."
}

func writeSpool(ctx context.Context, o Options, b []byte) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	base := filepath.Join(o.StateDir, "spool", string(o.Client))
	tmp, e := openDir(filepath.Join(base, "tmp"), true, true)
	if e != nil {
		return e
	}
	defer tmp.close()
	newDir, e := openDir(filepath.Join(base, "new"), true, true)
	if e != nil {
		return e
	}
	defer newDir.close()
	name, e := ulid()
	if e != nil {
		return e
	}
	name += ".json"
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = tmp.create(name, b); e != nil {
		return e
	}
	defer tmp.remove(name)
	if e = ctx.Err(); e != nil {
		return e
	}
	return move(tmp, name, newDir)
}

func ulid() (string, error) {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	if _, e := rand.Read(b[6:]); e != nil {
		return "", e
	}
	n := new(big.Int).SetBytes(b[:])
	mask := big.NewInt(31)
	q := new(big.Int)
	out := make([]byte, 26)
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := 25; i >= 0; i-- {
		q.And(n, mask)
		out[i] = alphabet[q.Int64()]
		n.Rsh(n, 5)
	}
	return string(out), nil
}

func processName(s string) string {
	s = strings.ToLower(filepath.Base(s))
	s = strings.TrimSuffix(s, ".exe")
	switch s {
	case "node", "claude", "codex", "agent", "cursor-agent", "cursor", "pi", "bash", "zsh", "sh", "pwsh", "powershell", "cmd", "launchd", "systemd":
		return s
	}
	return "process"
}
