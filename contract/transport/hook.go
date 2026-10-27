package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/Telara-Labs/hilo/contract/jcs"
	"path/filepath"
	"strings"
	"unicode"
)

type Proc struct {
	PID     int    `json:"pid"`
	StartMS int64  `json:"start_ms"`
	Argv0   string `json:"argv0"`
}
type HookSignal struct {
	V              int    `json:"v"`
	At             int64  `json:"at"`
	Client         string `json:"client"`
	ClientVersion  string `json:"client_version"`
	Event          string `json:"event"`
	NativeSession  string `json:"native_session"`
	TranscriptPath string `json:"transcript_path"`
	Cwd            string `json:"cwd"`
	PromptID       string `json:"prompt_id"`
	Source         string `json:"source"`
	Reason         string `json:"reason"`
	Status         string `json:"status"`
	HookPID        int    `json:"hook_pid"`
	Ancestry       []Proc `json:"ancestry"`
}

// HookRules are the client's installed finite vocabulary. An absent enum permits
// only the empty value. Path checks are lexical; the adapter must resolve symlinks
// against its known client root before opening any transcript.
type HookRules struct {
	Client, TranscriptRoot                                                                                       string
	Events, Sources, Reasons, Statuses                                                                           map[string]bool
	ValidateNativeSession, ValidatePromptID, ValidateVersion, ValidateCwd, ValidateArgv0, ValidateTranscriptPath func(string) bool
}

func ParseHook(raw []byte, rules HookRules) (*HookSignal, error) {
	if len(raw) > 16<<10 {
		return nil, errors.New("hook too large")
	}
	if _, err := jcs.Canonicalize(raw); err != nil {
		return nil, errors.New("invalid hook JSON")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, errors.New("hook object required")
	}
	allowed := map[string]bool{}
	shape, _ := json.Marshal(HookSignal{})
	var names map[string]json.RawMessage
	json.Unmarshal(shape, &names)
	for name := range names {
		allowed[name] = true
	}
	for name := range fields {
		if !allowed[name] {
			return nil, errors.New("unknown hook member")
		}
	}
	var h HookSignal
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&h) != nil {
		return nil, errors.New("unknown or invalid hook member")
	}
	if h.V != 3 || h.At <= 0 || h.Client != rules.Client || h.HookPID <= 0 || len(h.Ancestry) > 6 || !rules.Events[h.Event] || !enum(rules.Sources, h.Source) || !enum(rules.Reasons, h.Reason) || !enum(rules.Statuses, h.Status) {
		return nil, errors.New("invalid hook identity or enum")
	}
	for _, f := range []struct {
		value    string
		limit    int
		validate func(string) bool
	}{{h.NativeSession, 256, rules.ValidateNativeSession}, {h.PromptID, 256, rules.ValidatePromptID}, {h.ClientVersion, 64, rules.ValidateVersion}, {h.Cwd, 4096, rules.ValidateCwd}, {h.TranscriptPath, 4096, rules.ValidateTranscriptPath}} {
		if !identity(f.value, f.limit, f.validate) {
			return nil, errors.New("invalid client identity or path hint")
		}
	}
	for _, p := range h.Ancestry {
		if p.PID <= 0 || p.StartMS <= 0 || p.Argv0 == "" || !identity(p.Argv0, 256, rules.ValidateArgv0) {
			return nil, errors.New("invalid hook ancestry")
		}
	}
	if h.TranscriptPath != "" {
		rel, err := filepath.Rel(rules.TranscriptRoot, h.TranscriptPath)
		if rules.TranscriptRoot == "" || !filepath.IsAbs(rules.TranscriptRoot) || !filepath.IsAbs(h.TranscriptPath) || err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, errors.New("transcript outside client root")
		}
	}
	return &h, nil
}
func enum(m map[string]bool, s string) bool { return s == "" || m[s] }

// Nonempty identity values require a client-specific shape/path validator; no
// permissive generic fallback can turn source prose into retained metadata.
func identity(s string, limit int, validate func(string) bool) bool {
	if s == "" {
		return true
	}
	if len(s) > limit || validate == nil {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return validate(s)
}
