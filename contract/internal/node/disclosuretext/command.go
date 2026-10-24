// Package disclosuretext contains fixed, authority-free node text operations.
// It cannot read a store, authorize a grant, sign, commit or release data.
package disclosuretext

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// Error deliberately never wraps parser, argument, policy or identity text.
type Error struct{ code string }

func (e *Error) Error() string { return e.code }
func fail(code string) error   { return &Error{code} }
func Code(e error) string {
	if e == nil {
		return ""
	}
	if x, ok := e.(*Error); ok {
		return x.code
	}
	return "text_failure"
}

const MaxEnvelope = 1 << 20

type ByteBudget struct{ MaxBytes int }
type Step struct {
	Step   string `json:"step"`
	Status string `json:"status"`
}
type Arguments struct {
	Name, FinalSummary                                                                                             *string
	Goal, TaskID, Milestone, NextSteps, ResumeContext, ProgressNotes, HandoffHint, RecordID, Query, Mode, CursorID string
	FilePaths, KnowledgeRefs, ChangesMade, ResourceTypes                                                           []string
	TaskTree                                                                                                       []Step
	TokenEstimate                                                                                                  *int64
	IncludeCompleted                                                                                               bool
	IncludeContent                                                                                                 bool
	RecordKind                                                                                                     record.Kind
	Limit                                                                                                          int
}

// Command retains complete syntax and field presence, not defaulted semantics.
type Command struct {
	tool string
	raw  []byte
}

func (c Command) Tool() string { return c.tool }

type NormalizedCommand struct {
	Tool, SchemaID, RulesetFingerprint, ArgsHash string
	Canonical                                    []byte
	Args                                         Arguments
	Budget                                       ByteBudget
}

var tools = map[string]string{
	"local.create_task": "create_task_args_v1", "local.checkpoint_task": "checkpoint_task_args_v1",
	"local.pause_task": "pause_task_args_v1", "local.complete_task": "complete_task_args_v1",
	"local.resume_task": "resume_task_args_v1", "local.list_tasks": "list_tasks_args_v1",
	"local.lookup_record": "lookup_record_args_v1", "local.lexical_search": "lexical_search_args_v1",
	"local.next_page": "next_page_args_v1",
}

func CurrentSchema(tool string) string { return tools[tool] }

// strictJSON first applies the generic I-JSON gate, not the no-null record
// profile. Its separate depth bound is narrower than the record parser's.
func strictJSON(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelope {
		return nil, fail("argument_limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	depth := 0
	for {
		t, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, fail("invalid_arguments")
		}
		if x, ok := t.(json.Delim); ok {
			if x == '{' || x == '[' {
				depth++
				if depth > 32 {
					return nil, fail("argument_depth")
				}
			} else {
				depth--
			}
		}
	}
	c, e := jcs.Canonicalize(raw)
	if e != nil {
		return nil, fail("invalid_arguments")
	}
	if len(c) > MaxEnvelope {
		return nil, fail("argument_limit")
	}
	return c, nil
}
func DecodeCommand(tool string, raw []byte) (Command, error) {
	if CurrentSchema(tool) == "" {
		return Command{}, fail("unsupported_tool")
	}
	c, e := strictJSON(raw)
	if e != nil {
		return Command{}, e
	}
	if len(c) == 0 || c[0] != '{' {
		return Command{}, fail("invalid_arguments")
	}
	// Preserve the original validated numeric spelling through schema checks.
	return Command{tool, append([]byte(nil), raw...)}, nil
}

func NormalizeCommand(c Command, budget ByteBudget, schemaID, fingerprint string) (NormalizedCommand, error) {
	return NormalizeTenantCommand(c, budget, schemaID, fingerprint, nil)
}

// NormalizeTenantCommand applies the verified policy before bounds and sealing.
func NormalizeTenantCommand(c Command, budget ByteBudget, schemaID, fingerprint string, tenant *record.PolicyBody) (NormalizedCommand, error) {
	var out NormalizedCommand
	overlay, err := localpolicy.TenantOverlay(tenant)
	if err != nil {
		return out, fail("local_policy_unavailable")
	}
	if CurrentSchema(c.tool) == "" || schemaID != CurrentSchema(c.tool) {
		return out, fail("op_schema_unavailable")
	}
	r, e := localpolicy.Ruleset()
	if e != nil {
		return out, fail("local_policy_unavailable")
	}
	if r.Fingerprint() != fingerprint {
		return out, fail("op_schema_unavailable")
	}
	if budget.MaxBytes < 2048 || budget.MaxBytes > 262144 {
		return out, fail("invalid_budget")
	}
	_, e = strictJSON(c.raw)
	if e != nil {
		return out, e
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(c.raw, &m) != nil {
		return out, fail("invalid_arguments")
	}
	accepted := map[string]string{
		"local.create_task":     "name goal file_paths",
		"local.checkpoint_task": "task_id milestone next_steps knowledge_refs task_tree",
		"local.pause_task":      "task_id resume_context progress_notes handoff_hint token_estimate",
		"local.complete_task":   "task_id final_summary changes_made token_estimate",
		"local.resume_task":     "task_id", "local.list_tasks": "include_completed include_receipts limit mode query",
		"local.lookup_record": "record_id record_kind include_content max_neighbors", "local.lexical_search": "query limit resource_types include_history",
		"local.next_page": "cursor_id",
	}
	allowed := map[string]bool{}
	for _, k := range strings.Fields(accepted[c.tool]) {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return out, fail("unsupported_argument")
		}
	}
	a := Arguments{}
	canon := map[string]any{"budget_unit": "utf8-bytes", "max_bytes": budget.MaxBytes}
	work := &WorkBudget{}
	redact := func(k, s string) (string, error) {
		s = overlay.Argument(k, overlay.Text(s))
		if tenant == nil {
			return s, nil
		}
		v, _, err := NormalizePolicyValue(s, work)
		if err != nil {
			return "", err
		}
		redacted := overlay.Argument(k, overlay.Text(v))
		if redacted != v {
			// Preserve ordinary Unicode argument identity. Only a policy hit
			// constructed by display normalization needs a sanitized replacement.
			return redacted, nil
		}
		return s, nil
	}
	text := func(k string, max int, required bool) (string, error) {
		v, ok := m[k]
		if !ok {
			if required {
				return "", fail("missing_argument")
			}
			return "", nil
		}
		var s string
		if json.Unmarshal(v, &s) != nil || bytes.Equal(v, []byte("null")) {
			return "", fail("invalid_arguments")
		}
		var err error
		s, err = redact(k, s)
		if err != nil {
			return "", err
		}
		if len(s) > max {
			return "", fail("argument_limit")
		}
		return s, nil
	}
	list := func(k string, n, max int) ([]string, error) {
		v, ok := m[k]
		if !ok {
			return []string{}, nil
		}
		var elements []json.RawMessage
		if json.Unmarshal(v, &elements) != nil || bytes.Equal(v, []byte("null")) {
			return nil, fail("invalid_arguments")
		}
		if len(elements) > n {
			return nil, fail("argument_limit")
		}
		ss := make([]string, len(elements))
		for i, element := range elements {
			var s string
			if json.Unmarshal(element, &s) != nil || bytes.Equal(element, []byte("null")) {
				return nil, fail("invalid_arguments")
			}
			var err error
			ss[i], err = redact(k, s)
			if err != nil {
				return nil, err
			}
			if len(ss[i]) > max {
				return nil, fail("argument_limit")
			}
		}
		return ss, nil
	}
	integer := func(k string, def, lo, hi int64, required bool) (int64, error) {
		v, ok := m[k]
		if !ok {
			if required {
				return 0, fail("missing_argument")
			}
			return def, nil
		}
		n, ok := exactInteger(v, lo, hi)
		if !ok {
			return 0, fail("invalid_arguments")
		}
		return n, nil
	}
	boolean := func(k string) (bool, error) {
		v, ok := m[k]
		if !ok {
			return false, nil
		}
		var b bool
		if json.Unmarshal(v, &b) != nil || bytes.Equal(v, []byte("null")) {
			return false, fail("invalid_arguments")
		}
		return b, nil
	}
	target := func(k string, uuid bool) (string, error) {
		v, ok := m[k]
		if !ok {
			return "", fail("missing_argument")
		}
		var s string
		if json.Unmarshal(v, &s) != nil {
			return "", fail("invalid_arguments")
		}
		if (uuid && !record.IsUUIDv4(s)) || (!uuid && !record.IsHex64(s)) {
			return "", fail("invalid_arguments")
		}
		if localpolicy.Text(s) != s || localpolicy.Argument(k, s) != s {
			return "", fail("unsafe_identity")
		}
		return s, nil
	}
	setText := func(k string, dst *string, max int, required bool) error {
		s, e := text(k, max, required)
		if e != nil {
			return e
		}
		*dst = s
		canon[k] = s
		return nil
	}
	setList := func(k string, dst *[]string, n, max int) error {
		s, e := list(k, n, max)
		if e != nil {
			return e
		}
		*dst = s
		canon[k] = s
		return nil
	}
	if c.tool == "local.create_task" {
		if e = setText("goal", &a.Goal, 16384, true); e != nil {
			return out, e
		}
		if e = setList("file_paths", &a.FilePaths, 64, 1000); e != nil {
			return out, e
		}
		if _, ok := m["name"]; ok {
			s, e := text("name", MaxEnvelope, false)
			if e != nil {
				return out, e
			}
			if utf8.RuneCountInString(s) > 100 {
				return out, fail("argument_limit")
			}
			a.Name = &s
			canon["name"] = s
		}
	}
	if c.tool == "local.checkpoint_task" || c.tool == "local.pause_task" || c.tool == "local.complete_task" || c.tool == "local.resume_task" {
		a.TaskID, e = target("task_id", true)
		if e != nil {
			return out, e
		}
		canon["task_id"] = a.TaskID
	}
	switch c.tool {
	case "local.checkpoint_task":
		if e = setText("milestone", &a.Milestone, 16384, true); e != nil {
			return out, e
		}
		if e = setText("next_steps", &a.NextSteps, 16384, false); e != nil {
			return out, e
		}
		if e = setList("knowledge_refs", &a.KnowledgeRefs, 64, 64); e != nil {
			return out, e
		}
		for _, id := range a.KnowledgeRefs {
			if !record.IsHex64(id) {
				return out, fail("unsupported_argument")
			}
		}
		a.TaskTree = []Step{}
		if v, ok := m["task_tree"]; ok {
			var items []map[string]json.RawMessage
			if json.Unmarshal(v, &items) != nil || bytes.Equal(v, []byte("null")) || len(items) > 256 {
				return out, fail("invalid_arguments")
			}
			for _, item := range items {
				for key := range item {
					if key != "step" && key != "status" {
						return out, fail("unsupported_argument")
					}
				}
				stepRaw, stepPresent := item["step"]
				statusRaw, statusPresent := item["status"]
				if !stepPresent || !statusPresent || len(stepRaw) == 0 || len(statusRaw) == 0 || stepRaw[0] != '"' || statusRaw[0] != '"' {
					return out, fail("invalid_arguments")
				}
				var entry Step
				if json.Unmarshal(stepRaw, &entry.Step) != nil || json.Unmarshal(statusRaw, &entry.Status) != nil {
					return out, fail("invalid_arguments")
				}
				var err error
				entry.Step, err = redact("step", entry.Step)
				if err != nil {
					return out, err
				}
				if len(entry.Step) > 1000 {
					return out, fail("argument_limit")
				}
				if entry.Status != "pending" && entry.Status != "in_progress" && entry.Status != "done" {
					return out, fail("invalid_arguments")
				}
				a.TaskTree = append(a.TaskTree, entry)
			}
		}
		canon["task_tree"] = a.TaskTree
	case "local.pause_task":
		if e = setText("resume_context", &a.ResumeContext, 16384, true); e != nil {
			return out, e
		}
		if e = setText("progress_notes", &a.ProgressNotes, 16384, false); e != nil {
			return out, e
		}
		if e = setText("handoff_hint", &a.HandoffHint, 1000, false); e != nil {
			return out, e
		}
	case "local.complete_task":
		if _, ok := m["final_summary"]; ok {
			s, e := text("final_summary", 16384, false)
			if e != nil {
				return out, e
			}
			a.FinalSummary = &s
			canon["final_summary"] = s
		}
		if e = setList("changes_made", &a.ChangesMade, 64, 1000); e != nil {
			return out, e
		}
	case "local.list_tasks":
		a.IncludeCompleted, e = boolean("include_completed")
		if e != nil {
			return out, e
		}
		canon["include_completed"] = a.IncludeCompleted
		b, e := boolean("include_receipts")
		if e != nil {
			return out, e
		}
		if b {
			return out, fail("unsupported_argument")
		}
		canon["include_receipts"] = false
		if e = setText("mode", &a.Mode, 20, false); e != nil {
			return out, e
		}
		if a.Mode == "" {
			a.Mode = "summary"
		}
		if a.Mode != "summary" && a.Mode != "detail" {
			return out, fail("invalid_arguments")
		}
		canon["mode"] = a.Mode
		def := int64(10)
		if a.Mode == "detail" {
			def = 25
		}
		n, e := integer("limit", def, 1, 25, false)
		if e != nil {
			return out, e
		}
		a.Limit = int(n)
		canon["limit"] = n
		if e = setText("query", &a.Query, 1000, false); e != nil {
			return out, e
		}
	case "local.lookup_record":
		a.RecordID, e = target("record_id", false)
		if e != nil {
			return out, e
		}
		canon["record_id"] = a.RecordID
		if raw, ok := m["record_kind"]; ok {
			var kind string
			if json.Unmarshal(raw, &kind) != nil || !record.Kind(kind).Known() || record.Kind(kind).IsControl() {
				return out, fail("unsupported_filter")
			}
			a.RecordKind = record.Kind(kind)
			canon["record_kind"] = kind
		}
		// Preserve the preexisting local lookup's full projection by default.
		// Public get_context must explicitly select its metadata-only default.
		a.IncludeContent = true
		if _, ok := m["include_content"]; ok {
			a.IncludeContent, e = boolean("include_content")
			if e != nil {
				return out, e
			}
		}
		canon["include_content"] = a.IncludeContent
		n, e := integer("max_neighbors", 0, 0, 0, false)
		if e != nil {
			return out, fail("unsupported_argument")
		}
		canon["max_neighbors"] = n
	case "local.lexical_search":
		if e = setText("query", &a.Query, 1000, false); e != nil {
			return out, e
		}
		n, e := integer("limit", 10, 1, 50, false)
		if e != nil {
			return out, e
		}
		a.Limit = int(n)
		canon["limit"] = n
		b, e := boolean("include_history")
		if e != nil {
			return out, e
		}
		if b {
			return out, fail("unsupported_argument")
		}
		canon["include_history"] = false
		if e = setList("resource_types", &a.ResourceTypes, 4, 30); e != nil {
			return out, e
		}
		if _, ok := m["resource_types"]; !ok {
			a.ResourceTypes = []string{"checkpoint", "evidence", "session", "task_summary"}
		}
		sort.Strings(a.ResourceTypes)
		for i, v := range a.ResourceTypes {
			if v != "checkpoint" && v != "evidence" && v != "session" && v != "task_summary" {
				return out, fail("unsupported_filter")
			}
			if i > 0 && a.ResourceTypes[i-1] == v {
				return out, fail("invalid_arguments")
			}
		}
		canon["resource_types"] = a.ResourceTypes
	case "local.next_page":
		a.CursorID, e = target("cursor_id", true)
		if e != nil {
			return out, e
		}
		canon["cursor_id"] = a.CursorID
	}
	if c.tool == "local.pause_task" || c.tool == "local.complete_task" {
		n, e := integer("token_estimate", 0, 0, math.MaxInt32, true)
		if e != nil {
			return out, e
		}
		a.TokenEstimate = &n
		canon["token_estimate"] = n
	}
	b, e := jcs.Marshal(canon)
	if e != nil {
		return out, fail("invalid_arguments")
	}
	if len(b) > MaxEnvelope {
		return out, fail("argument_limit")
	}
	// Content comparators belong only to a live signed CallBody's erasable
	// key. Normalization must never manufacture a standalone prose digest.
	return NormalizedCommand{c.tool, schemaID, fingerprint, "", b, a, budget}, nil
}

// exactInteger validates the ORIGINAL JSON number as an exact decimal before
// JCS can round it to binary64. Work and storage are linear in the bounded
// envelope; huge zero/exponent spellings never allocate a giant big integer.
func exactInteger(raw []byte, lo, hi int64) (int64, bool) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s[0] == '"' || s == "null" {
		return 0, false
	}
	negative := s[0] == '-'
	if negative {
		s = s[1:]
	}
	exponent := 0
	if at := strings.IndexAny(s, "eE"); at >= 0 {
		exp := s[at+1:]
		s = s[:at]
		sign := 1
		if exp != "" && (exp[0] == '+' || exp[0] == '-') {
			if exp[0] == '-' {
				sign = -1
			}
			exp = exp[1:]
		}
		if exp == "" {
			return 0, false
		}
		for _, c := range exp {
			if c < '0' || c > '9' {
				return 0, false
			}
			if exponent < 2*MaxEnvelope {
				exponent = exponent*10 + int(c-'0')
				if exponent > 2*MaxEnvelope {
					exponent = 2 * MaxEnvelope
				}
			}
		}
		exponent *= sign
	}
	fraction := 0
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		fraction = len(s) - dot - 1
		s = s[:dot] + s[dot+1:]
	}
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	digits := strings.TrimLeft(s, "0")
	if digits == "" {
		return 0, lo <= 0 && hi >= 0
	}
	scale := exponent - fraction
	if scale < 0 {
		remove := -scale
		if remove >= len(digits) || strings.Trim(digits[len(digits)-remove:], "0") != "" {
			return 0, false
		}
		digits = digits[:len(digits)-remove]
	} else {
		if len(digits) > 19 || scale > 19-len(digits) {
			return 0, false
		}
		digits += strings.Repeat("0", scale)
	}
	if len(digits) > 19 {
		return 0, false
	}
	if negative {
		digits = "-" + digits
	}
	n, e := strconv.ParseInt(digits, 10, 64)
	return n, e == nil && n >= lo && n <= hi
}
