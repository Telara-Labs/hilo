package record

// Bodies of the kind union. JSON names are snake_case and every
// optional field is omitted when empty. Unknown body fields are kept in the
// bytes and ignored on decode, except in the v1 export bodies, which
// must match their allowlist exactly.
//
// Nested types the specification names without defining are taken from the
// portion designs and marked provisional; adding fields to them is a MINOR
// change.

// SessionBody is one page of one machine's snapshot of a session.
type SessionBody struct {
	Salt           string        `json:"salt,omitempty"`
	NativeID       string        `json:"native_id,omitempty"`
	NativeIDKind   string        `json:"native_id_kind,omitempty"` // global | local
	MachineOS      string        `json:"machine_os,omitempty"`
	Repo           *RepoRef      `json:"repo,omitempty"`
	Cwd            string        `json:"cwd,omitempty"`   // home-relative, redacted
	Title          string        `json:"title,omitempty"` // first prompt, redacted, ≤120 runes
	StartedAt      int64         `json:"started_at,omitempty"`
	LastEventAt    int64         `json:"last_event_at,omitempty"`
	EndedAt        int64         `json:"ended_at,omitempty"` // 0 = open
	End            string        `json:"end,omitempty"`      // client-end | idle | source-gone
	Page           int64         `json:"page,omitempty"`
	Chunks         []string      `json:"chunks,omitempty"` // ≤8,192 chunk ids of this page, in seq order
	SettledThrough int64         `json:"settled_through,omitempty"`
	Counts         *Counts       `json:"counts,omitempty"`
	Links          []SessionLink `json:"links,omitempty"`
	Reader         *SourceRef    `json:"reader,omitempty"`
}

// RepoRef (provisional shape).
type RepoRef struct {
	ID          string `json:"id,omitempty"`
	Remote      string `json:"remote,omitempty"`
	Branch      string `json:"branch,omitempty"`
	CommitStart string `json:"commit_start,omitempty"`
	CommitEnd   string `json:"commit_end,omitempty"`
	CommitBasis string `json:"commit_basis,omitempty"`
	Dirty       *bool  `json:"dirty,omitempty"`
}

// Counts (provisional shape).
type Counts struct {
	Requests        int `json:"requests,omitempty"`
	ToolCalls       int `json:"tool_calls,omitempty"`
	ToolFailures    int `json:"tool_failures,omitempty"`
	AssistantFinals int `json:"assistant_finals,omitempty"`
	SkippedRecords  int `json:"skipped_records,omitempty"`
}

// SessionLink relates two sessions (provisional shape).
type SessionLink struct {
	Relation        string `json:"relation"` // fork | resume | subagent | compaction
	OtherSessionKey string `json:"other_session_key"`
	Direction       string `json:"direction,omitempty"` // parent | child
}

// SourceRef names the reader that produced a snapshot. It carries no source
// digest: a hash of raw transcript bytes must never enter a record.
type SourceRef struct {
	Reader        string `json:"reader,omitempty"`
	ReaderVersion string `json:"reader_version,omitempty"`
}

// ChunkBody holds ≤256 events and ≤1 MiB canonical.
type ChunkBody struct {
	Salt   string  `json:"salt,omitempty"`
	Events []Event `json:"events"`
}

// Event is one ordered item of a session.
type Event struct {
	Salt        string            `json:"salt"` // protected revision salt, erasable body only
	ID          string            `json:"id"`
	Revision    string            `json:"revision"`
	Replaces    []string          `json:"replaces,omitempty"`
	Seq         int64             `json:"seq,omitempty"`
	Kind        string            `json:"kind"`
	At          int64             `json:"at,omitempty"`
	AtPrecision string            `json:"at_precision,omitempty"` // exact | minute | inferred
	Request     string            `json:"request,omitempty"`      // native request identity or idx:<n>
	Prov        string            `json:"prov"`                   // transcript | hook
	Ruleset     int               `json:"ruleset,omitempty"`      // redaction epoch
	Text        *Text             `json:"text,omitempty"`
	Call        *ToolCall         `json:"call,omitempty"`
	Result      *ToolResult       `json:"result,omitempty"`
	Link        *SessionLink      `json:"link,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
	Recalled    []string          `json:"recalled,omitempty"` // lid@id of read-back seen
	Src         *SourcePos        `json:"src,omitempty"`
}

// Text (provisional shape).
type Text struct {
	Body      string `json:"body,omitempty"`
	Bytes     int    `json:"bytes,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Digest    string `json:"digest,omitempty"` // of the redacted body
}

// ToolCall (provisional shape).
type ToolCall struct {
	Tool      string            `json:"tool,omitempty"`
	MCPServer string            `json:"mcp_server,omitempty"`
	MCPTool   string            `json:"mcp_tool,omitempty"`
	Command   string            `json:"command,omitempty"`
	Args      map[string]string `json:"args,omitempty"`
	RawArgs   map[string]bool   `json:"raw_args,omitempty"`
}

// ToolResult (provisional shape).
type ToolResult struct {
	CallEventID string   `json:"call_event_id,omitempty"`
	Outcome     string   `json:"outcome,omitempty"` // ok | error | unknown
	ErrorClass  string   `json:"error_class,omitempty"`
	Excerpt     string   `json:"excerpt,omitempty"`
	Bytes       int      `json:"bytes,omitempty"`
	OutIDs      []string `json:"out_ids,omitempty"`
	OutPaths    []string `json:"out_paths,omitempty"`
	OutTokens   []string `json:"out_tokens,omitempty"`
}

// SourcePos (provisional shape).
type SourcePos struct {
	Path   string `json:"path,omitempty"`
	Line   int64  `json:"line,omitempty"`
	Record string `json:"record,omitempty"`
}

// ConclusionBody is an explicit, final-answer or hook-final conclusion.
type ConclusionBody struct {
	RequestKey    string   `json:"request_key,omitempty"` // bounded native identity, distinct from Request prompt text
	Salt          string   `json:"salt,omitempty"`
	Source        string   `json:"source"` // explicit | final-answer | hook-final
	State         string   `json:"state,omitempty"`
	Request       string   `json:"request,omitempty"` // ≤1000 B
	Text          string   `json:"text,omitempty"`    // ≤16 KiB
	Supports      []string `json:"supports,omitempty"`
	ChangesMade   []string `json:"changes_made,omitempty"`   // explicit only
	TokenEstimate *int64   `json:"token_estimate,omitempty"` // explicit only; nil = unreported
}

// TaskBody opens or edits a task.
type TaskBody struct {
	Salt    string   `json:"salt,omitempty"`
	Name    string   `json:"name,omitempty"`
	Goal    string   `json:"goal,omitempty"`
	Anchors *Anchors `json:"anchors,omitempty"`
	Status  string   `json:"status"` // active | completed | abandoned
}

// Anchors (provisional shape).
type Anchors struct {
	Files   []string `json:"files,omitempty"`
	Commits []string `json:"commits,omitempty"`
	Refs    []string `json:"refs,omitempty"`
}

// CheckpointBody is one task checkpoint.
type CheckpointBody struct {
	Salt          string   `json:"salt,omitempty"`
	Milestone     string   `json:"milestone,omitempty"`
	NextSteps     string   `json:"next_steps,omitempty"`
	KnowledgeRefs []string `json:"knowledge_refs,omitempty"`
	Supports      []string `json:"supports,omitempty"`
	TaskTree      []Step   `json:"task_tree,omitempty"`
}

// Step (provisional shape).
type Step struct {
	Title  string `json:"title,omitempty"`
	Status string `json:"status,omitempty"`
}

// PauseBody records a task pause.
type PauseBody struct {
	Salt          string `json:"salt,omitempty"`
	ResumeContext string `json:"resume_context,omitempty"`
	ProgressNotes string `json:"progress_notes,omitempty"`
	HandoffHint   string `json:"handoff_hint,omitempty"`
	TokenEstimate *int64 `json:"token_estimate,omitempty"`
}

// CallBody is the receipt of one MCP call. Hashes are over redacted JCS.
type CallBody struct {
	CallRef    string `json:"call_ref"`
	ScopeID    string `json:"scope_id"`
	Tool       string `json:"tool"`
	ArgsHash   string `json:"args_hash,omitempty"`
	ResultHash string `json:"result_hash,omitempty"`
	TaskID     string `json:"task_id,omitempty"`
	Outcome    string `json:"outcome,omitempty"`
	Err        string `json:"err,omitempty"`
}

// BindingBody attributes one call to one session.
type BindingBody struct {
	CallRef    string        `json:"call_ref"`
	Target     *BindTarget   `json:"target,omitempty"` // nil unless bound
	Confidence string        `json:"confidence"`
	Status     string        `json:"status"` // bound | ambiguous | retracted
	Evidence   *BindEvidence `json:"evidence,omitempty"`
}

// BindTarget names the session a call is bound to.
type BindTarget struct {
	SessionKey      string `json:"session_key"`
	Client          string `json:"client,omitempty"`
	NativeSessionID string `json:"native_session_id,omitempty"`
}

// BindEvidence holds no free text.
type BindEvidence struct {
	SightingEventIDs []string `json:"sighting_event_ids,omitempty"`
	AncestryMatch    bool     `json:"ancestry_match,omitempty"`
	Handle           string   `json:"handle,omitempty"`
}

// DigestBody is a node-derived session digest.
type DigestBody struct {
	Salt       string            `json:"salt,omitempty"`
	HasOutcome bool              `json:"has_outcome,omitempty"`
	Requests   []string          `json:"requests,omitempty"`
	Outcome    string            `json:"outcome,omitempty"`
	Touched    []string          `json:"touched,omitempty"`
	Failures   []string          `json:"failures,omitempty"`
	Evidence   []EvidencePointer `json:"evidence,omitempty"`
}

// EvidencePointer (provisional shape).
type EvidencePointer struct {
	Source   string `json:"source,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Ref      string `json:"ref,omitempty"`
	Location string `json:"location,omitempty"`
	Revision string `json:"revision,omitempty"`
}

// RollupBody merges checkpoints.
type RollupBody struct {
	Salt   string   `json:"salt,omitempty"`
	Covers []string `json:"covers,omitempty"` // checkpoint ids it merges
	Text   string   `json:"text,omitempty"`
}

// SessionMetaBody is the v1 export variant of a session (push-metadata).
// Exactly these fields; nothing else is allowed.
type SessionMetaBody struct {
	Salt         string        `json:"salt,omitempty"`
	NativeIDKind string        `json:"native_id_kind,omitempty"`
	MachineOS    string        `json:"machine_os,omitempty"`
	Repo         *MetaRepo     `json:"repo,omitempty"`
	StartedAt    int64         `json:"started_at,omitempty"`
	LastEventAt  int64         `json:"last_event_at,omitempty"`
	EndedAt      int64         `json:"ended_at,omitempty"`
	End          string        `json:"end,omitempty"`
	Counts       *MetaCounts   `json:"counts,omitempty"`
	Title        string        `json:"title,omitempty"`
	Pointers     []MetaPointer `json:"pointers,omitempty"` // ≤64, failures first
}

// MetaRepo is the exported repository reference.
type MetaRepo struct {
	ID          string `json:"id,omitempty"`
	Remote      string `json:"remote,omitempty"`
	CommitStart string `json:"commit_start,omitempty"`
	CommitEnd   string `json:"commit_end,omitempty"`
}

// MetaCounts are the exported counters.
type MetaCounts struct {
	Requests     int `json:"requests,omitempty"`
	ToolCalls    int `json:"tool_calls,omitempty"`
	ToolFailures int `json:"tool_failures,omitempty"`
}

// MetaPointer is one exported evidence pointer.
type MetaPointer struct {
	Tool     string `json:"tool,omitempty"`
	Outcome  string `json:"outcome,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Ref      string `json:"ref,omitempty"`
	Revision string `json:"revision,omitempty"`
}

// TaskMetaBody is the v1 export variant of a task (push-metadata).
type TaskMetaBody struct {
	Salt   string `json:"salt,omitempty"`
	Status string `json:"status,omitempty"`
}

// RetractionBody invalidates exact ids and their closure; it never bans a LID.
type RetractionBody struct {
	IDs    []string `json:"ids"`
	Reason string   `json:"reason"` // redaction_repair | export_superseded | rule_removed
}

// TaskSelector names the owner as well as the task, including before its arrival.
type TaskSelector struct {
	Owner  string `json:"owner"`
	TaskID string `json:"task_id"`
}

// Selectors of an erasure.
type Selectors struct {
	IDs      []string       `json:"ids,omitempty"`
	LIDs     []string       `json:"lids,omitempty"`
	Tasks    []TaskSelector `json:"tasks,omitempty"`
	Sessions []string       `json:"sessions,omitempty"`
	Sources  []string       `json:"sources,omitempty"`
}

// Count is the number of selector entries.
func (s Selectors) Count() int {
	return len(s.IDs) + len(s.LIDs) + len(s.Tasks) + len(s.Sessions) + len(s.Sources)
}

// ErasureBody is a permanent erasure.
type ErasureBody struct {
	Selectors Selectors `json:"selectors"`
	Reason    string    `json:"reason"`             // user_request | redaction_miss | device_compromise | retention_policy
	Resolved  int64     `json:"resolved,omitempty"` // records resolved at issue time (bulk guard)
}

// WithdrawalBody records that a tenant grant was removed.
type WithdrawalBody struct {
	Tenant    string   `json:"tenant"`
	PolicySeq int64    `json:"policy_seq,omitempty"` // the policy under which the grant ended
	IDs       []string `json:"ids,omitempty"`        // exact ids, ≤4096
	All       bool     `json:"all,omitempty"`        // every record whose Grants contain this tenant
	Reason    string   `json:"reason"`               // policy_narrowed | user_removed | offboarded | kill_switch
}

// KeyRef describes a key in a key operation.
type KeyRef struct {
	KeyID     string `json:"key_id"`
	Alg       string `json:"alg"`
	Pub       string `json:"pub"` // base64url raw 32 bytes, no padding
	Role      Role   `json:"role"`
	MachineID string `json:"machine_id,omitempty"`
}

// KeyOpBody is one entry of the keyring chain.
type KeyOpBody struct {
	Op       string   `json:"op"`
	Subject  KeyRef   `json:"subject"`
	Reason   string   `json:"reason,omitempty"`   // revoke reason
	Previous string   `json:"previous,omitempty"` // rotated key id
	Genesis  string   `json:"genesis,omitempty"`  // genesis key id or tenant id
	Parents  []string `json:"parents,omitempty"`  // keyring heads the author held, ≤16; empty only for genesis
}

// PolicyBody is a signed tenant policy.
type PolicyBody struct {
	Tenant       string         `json:"tenant"`
	Seq          int64          `json:"seq"`
	IssuedAt     int64          `json:"issued_at"`
	RefreshAfter int64          `json:"refresh_after,omitempty"`
	NotAfter     int64          `json:"not_after"`
	Applies      PolicyApplies  `json:"applies"`
	Kill         PolicyKill     `json:"kill,omitzero"`
	BlockedRepos []BlockedRepo  `json:"blocked_repos,omitempty"`
	Redaction    PolicyRedact   `json:"redaction,omitzero"`
	Push         PolicyPush     `json:"push,omitzero"`
	Readback     PolicyReadback `json:"readback,omitzero"`
}

// PolicyApplies names the users a policy applies to: ["*"] or user ids.
type PolicyApplies struct {
	Users []string `json:"users"`
}

// PolicyKill is the kill switch.
type PolicyKill struct {
	Sync               bool `json:"sync,omitempty"`
	CaptureTenantRepos bool `json:"capture_tenant_repos,omitempty"`
	WithdrawPulled     bool `json:"withdraw_pulled,omitempty"`
}

// BlockedRepo blocks capture or push for matching remotes.
type BlockedRepo struct {
	RemoteGlob string `json:"remote_glob"`
	Effect     string `json:"effect"` // no-capture | no-push
}

// PolicyRedact forces a minimum ruleset epoch and extra shapes.
type PolicyRedact struct {
	MinEpoch int     `json:"min_epoch,omitempty"`
	Shapes   []Shape `json:"shapes,omitempty"`
}

// IsZero lets encoding/json omit an empty redaction section.
func (r PolicyRedact) IsZero() bool { return r.MinEpoch == 0 && len(r.Shapes) == 0 }

// Shape is a tenant redaction pattern (RE2 syntax).
type Shape struct {
	Name string `json:"name"`
	RE2  string `json:"re2"`
}

// PolicyPush bounds what may leave the machine.
type PolicyPush struct {
	MaxProfile     string   `json:"max_profile,omitempty"`
	AllowRepos     []string `json:"allow_repos,omitempty"` // empty = none
	RequirePreview bool     `json:"require_preview,omitempty"`
}

// IsZero lets encoding/json omit an empty push section.
func (p PolicyPush) IsZero() bool {
	return p.MaxProfile == "" && len(p.AllowRepos) == 0 && !p.RequirePreview
}

// PolicyReadback says which read-back channels the user may enable.
type PolicyReadback struct {
	HookInjection    bool `json:"hook_injection,omitempty"`
	CloudPull        bool `json:"cloud_pull,omitempty"`
	HostedOriginPull bool `json:"hosted_origin_pull,omitempty"`
}

// newBody returns a pointer to a zero body of the named type.
func newBody(name string) any {
	switch name {
	case "SessionBody":
		return &SessionBody{}
	case "SessionMetaBody":
		return &SessionMetaBody{}
	case "ChunkBody":
		return &ChunkBody{}
	case "ConclusionBody":
		return &ConclusionBody{}
	case "TaskBody":
		return &TaskBody{}
	case "TaskMetaBody":
		return &TaskMetaBody{}
	case "CheckpointBody":
		return &CheckpointBody{}
	case "PauseBody":
		return &PauseBody{}
	case "CallBody":
		return &CallBody{}
	case "BindingBody":
		return &BindingBody{}
	case "DigestBody":
		return &DigestBody{}
	case "RollupBody":
		return &RollupBody{}
	case "RetractionBody":
		return &RetractionBody{}
	case "ErasureBody":
		return &ErasureBody{}
	case "WithdrawalBody":
		return &WithdrawalBody{}
	case "KeyOpBody":
		return &KeyOpBody{}
	case "PolicyBody":
		return &PolicyBody{}
	}
	return nil
}

// saltOf and setSalt reach the Salt field of salted bodies.
func saltOf(b any) (string, bool) {
	switch v := b.(type) {
	case *SessionBody:
		return v.Salt, true
	case *SessionMetaBody:
		return v.Salt, true
	case *ChunkBody:
		return v.Salt, true
	case *ConclusionBody:
		return v.Salt, true
	case *TaskBody:
		return v.Salt, true
	case *TaskMetaBody:
		return v.Salt, true
	case *CheckpointBody:
		return v.Salt, true
	case *PauseBody:
		return v.Salt, true
	case *DigestBody:
		return v.Salt, true
	case *RollupBody:
		return v.Salt, true
	}
	return "", false
}

func setSalt(b any, s string) bool {
	switch v := b.(type) {
	case *SessionBody:
		v.Salt = s
	case *SessionMetaBody:
		v.Salt = s
	case *ChunkBody:
		v.Salt = s
	case *ConclusionBody:
		v.Salt = s
	case *TaskBody:
		v.Salt = s
	case *TaskMetaBody:
		v.Salt = s
	case *CheckpointBody:
		v.Salt = s
	case *PauseBody:
		v.Salt = s
	case *DigestBody:
		v.Salt = s
	case *RollupBody:
		v.Salt = s
	default:
		return false
	}
	return true
}
