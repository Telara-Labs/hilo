package record

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
)

var (
	surfaces       = set("cli", "ide", "desktop", "cloud", "connector")
	sessionEnds    = set("client-end", "idle", "source-gone")
	linkRelations  = set("fork", "resume", "subagent", "compaction")
	linkDirections = set("parent", "child")
	atPrecisions   = set("exact", "minute", "inferred")
	eventProvs     = set(string(ProvTranscript), string(ProvHook))
	outcomes       = set("ok", "error", "unknown")
	conclSources   = set("explicit", "final-answer", "hook-final")
	conclStates    = set("answered", "awaiting-user", "interrupted", "errored", "unknown")
	taskStatuses   = set("active", "completed", "abandoned")
	bindConfidence = map[string]int{"stated": 5, "transcript-echo": 4, "process-matched": 3, "handle-only": 2, "inferred": 1}
	bindStatuses   = set("bound", "ambiguous", "retracted")
	retractReasons = set("redaction_repair", "export_superseded", "rule_removed")
	eraseReasons   = set("user_request", "redaction_miss", "device_compromise", "retention_policy")
	withdrawReason = set("policy_narrowed", "user_removed", "offboarded", "kill_switch")
	taintSet       = set(TaintValues...)
	coverageSet    = set(CoverageValues...)
	flagSet        = set(FlagValues...)
	recalledRe     = regexp.MustCompile(`^[0-9a-f]{64}@[0-9a-f]{64}$`)
)

func set(v ...string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}

// ConfidenceRank returns the binding rank of a confidence value, 0
// for an unknown value.
func ConfidenceRank(c string) int { return bindConfidence[c] }

func uniqueHex64(list []string) bool {
	seen := map[string]bool{}
	for _, s := range list {
		if !IsHex64(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

func sortedUniqueIn(list []string, allowed map[string]bool) bool {
	if !sort.StringsAreSorted(list) {
		return false
	}
	for i, s := range list {
		if !allowed[s] || (i > 0 && list[i-1] == s) {
			return false
		}
	}
	return true
}

// provsForKind lists the provenance values any matrix row allows for k.
func provAllowed(k Kind, p Prov) bool {
	for _, r := range Matrix {
		if r.Kind == k && r.Prov == p {
			return true
		}
	}
	return false
}

func isExplicitProv(p Prov) bool { return p == ProvMCPExplicit || p == ProvGateway }

func validateHeader(h *Header) error {
	if !IsHex64(h.LID) {
		return rej(CodeInvalidHeader, "lid must be 64 lowercase hex")
	}
	if !IsKeyID(h.Author.KeyID) {
		return rej(CodeInvalidHeader, "author.key_id must be 32 lowercase hex")
	}
	if h.Author.MachineID != "" && !IsUUIDv4(h.Author.MachineID) {
		return rej(CodeInvalidHeader, "author.machine_id must be a lowercase UUIDv4")
	}
	if h.At <= 0 || h.At > jcs.MaxSafeInteger {
		return rej(CodeInvalidHeader, "at must be a positive unix ms time")
	}
	if !provAllowed(h.Type, h.Prov) {
		return rej(CodeProvNotAllowed, "prov %q is not allowed for %s", h.Prov, h.Type)
	}
	// subject
	s := h.Subj
	if s.SessionKey != "" && !IsSessionKey(s.SessionKey) {
		return rej(CodeInvalidHeader, "subj.session_key malformed")
	}
	if s.TaskID != "" && !IsUUID(s.TaskID) {
		return rej(CodeInvalidHeader, "subj.task_id must be a lowercase UUID")
	}
	if s.RepoID != "" && !IsRepoID(s.RepoID) {
		return rej(CodeInvalidHeader, "subj.repo_id malformed")
	}
	if s.Source != "" && !IsHex64(s.Source) {
		return rej(CodeInvalidHeader, "subj.source must be 64 hex")
	}
	if c := s.Client; c != nil {
		if !isToken(c.ID) || (c.Version != "" && !isToken(c.Version)) {
			return rej(CodeInvalidHeader, "subj.client id and version must be short identifiers")
		}
		if c.Surface != "" && !surfaces[c.Surface] {
			return rej(CodeInvalidHeader, "subj.client.surface %q", c.Surface)
		}
	}
	// redaction state
	switch {
	case ReservedProfiles[h.Red.Profile]:
		return rej(CodeProfileNotAllowed, "profile %q is reserved for a later extension", h.Red.Profile)
	case h.Red.Profile != ProfileLocal && h.Red.Profile != ProfilePushMetadata:
		return rej(CodeProfileNotAllowed, "profile %q", h.Red.Profile)
	}
	if h.Red.Epoch < 0 || h.Red.Findings < 0 {
		return rej(CodeInvalidHeader, "red.epoch and red.findings must not be negative")
	}
	if h.Red.Fingerprint != "" && !IsHex64(h.Red.Fingerprint) {
		return rej(CodeInvalidHeader, "red.fingerprint must be 64 hex")
	}
	if h.Pol != "" && !IsHex64(h.Pol) {
		return rej(CodeInvalidHeader, "pol must be a policy record id")
	}
	exportVariant := h.Prov == ProvDerived && (h.Type == KindSession || h.Type == KindTask)
	if exportVariant != (h.Red.Profile == ProfilePushMetadata) {
		return rej(CodeProfileNotAllowed, "push-metadata is exactly the profile of session and task export variants")
	}
	if exportVariant && h.Links.Origin == "" {
		return rej(CodeInvalidHeader, "an export variant must name its source in links.origin")
	}
	// trust
	if !sortedUniqueIn(h.Trust.Taint, taintSet) {
		return rej(CodeInvalidHeader, "trust.taint must be a sorted set of known values")
	}
	if h.Trust.Coverage != "" && !coverageSet[h.Trust.Coverage] {
		return rej(CodeInvalidHeader, "trust.coverage %q", h.Trust.Coverage)
	}
	if !sortedUniqueIn(h.Trust.Flags, flagSet) {
		return rej(CodeInvalidHeader, "trust.flags must be a sorted set of known values")
	}
	// links
	if !uniqueHex64(h.Links.Supersedes) || !uniqueHex64(h.Links.DerivedFrom) {
		return rej(CodeInvalidHeader, "links lists must hold distinct 64-hex ids")
	}
	if (h.Links.Origin != "" && !IsHex64(h.Links.Origin)) || (h.Links.Prev != "" && !IsHex64(h.Links.Prev)) {
		return rej(CodeInvalidHeader, "links.origin and links.prev must be 64-hex ids")
	}
	if h.Type.IsControl() && !h.Links.IsZero() {
		return rej(CodeInvalidHeader, "control records are never versioned and carry no links")
	}
	// body reference: every v1 kind has a body (OPEN-QUESTIONS Q11)
	if h.Body == nil {
		return rej(CodeInvalidHeader, "body reference is required")
	}
	if !IsHex64(h.Body.Digest) || h.Body.Size < 2 || h.Body.Size > MaxBodyBytes {
		return rej(CodeInvalidHeader, "body reference malformed")
	}
	// op
	needOp := h.Prov == ProvMCPExplicit || h.Type == KindCheckpoint || h.Type == KindPause
	if needOp && !IsHex64(h.Op) {
		return rej(CodeInvalidHeader, "op is required for this record")
	}
	if h.Op != "" && !(h.Prov == ProvMCPExplicit || h.Prov == ProvGateway) {
		return rej(CodeInvalidHeader, "op is only carried by explicit writes")
	}
	if h.Op != "" && !IsHex64(h.Op) {
		return rej(CodeInvalidHeader, "op must be 64 hex")
	}
	// per-kind identity fields
	need := func(ok bool, what string) error {
		if !ok {
			return rej(CodeInvalidHeader, "%s requires %s", h.Type, what)
		}
		return nil
	}
	hasMachine := h.Author.MachineID != ""
	switch h.Type {
	case KindSession, KindChunk, KindDigest:
		if err := need(s.SessionKey != "" && hasMachine, "subj.session_key and author.machine_id"); err != nil {
			return err
		}
	case KindConclusion:
		if isExplicitProv(h.Prov) {
			return need(s.TaskID != "", "subj.task_id")
		}
		return need(s.SessionKey != "", "subj.session_key")
	case KindTask:
		return need(s.TaskID != "", "subj.task_id")
	case KindCheckpoint:
		return need(s.TaskID != "", "subj.task_id")
	case KindPause, KindRollup:
		return need(s.TaskID != "" && hasMachine, "subj.task_id and author.machine_id")
	}
	return nil
}

func runes(s string) int { return utf8.RuneCountInString(s) }

func validateBody(h *Header, body any) error {
	if salted(h.Type) {
		salt, _ := saltOf(body)
		if !saltRe.MatchString(salt) {
			return rej(CodeInvalidBody, "%s body needs a 22-character base64url salt", h.Type)
		}
	}
	bad := func(format string, a ...any) error { return rej(CodeInvalidBody, format, a...) }
	long := func(format string, a ...any) error { return rej(CodeListTooLong, format, a...) }
	switch b := body.(type) {
	case *SessionBody:
		if b.NativeID == "" || (b.NativeIDKind != NativeGlobal && b.NativeIDKind != NativeLocal) {
			return bad("session: native_id and native_id_kind (global|local) are required")
		}
		if b.Page < 0 || b.StartedAt < 0 || b.LastEventAt < 0 || b.EndedAt < 0 || b.SettledThrough < 0 {
			return bad("session: negative page, time or seq")
		}
		if (b.EndedAt == 0) != (b.End == "") || (b.End != "" && !sessionEnds[b.End]) {
			return bad("session: end and ended_at must be set together, end in client-end|idle|source-gone")
		}
		if runes(b.Title) > MaxTitleRunes {
			return bad("session: title longer than %d runes", MaxTitleRunes)
		}
		if len(b.Chunks) > MaxSnapshotChunks {
			return long("session: %d chunk ids, limit %d", len(b.Chunks), MaxSnapshotChunks)
		}
		if !uniqueHex64(b.Chunks) {
			return bad("session: chunk ids must be distinct 64-hex ids")
		}
		for _, l := range b.Links {
			if err := checkSessionLink(&l); err != nil {
				return err
			}
		}
		if b.Repo != nil && b.Repo.ID != "" && !IsRepoID(b.Repo.ID) {
			return bad("session: repo.id malformed")
		}
		if b.Repo != nil && b.Repo.ID != "" && h.Subj.RepoID != "" && b.Repo.ID != h.Subj.RepoID {
			return bad("session: repo.id differs from subj.repo_id")
		}
	case *SessionMetaBody:
		if b.NativeIDKind != NativeGlobal && b.NativeIDKind != NativeLocal {
			return bad("session meta: native_id_kind must be global or local")
		}
		if (b.EndedAt == 0) != (b.End == "") || (b.End != "" && !sessionEnds[b.End]) {
			return bad("session meta: end and ended_at must be set together")
		}
		if runes(b.Title) > MaxTitleRunes {
			return bad("session meta: title longer than %d runes", MaxTitleRunes)
		}
		if len(b.Pointers) > MaxMetaPointers {
			return long("session meta: %d pointers, limit %d", len(b.Pointers), MaxMetaPointers)
		}
		if b.Repo != nil && b.Repo.ID != "" && !IsRepoID(b.Repo.ID) {
			return bad("session meta: repo.id malformed")
		}
		if b.StartedAt < 0 || b.LastEventAt < 0 || b.EndedAt < 0 {
			return bad("session meta: negative time")
		}
	case *ChunkBody:
		if len(b.Events) == 0 {
			return bad("chunk: at least one event")
		}
		if len(b.Events) > MaxChunkEvents {
			return long("chunk: %d events, limit %d", len(b.Events), MaxChunkEvents)
		}
		seen := map[string]bool{}
		for i, e := range b.Events {
			if !IsEventID(e.ID) || seen[e.ID] {
				return bad("chunk: event %d id malformed or repeated", i)
			}
			if !validEventSalt(e.Salt) {
				return bad("event protected salt")
			}
			if !IsHex64(e.Revision) || len(e.Replaces) > 8 || !sort.StringsAreSorted(e.Replaces) || !uniqueHex64(e.Replaces) || containsString(e.Replaces, e.Revision) {
				return bad("chunk: event revision or predecessors invalid")
			}
			if rev, err := EventRevision(e); err != nil || rev != e.Revision {
				return bad("chunk: event revision hash mismatch")
			}
			seen[e.ID] = true
			if i > 0 && e.Seq <= b.Events[i-1].Seq {
				return bad("chunk: events must be in strictly increasing seq order")
			}
			if e.Seq < 0 || e.At < 0 || e.Ruleset < 0 {
				return bad("chunk: event %d negative seq, time or ruleset", i)
			}
			if !eventKinds[e.Kind] || !eventProvs[e.Prov] {
				return bad("chunk: event %d kind %q or prov %q", i, e.Kind, e.Prov)
			}
			if e.AtPrecision != "" && !atPrecisions[e.AtPrecision] {
				return bad("chunk: event %d at_precision %q", i, e.AtPrecision)
			}
			for _, r := range e.Recalled {
				if !recalledRe.MatchString(r) {
					return bad("chunk: event %d recalled entry must be lid@id", i)
				}
			}
			if e.Link != nil {
				if err := checkSessionLink(e.Link); err != nil {
					return err
				}
			}
			if e.Result != nil && e.Result.Outcome != "" && !outcomes[e.Result.Outcome] {
				return bad("chunk: event %d result outcome %q", i, e.Result.Outcome)
			}
		}
	case *ConclusionBody:
		if !conclSources[b.Source] {
			return bad("conclusion: source %q", b.Source)
		}
		wantSource := map[Prov]string{ProvMCPExplicit: "explicit", ProvGateway: "explicit", ProvTranscript: "final-answer", ProvHook: "hook-final"}[h.Prov]
		if (b.Source != "explicit" || b.RequestKey != "") && !isToken(b.RequestKey) {
			return bad("conclusion: bounded native request_key is required")
		}
		if b.Source != wantSource {
			return bad("conclusion: source %q does not match prov %q", b.Source, h.Prov)
		}
		if b.State != "" && !conclStates[b.State] {
			return bad("conclusion: state %q", b.State)
		}
		if len(b.Request) > MaxRequestBytes || len(b.Text) > MaxTextBytes {
			return bad("conclusion: request ≤ %d bytes, text ≤ %d bytes", MaxRequestBytes, MaxTextBytes)
		}
		for _, s := range b.Supports {
			if !IsEventID(s) {
				return bad("conclusion: supports must be event ids")
			}
		}
		if b.Source != "explicit" && (len(b.ChangesMade) > 0 || b.TokenEstimate != nil) {
			return bad("conclusion: changes_made and token_estimate are explicit only")
		}
		if b.TokenEstimate != nil && *b.TokenEstimate < 0 {
			return bad("conclusion: negative token_estimate")
		}
	case *TaskBody:
		if !taskStatuses[b.Status] {
			return bad("task: status %q", b.Status)
		}
	case *TaskMetaBody:
		if b.Status != "" && !taskStatuses[b.Status] {
			return bad("task meta: status %q", b.Status)
		}
	case *CheckpointBody:
		for _, s := range b.Supports {
			if !IsEventID(s) {
				return bad("checkpoint: supports must be event ids")
			}
		}
	case *PauseBody:
		if b.TokenEstimate != nil && *b.TokenEstimate < 0 {
			return bad("pause: negative token_estimate")
		}
	case *CallBody:
		if !IsCallRef(b.CallRef) || b.ScopeID == "" || b.Tool == "" {
			return bad("call: call_ref, scope_id and tool are required")
		}
		if (b.ArgsHash != "" && !IsHex64(b.ArgsHash)) || (b.ResultHash != "" && !IsHex64(b.ResultHash)) {
			return bad("call: hashes must be 64 hex")
		}
		if b.TaskID != "" && !IsUUID(b.TaskID) {
			return bad("call: task_id must be a UUID")
		}
		if b.Outcome != "" && !outcomes[b.Outcome] {
			return bad("call: outcome %q", b.Outcome)
		}
	case *BindingBody:
		if !IsCallRef(b.CallRef) {
			return bad("binding: call_ref malformed")
		}
		if ConfidenceRank(b.Confidence) == 0 || !bindStatuses[b.Status] {
			return bad("binding: confidence %q or status %q", b.Confidence, b.Status)
		}
		if (b.Status == "bound") != (b.Target != nil) {
			return bad("binding: target is set exactly when status is bound")
		}
		if b.Target != nil && !IsSessionKey(b.Target.SessionKey) {
			return bad("binding: target.session_key malformed")
		}
		if b.Evidence != nil {
			for _, s := range b.Evidence.SightingEventIDs {
				if !IsEventID(s) {
					return bad("binding: sighting ids must be event ids")
				}
			}
		}
	case *DigestBody:
		// free-form derived content; bounded by the body size limit
	case *RollupBody:
		if !uniqueHex64(b.Covers) {
			return bad("rollup: covers must be distinct 64-hex ids")
		}
	case *RetractionBody:
		if len(b.IDs) == 0 {
			return bad("retraction: at least one id")
		}
		if len(b.IDs) > MaxRetractionIDs {
			return long("retraction: %d ids, limit %d", len(b.IDs), MaxRetractionIDs)
		}
		if !uniqueHex64(b.IDs) || !retractReasons[b.Reason] {
			return bad("retraction: ids must be distinct 64-hex ids; reason %q", b.Reason)
		}
	case *ErasureBody:
		n := b.Selectors.Count()
		if n == 0 {
			return bad("erasure: at least one selector")
		}
		if n > MaxErasureEntries {
			return long("erasure: %d selector entries, limit %d", n, MaxErasureEntries)
		}
		if !eraseReasons[b.Reason] || b.Resolved < 0 {
			return bad("erasure: reason %q", b.Reason)
		}
		if err := checkSelectors(b.Selectors.IDs, b.Selectors.LIDs, b.Selectors.Tasks, b.Selectors.Sessions); err != nil {
			return err
		}
		if !uniqueHex64(b.Selectors.Sources) {
			return bad("erasure: sources must be distinct 64-hex source keys")
		}
	case *WithdrawalBody:
		if b.Tenant == "" || !isToken(b.Tenant) || b.PolicySeq <= 0 {
			return bad("withdrawal: tenant is required")
		}
		if len(b.IDs) > MaxRetractionIDs {
			return long("withdrawal: %d ids, limit %d", len(b.IDs), MaxRetractionIDs)
		}
		if (len(b.IDs) == 0) == !b.All {
			return bad("withdrawal: either all or at least one id, not both")
		}
		if !uniqueHex64(b.IDs) || !withdrawReason[b.Reason] {
			return bad("withdrawal: ids must be distinct 64-hex ids; reason %q", b.Reason)
		}
	case *KeyOpBody:
		return validateKeyOpShape(b)
	case *PolicyBody:
		return ValidatePolicyShape(b)
	}
	return nil
}

func checkSessionLink(l *SessionLink) error {
	if !linkRelations[l.Relation] || !IsSessionKey(l.OtherSessionKey) || (l.Direction != "" && !linkDirections[l.Direction]) {
		return rej(CodeInvalidBody, "session link malformed")
	}
	return nil
}

func checkSelectors(ids, lids []string, tasks []TaskSelector, sessions []string) error {
	if !uniqueHex64(ids) || !uniqueHex64(lids) {
		return rej(CodeInvalidBody, "selector ids and lids must be distinct 64-hex values")
	}
	seen := map[string]bool{}
	for _, t := range tasks {
		key := t.Owner + "/" + t.TaskID
		if !ValidOwner(t.Owner) || !IsUUID(t.TaskID) || seen[key] {
			return rej(CodeInvalidBody, "selector tasks must be distinct owner/task UUID pairs")
		}
		seen[key] = true
	}
	for _, s := range sessions {
		if !IsSessionKey(s) || seen[s] {
			return rej(CodeInvalidBody, "selector sessions must be distinct session keys")
		}
		seen[s] = true
	}
	return nil
}

// Key operations.
const (
	OpGenesis         = "genesis"
	OpDeviceAdd       = "device_add"
	OpDeviceRotate    = "device_rotate"
	OpDeviceRevoke    = "device_revoke"
	OpTenantKey       = "tenant_key"
	OpTenantKeyRotate = "tenant_key_rotate"
)

// RevokeReasons are the device_revoke reasons. "compromised" cascades.
// "conflict" is not written by authors: the key state fold reports it for the
// losing subject of concurrent rotations.
var RevokeReasons = set("compromised", "lost", "user_request")

// MaxKeyOpParents bounds KeyOpBody.Parents.
const MaxKeyOpParents = 16

var keyOps = set(OpGenesis, OpDeviceAdd, OpDeviceRotate, OpDeviceRevoke, OpTenantKey, OpTenantKeyRotate)

func validateKeyOpShape(b *KeyOpBody) error {
	bad := func(format string, a ...any) error { return rej(CodeInvalidBody, format, a...) }
	if !keyOps[b.Op] {
		return bad("key_op: op %q is not supported", b.Op)
	}
	s := b.Subject
	if s.Alg != "ed25519" || !IsKeyID(s.KeyID) || s.Pub == "" {
		return bad("key_op: subject must be an ed25519 key with key_id and pub")
	}
	if s.Role != RoleDevice && s.Role != RoleService && s.Role != RolePolicy {
		return bad("key_op: subject role %q", s.Role)
	}
	if (s.Role == RoleDevice) != (s.MachineID != "") || (s.MachineID != "" && !IsUUIDv4(s.MachineID)) {
		return bad("key_op: a device key names its machine, other keys do not")
	}
	if b.Previous != "" && !IsKeyID(b.Previous) {
		return bad("key_op: previous must be a key id")
	}
	if len(b.Parents) > MaxKeyOpParents || !uniqueHex64(b.Parents) {
		return bad("key_op: parents must be at most %d distinct record ids", MaxKeyOpParents)
	}
	if root := b.Op == OpGenesis || b.Op == OpTenantKey; root != (len(b.Parents) == 0) {
		return bad("key_op: parents are empty exactly for genesis and tenant_key")
	}
	switch b.Op {
	case OpGenesis, OpDeviceAdd, OpDeviceRotate, OpDeviceRevoke:
		if s.Role != RoleDevice {
			return bad("key_op: %s concerns a device key", b.Op)
		}
		if !IsKeyID(b.Genesis) {
			return bad("key_op: %s must name its genesis key id", b.Op)
		}
		if b.Op == OpGenesis && b.Genesis != s.KeyID {
			return bad("key_op: a genesis names itself as genesis")
		}
	case OpTenantKey, OpTenantKeyRotate:
		if s.Role == RoleDevice || b.Genesis == "" || !isToken(b.Genesis) {
			return bad("key_op: %s concerns a service or policy key and names the tenant", b.Op)
		}
	}
	if (b.Op == OpDeviceRotate || b.Op == OpTenantKeyRotate) != (b.Previous != "") {
		return bad("key_op: previous is set exactly for rotations")
	}
	if (b.Op == OpDeviceRevoke) != (b.Reason != "") || (b.Reason != "" && !RevokeReasons[b.Reason]) {
		return bad("key_op: a revoke carries a known reason, other ops none")
	}
	return nil
}

// ValidatePolicyShape checks a policy body's fields. Freshness and
// sequence are checked by package policy.
func ValidatePolicyShape(b *PolicyBody) error {
	bad := func(format string, a ...any) error { return rej(CodeInvalidBody, format, a...) }
	if b.Tenant == "" || !isToken(b.Tenant) {
		return bad("policy: tenant is required")
	}
	if b.Seq <= 0 || b.IssuedAt <= 0 {
		return bad("policy: seq and issued_at must be positive")
	}
	if b.NotAfter <= b.IssuedAt || b.NotAfter > b.IssuedAt+PolicyMaxLifetimeMs {
		return bad("policy: not_after must be after issued_at and at most 30 days later")
	}
	if b.RefreshAfter != 0 && (b.RefreshAfter < b.IssuedAt || b.RefreshAfter > b.NotAfter) {
		return bad("policy: refresh_after must lie between issued_at and not_after")
	}
	if len(b.Applies.Users) == 0 {
		return bad("policy: applies.users is required")
	}
	for _, u := range b.Applies.Users {
		if u == "*" && len(b.Applies.Users) != 1 {
			return bad("policy: \"*\" stands alone in applies.users")
		}
		if u == "" {
			return bad("policy: empty user id")
		}
	}
	for _, r := range b.BlockedRepos {
		if r.RemoteGlob == "" || (r.Effect != "no-capture" && r.Effect != "no-push") {
			return bad("policy: blocked repo needs a glob and effect no-capture|no-push")
		}
	}
	if b.Redaction.MinEpoch < 0 {
		return bad("policy: negative min_epoch")
	}
	for _, s := range b.Redaction.Shapes {
		if s.Name == "" || s.RE2 == "" {
			return bad("policy: shape needs a name and a pattern")
		}
		if _, err := regexp.Compile(s.RE2); err != nil {
			return bad("policy: shape %q does not compile: %v", s.Name, err)
		}
	}
	if p := b.Push.MaxProfile; p != "" && p != ProfileLocal && p != ProfilePushMetadata {
		return bad("policy: push.max_profile %q", p)
	}
	return nil
}

// PolicyMaxLifetimeMs is the longest allowed span from issued_at to not_after.
const PolicyMaxLifetimeMs = 30 * 24 * 60 * 60 * 1000

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ValidOwner accepts only a genesis key id or a bounded tenant namespace.
func ValidOwner(owner string) bool {
	return IsKeyID(owner) || (strings.HasPrefix(owner, "tenant:") && isToken(strings.TrimPrefix(owner, "tenant:")))
}
