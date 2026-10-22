package record

// Kind is a record type (§2.1).
type Kind string

const (
	KindSession    Kind = "session"
	KindChunk      Kind = "chunk"
	KindConclusion Kind = "conclusion"
	KindTask       Kind = "task"
	KindCheckpoint Kind = "checkpoint"
	KindPause      Kind = "pause"
	KindCall       Kind = "call"
	KindBinding    Kind = "binding"
	KindDigest     Kind = "digest"
	KindRollup     Kind = "rollup"
	KindRetraction Kind = "retraction"
	KindErasure    Kind = "erasure"
	KindWithdrawal Kind = "withdrawal"
	KindKeyOp      Kind = "key_op"
	KindPolicy     Kind = "policy"
)

// Kinds lists every kind of the union, in specification order. Stores derive
// their checks from this list.
var Kinds = []Kind{
	KindSession, KindChunk, KindConclusion, KindTask, KindCheckpoint, KindPause,
	KindCall, KindBinding, KindDigest, KindRollup, KindRetraction, KindErasure,
	KindWithdrawal, KindKeyOp, KindPolicy,
}

// Class of a kind. It is a function of the type and is not in the header.
type Class string

const (
	ClassActivity   Class = "activity"
	ClassConclusion Class = "conclusion"
	ClassControl    Class = "control"
)

var kindClass = map[Kind]Class{
	KindSession: ClassActivity, KindChunk: ClassActivity, KindConclusion: ClassConclusion,
	KindTask: ClassConclusion, KindCheckpoint: ClassConclusion, KindPause: ClassConclusion,
	KindCall: ClassActivity, KindBinding: ClassActivity, KindDigest: ClassActivity,
	KindRollup: ClassConclusion, KindRetraction: ClassControl, KindErasure: ClassControl,
	KindWithdrawal: ClassControl, KindKeyOp: ClassControl, KindPolicy: ClassControl,
}

// Known reports whether k is a kind of the v1 union.
func (k Kind) Known() bool { _, ok := kindClass[k]; return ok }

// Class returns the class of k, or "" for an unknown kind.
func (k Kind) Class() Class { return kindClass[k] }

// IsControl reports whether k is a control kind.
func (k Kind) IsControl() bool { return kindClass[k] == ClassControl }

// Reducer of a kind (§1.5).
type Reducer string

const (
	HeadSingle Reducer = "head_single" // one current version
	HeadMulti  Reducer = "head_multi"  // concurrent heads all shown, a conflict
	Set        Reducer = "set"         // every live member counts
	Control    Reducer = "control"     // applied once, never versioned
)

// ReducerOf returns the reducer for a record of kind k with provenance p.
// Conclusions split by provenance: explicit (mcp-explicit, gateway) are
// HeadMulti, request conclusions (transcript, hook) are HeadSingle. Policy
// heads are chosen by sequence (package policy) and reported as HeadSingle.
func ReducerOf(k Kind, p Prov) Reducer {
	switch k {
	case KindSession, KindTask, KindDigest, KindRollup, KindPolicy:
		return HeadSingle
	case KindConclusion:
		if p == ProvMCPExplicit || p == ProvGateway {
			return HeadMulti
		}
		return HeadSingle
	case KindBinding:
		return HeadMulti
	case KindChunk, KindCheckpoint, KindPause, KindCall:
		return Set
	case KindRetraction, KindErasure, KindWithdrawal, KindKeyOp:
		return Control
	}
	return ""
}

// Prov is header provenance (§2.3), set by the author at capture and signed.
type Prov string

const (
	ProvTranscript  Prov = "transcript"
	ProvHook        Prov = "hook"
	ProvMCPExplicit Prov = "mcp-explicit"
	ProvDerived     Prov = "derived"
	ProvGateway     Prov = "gateway"
	ProvUser        Prov = "user"
)

// Provs lists every provenance value.
var Provs = []Prov{ProvTranscript, ProvHook, ProvMCPExplicit, ProvDerived, ProvGateway, ProvUser}

// Route is the receiver-side delivery route, never hashed or signed.
type Route string

const (
	RouteLocal        Route = "local"
	RouteHostedPull   Route = "hosted-pull"
	RouteBundleImport Route = "bundle-import"
	RouteGitImport    Route = "git-import"
)

// Role of a signing key (§4.1).
type Role string

const (
	RoleDevice  Role = "device"  // device record key (DRK)
	RoleService Role = "service" // tenant service key (TSK)
	RolePolicy  Role = "policy"  // tenant policy key (TPK)
)

// Redaction profiles (§6.3).
const (
	ProfileLocal        = "local"
	ProfilePushMetadata = "push-metadata"
)

// ReservedProfiles are names held for the deferred text extension. A v1
// receiver rejects them with profile_not_allowed.
var ReservedProfiles = map[string]bool{
	"push-conclusions": true, "push-excerpts": true, "hosted-stripped": true,
}

// Taint values, coverage values and flags (§10.1).
var (
	TaintValues    = []string{"foreign-path", "recalled-memory", "taint-unknown", "third-party-mcp", "web"}
	CoverageValues = []string{"complete", "incomplete", "unknown"}
	FlagValues     = []string{"hook-unconfirmed", "instruction-shaped"}
)

// Event kinds a chunk may hold.
var eventKinds = map[string]bool{
	"user_prompt": true, "injected_context": true, "assistant_text": true, "assistant_final": true,
	"tool_call": true, "tool_result": true, "approval": true, "session_meta": true, "link": true,
}

// MatrixRow is one allowed (role, prov, kind, body) combination of the
// signer and provenance matrix (§2.1). Body names the Go body type.
type MatrixRow struct {
	Role Role
	Prov Prov
	Kind Kind
	Body string
}

// Matrix is the complete signer and provenance matrix. Every other
// combination is forbidden. Key operations are listed with provenance
// "user"; their signers are checked by VerifyKeyOp (OPEN-QUESTIONS Q13).
var Matrix = []MatrixRow{
	{RoleDevice, ProvTranscript, KindSession, "SessionBody"},
	{RoleDevice, ProvHook, KindSession, "SessionBody"},
	{RoleDevice, ProvTranscript, KindChunk, "ChunkBody"},
	{RoleDevice, ProvHook, KindChunk, "ChunkBody"},
	{RoleDevice, ProvTranscript, KindConclusion, "ConclusionBody"},
	{RoleDevice, ProvHook, KindConclusion, "ConclusionBody"},
	{RoleDevice, ProvMCPExplicit, KindTask, "TaskBody"},
	{RoleDevice, ProvMCPExplicit, KindCheckpoint, "CheckpointBody"},
	{RoleDevice, ProvMCPExplicit, KindPause, "PauseBody"},
	{RoleDevice, ProvMCPExplicit, KindConclusion, "ConclusionBody"},
	{RoleDevice, ProvMCPExplicit, KindCall, "CallBody"},
	{RoleDevice, ProvDerived, KindBinding, "BindingBody"},
	{RoleDevice, ProvDerived, KindDigest, "DigestBody"},
	{RoleDevice, ProvDerived, KindRollup, "RollupBody"},
	{RoleDevice, ProvDerived, KindSession, "SessionMetaBody"},
	{RoleDevice, ProvDerived, KindTask, "TaskMetaBody"},
	{RoleDevice, ProvUser, KindRetraction, "RetractionBody"},
	{RoleDevice, ProvUser, KindErasure, "ErasureBody"},
	{RoleDevice, ProvUser, KindKeyOp, "KeyOpBody"},
	{RoleService, ProvGateway, KindTask, "TaskBody"},
	{RoleService, ProvGateway, KindCheckpoint, "CheckpointBody"},
	{RoleService, ProvGateway, KindConclusion, "ConclusionBody"},
	{RoleService, ProvUser, KindWithdrawal, "WithdrawalBody"},
	{RoleService, ProvUser, KindRetraction, "RetractionBody"},
	{RoleService, ProvUser, KindErasure, "ErasureBody"},
	{RoleService, ProvUser, KindKeyOp, "KeyOpBody"},
	{RolePolicy, ProvUser, KindPolicy, "PolicyBody"},
	{RolePolicy, ProvUser, KindKeyOp, "KeyOpBody"},
}

// BodyTypeName returns the Go body type a (kind, prov) pair carries, or "" if
// no matrix row has that pair.
func BodyTypeName(k Kind, p Prov) string {
	for _, r := range Matrix {
		if r.Kind == k && r.Prov == p {
			return r.Body
		}
	}
	return ""
}

// MatrixAllows reports whether (role, prov, kind) is a row of the matrix.
// The body type is a function of (kind, prov), so it needs no separate check.
func MatrixAllows(role Role, p Prov, k Kind) bool {
	for _, r := range Matrix {
		if r.Role == role && r.Prov == p && r.Kind == k {
			return true
		}
	}
	return false
}

// salted reports whether a kind's body must carry a salt (R1.4).
func salted(k Kind) bool {
	switch k {
	case KindSession, KindChunk, KindConclusion, KindTask, KindCheckpoint, KindPause, KindDigest, KindRollup:
		return true
	}
	return false
}
