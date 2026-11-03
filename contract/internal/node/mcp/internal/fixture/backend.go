package fixture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	tapredact "github.com/Telara-Labs/TAP-Runtime/discover/redact"
	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
)

type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
type Result struct {
	IsError bool      `json:"isError"`
	Content []Content `json:"content"`
}

func result(text string, bad bool) Result { return Result{bad, []Content{{"text", text}}} }

// Item is a detached, currently permitted receiver projection. No raw body or
// structuredContent is ever returned. Labels must come from receiver evaluation.
type Item struct {
	Explicit                                              bool
	ID, LID, Owner, TaskID, RepoID, Kind, State           string
	Source, Signature, Coverage, Trust, Evidence, Outcome string
	Fields                                                map[string]string
	Order                                                 int64
}
type Query struct {
	TaskSummariesOnly                               bool
	Tool, TaskID, EntityID, Text, Focus, EntityType string
	Kinds, Edges                                    []string
	IncludeCompleted, IncludeContent                bool
	Limit                                           int
}

// Mutation fields are structurally redacted in full, then bounded. Append MUST
// run the real Seal pipeline, compute owner-scoped LID, salt and sign, and update
// task heads/reducers in this same transaction. It must preserve every field.
type Mutation struct {
	Kind, TaskID string
	Fields       map[string]any
}
type Call struct {
	RedactionFindings  int
	Access             Access
	Tool, Op, ArgsHash string
	Arguments          []byte // redacted canonical JSON only
}
type Transaction interface {
	// Items enforces current installed grant, tenant ceiling, channel S, owner
	// namespace, dependency eligibility and bounded search/context projection.
	// Nonempty TaskID selects a bounded task brief across ALL visible owners,
	// ignoring list text/status/limit filters until ownership is resolved.
	Items(Query) ([]Item, error)
	Append(Mutation) (Item, error)
	ReserveCallRef(string) (bool, error)
	// Exposure is conservative, synchronous and independent of delivery dedup.
	Exposure(callRef, nonce string, items []string) error
}

// Store is the required atomic MCP boundary. Execute rechecks authority on every
// replay, binds op to tool/args, and never repeats a committed mutation. It must
// atomically persist all Seal-backed call/binding records, mutation, result hash,
// dependencies, render versions and exposure before returning. Replay uses current
// eligibility/labels or the fixed unavailable-memory response. Errors roll back.
// A Snapshot+Append adapter cannot implement this interface safely.
type Store interface {
	Execute(context.Context, Call, func(Transaction) (Result, error)) (Result, error)
	Close() error
}
type Backend struct {
	store    Store
	resolver Resolver
}

func New(store Store, resolver Resolver) *Backend { return &Backend{store: store, resolver: resolver} }
func (b *Backend) StoreWired() bool               { return b.store != nil }
func (b *Backend) Close() error {
	if b.store != nil {
		return b.store.Close()
	}
	return nil
}

func rpcError(req daemon.Request, code int, message string) daemon.Response {
	return daemon.Response{JSONRPC: "2.0", ID: req.ID, Error: &daemon.RPCError{Code: code, Message: message}}
}
func (b *Backend) Handle(ctx context.Context, h ipc.Hello, req daemon.Request) daemon.Response {
	if out, ok := daemon.Setup(req); ok {
		return out
	}
	out := daemon.Response{JSONRPC: "2.0", ID: req.ID}
	params, m, e := daemon.RequestParams(req.Params)
	if e != nil {
		return rpcError(req, -32602, e.Error())
	}
	switch req.Method {
	case "resources/list":
		if !emptyParams(params) {
			return rpcError(req, -32602, "invalid_arguments")
		}
		out.Result = map[string]any{"resources": []any{}, "ttlMs": 15000, "cacheScope": "private"}
		return out
	case "resources/templates/list":
		if !emptyParams(params) {
			return rpcError(req, -32602, "invalid_arguments")
		}
		out.Result = map[string]any{"resourceTemplates": []any{}, "ttlMs": 15000, "cacheScope": "private"}
		return out
	case "prompts/list":
		if !emptyParams(params) {
			return rpcError(req, -32602, "invalid_arguments")
		}
		out.Result = map[string]any{"ttlMs": 15000, "cacheScope": "private", "prompts": []any{map[string]any{"name": "start-task", "description": "Use explicit local task tools when useful."}, map[string]any{"name": "checkpoint", "description": "Record an explicit milestone."}, map[string]any{"name": "finish-task", "description": "Record an agent-declared conclusion."}}}
		return out
	case "prompts/get":
		// P requires verified complete coverage and a committed exposure boundary.
		return rpcError(req, -32000, "prompt_unavailable")
	case "tools/call":
	default:
		return rpcError(req, -32601, "method_not_found")
	}
	if len(req.Params) > 1<<20 {
		return rpcError(req, -32602, "invalid_arguments")
	}
	raw := params
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if ipc.DecodeStrict(raw, &p) != nil {
		return rpcError(req, -32602, "invalid_arguments")
	}
	a, e := arguments(p.Name, p.Arguments)
	if e != nil {
		if e.Error() == "unsupported_tool" || errors.Is(e, errFilter) {
			out.Result = result(e.Error(), true)
			return out
		}
		return rpcError(req, -32602, "invalid_arguments")
	}

	// Always redact decoded full values BEFORE hashing or display bounds. No raw
	// argument/error value is persisted, logged, or interpolated in diagnostics.
	clean := redactObject(a)
	args, e := jcs.MarshalRecord(clean)
	if e != nil {
		return rpcError(req, -32602, "invalid_arguments")
	}
	if !validRPCID(req.ID) {
		return rpcError(daemon.Request{ID: json.RawMessage("null")}, -32602, "invalid_identity")
	}
	if b.store == nil || b.resolver == nil {
		out.Result = result("store_unavailable", true)
		return out
	}
	access, e := b.resolver.Resolve(ctx, h, m)
	if e != nil {
		if errors.Is(e, errIdentity) {
			return rpcError(req, -32602, "invalid_identity")
		}
		out.Result = result("identity_unavailable", true)
		return out
	}
	call := Call{Access: access, Tool: p.Name, ArgsHash: record.BodyDigest(args), Arguments: args}
	full, _ := jcs.MarshalRecord(a)
	if string(full) != string(args) {
		call.RedactionFindings = 1
	}
	if m.OpID != "" {
		call.Op, e = record.HE("fixture-supplied", access.CredentialID, m.OpID)
	} else {
		// Unidentified callers receive a fresh isolated scope, never restored state.
		// An ambiguous scope (03 section 3 step 5) never supplies retry identity.
		scope := access.ScopeID
		if scope == "" || access.Ambiguous {
			scope, e = randomHex(16)
			if e != nil {
				out.Result = result("storage_error", true)
				return out
			}
		}
		call.Op, e = fallbackOpID(scope, daemon.ConnectionID(ctx), req.CorrelationID(), p.Name, call.ArgsHash)
	}
	if e != nil {
		out.Result = result("identity_unavailable", true)
		return out
	}
	res, e := b.store.Execute(ctx, call, func(tx Transaction) (Result, error) { return execute(tx, call, clean) })
	if e != nil {
		out.Result = result(publicError(e), true)
	} else {
		out.Result = res
	}
	return out
}
func emptyParams(raw []byte) bool {
	if len(raw) == 0 {
		return true
	}
	b, e := jcs.Canonicalize(raw)
	return e == nil && string(b) == "{}"
}
func randomHex(n int) (string, error) {
	v := make([]byte, n)
	_, e := rand.Read(v)
	return hex.EncodeToString(v), e
}
func publicError(e error) string {
	switch e.Error() {
	case "op_conflict", "not_found", "ambiguous_id", "read_only", "unsupported_filter", "cursor_expired", "store_unavailable", "identity_unavailable", "render_unavailable":
		return e.Error()
	}
	return "storage_error"
}
func redactObject(a map[string]any) map[string]any {
	out := make(map[string]any, len(a))
	for k, v := range a {
		out[k] = redactValue(k, v)
	}
	return out
}
func redactValue(key string, v any) any {
	switch x := v.(type) {
	case string:
		return tapredact.Redact(tapredact.Argument(key, x))
	case map[string]any:
		return redactObject(x)
	case []any:
		out := make([]any, len(x))
		for i, y := range x {
			out[i] = redactValue(key, y)
		}
		return out
	default:
		return v
	}
}
func stringValue(a map[string]any, k string) string { s, _ := a[k].(string); return s }
func boolValue(a map[string]any, k string) bool     { v, _ := a[k].(bool); return v }
func intValue(a map[string]any, k string, def int) int {
	v, ok := a[k].(float64)
	if ok {
		return int(v)
	}
	return def
}
func stringsValue(a map[string]any, k string) []string {
	var out []string
	for _, v := range array(a, k) {
		out = append(out, v.(string))
	}
	return out
}
func execute(tx Transaction, call Call, a map[string]any) (Result, error) {
	var ref string
	for n := 0; n < 8; n++ {
		var e error
		ref, e = record.NewCallRef()
		if e != nil {
			return Result{}, e
		}
		ok, e := tx.ReserveCallRef(ref)
		if e != nil {
			return Result{}, e
		}
		if ok {
			break
		}
		ref = ""
	}
	if ref == "" {
		return Result{}, errors.New("call_ref_exhausted")
	}
	q := Query{Tool: call.Tool, TaskID: stringValue(a, "task_id"), EntityID: stringValue(a, "entity_id"), EntityType: stringValue(a, "entity_type"), Text: stringValue(a, "query"), Focus: stringValue(a, "focus_query"), Kinds: stringsValue(a, "resource_types"), Edges: stringsValue(a, "edge_types"), IncludeCompleted: boolValue(a, "include_completed"), IncludeContent: boolValue(a, "include_content"), Limit: intValue(a, "limit", 10)}
	if call.Tool == "telara_get_context" {
		q.Limit = 1 + intValue(a, "max_related", 5)
	}
	if call.Tool == "telara_task_list" {
		if stringValue(a, "mode") == "detail" {
			q.Limit = intValue(a, "limit", 25)
		}
		if q.TaskID == "" && record.IsUUID(strings.TrimSpace(q.Text)) {
			q.TaskID = strings.TrimSpace(q.Text)
		}
		if q.TaskID != "" {
			// Exact reads are a task brief, including completed tasks and checkpoints.
			// Caller list limits/status/text filters never hide it. Store bounds still
			// apply and selection must include all visible owners before rendering.
			q.Text = ""
			q.IncludeCompleted = true
			q.Limit = 64
		}
	}
	for i, k := range q.Kinds {
		if k == "task_summary" {
			q.Kinds[i] = "conclusion"
			q.TaskSummariesOnly = true
		}
	}
	for _, k := range stringsValue(a, "resource_types") {
		if k == "conclusion" {
			q.TaskSummariesOnly = false
		}
	}
	if q.EntityType == "task_summary" {
		q.EntityType = "conclusion"
		q.TaskSummariesOnly = true
	}
	var selected []Item
	var hint string
	switch call.Tool {
	case "telara_task_create":
		task, e := uuid()
		if e != nil {
			return Result{}, e
		}
		fields := boundObject(a)
		if stringValue(fields, "name") == "" {
			fields["name"] = boundText(stringValue(fields, "goal"), 100)
		}
		item, e := tx.Append(Mutation{"task", task, fields})
		if e != nil {
			return Result{}, e
		}
		selected = []Item{item}
	case "telara_task_checkpoint", "telara_task_pause", "telara_task_complete", "telara_task_resume", "telara_task_list":
		if call.Tool == "telara_task_list" && q.TaskID == "" {
			var e error
			selected, e = tx.Items(q)
			if e != nil {
				return Result{}, e
			}
			break
		}
		// Selection includes EVERY visible owner for this task id before limit. The
		// store must never return inaccessible matches or their existence/counts.
		candidates, e := tx.Items(q)
		if e != nil {
			return Result{}, e
		}
		owners := map[string]bool{}
		for _, item := range candidates {
			if item.TaskID == q.TaskID && eligible(item) {
				owners[item.Owner] = true
			}
		}
		if len(owners) == 0 {
			return result("call_ref "+ref+"\nRequested local record or task is unavailable.", true), nil
		}
		if len(owners) > 1 {
			return result("call_ref "+ref+"\nambiguous_id", true), nil
		}
		if call.Tool != "telara_task_resume" && call.Tool != "telara_task_list" {
			if !owners[call.Access.Owner] {
				return result("call_ref "+ref+"\nread_only", true), nil
			}
			k := map[string]string{"telara_task_checkpoint": "checkpoint", "telara_task_pause": "pause", "telara_task_complete": "conclusion"}[call.Tool]
			item, e := tx.Append(Mutation{k, q.TaskID, boundObject(a)})
			if e != nil {
				return Result{}, e
			}
			selected = []Item{item}
		} else {
			for _, item := range candidates {
				if item.TaskID == q.TaskID {
					selected = append(selected, item)
				}
			}
		}
	case "telara_knowledge_search":
		if strings.TrimSpace(q.Text) == "" {
			hint = "Query required. Use task_list."
		} else {
			var e error
			selected, e = tx.Items(q)
			if e != nil {
				return Result{}, e
			}
		}
	case "telara_get_context":
		var e error
		selected, e = tx.Items(q)
		if e != nil {
			return Result{}, e
		}
	}
	if call.Tool == "telara_get_context" {
		found := false
		for _, it := range selected {
			if it.ID == q.EntityID && eligible(it) && (!q.TaskSummariesOnly || it.Kind != "conclusion" || it.Explicit) {
				found = true
			}
		}
		if !found {
			return result("call_ref "+ref+"\nRequested local record or task is unavailable.", true), nil
		}
	}
	// The transaction is authoritative, but do not render obviously held rows even
	// if an adapter violates its projection contract. Missing labels fail closed.
	filtered := make([]Item, 0, len(selected))
	for _, it := range selected {
		if q.TaskSummariesOnly && it.Kind == "conclusion" && !it.Explicit {
			continue
		}
		if call.Tool == "telara_get_context" && !q.IncludeContent {
			fields := map[string]string{}
			for _, key := range []string{"name", "title", "status"} {
				if value, ok := it.Fields[key]; ok {
					fields[key] = value
				}
			}
			it.Fields = fields
		}
		if !eligible(it) {
			return Result{}, errors.New("render_unavailable")
		}
		filtered = append(filtered, it)
	}
	if call.Tool == "telara_task_list" && q.TaskID == "" {
		sort.SliceStable(filtered, func(i, j int) bool {
			ai := filtered[i].Fields["status"] == "active"
			aj := filtered[j].Fields["status"] == "active"
			if ai != aj {
				return ai
			}
			return filtered[i].Order > filtered[j].Order
		})
	}
	if len(filtered) > 64 {
		return Result{}, errors.New("render_unavailable")
	}
	if len(filtered) > q.Limit {
		filtered = filtered[:q.Limit]
		hint = "Selection truncated at the requested limit."
	}
	budget := intValue(a, "max_tokens", 4000) // conservative UTF-8 byte cap, never four-bytes-per-token
	nonce, e := randomHex(10)
	if e != nil {
		return Result{}, e
	}
	rendered, e := render(ref, nonce, filtered, hint, budget)
	if e != nil {
		return Result{}, e
	}
	if e = tx.Exposure(ref, nonce, rendered.Items); e != nil {
		return Result{}, e
	}
	return result(rendered.Text, false), nil
}
func eligible(i Item) bool {
	return record.IsHex64(i.ID) && record.IsHex64(i.LID) && i.Owner != "" && (i.State == "live" || i.State == "ancestry-pending") && i.Signature != "" && i.Coverage != "" && i.Trust != "" && i.Source != "" && i.Evidence != ""
}
func uuid() (string, error) {
	v := make([]byte, 16)
	if _, e := rand.Read(v); e != nil {
		return "", e
	}
	v[6] = (v[6] & 15) | 64
	v[8] = (v[8] & 63) | 128
	s := hex.EncodeToString(v)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}

// Bounds apply only after structural redaction. Canonical args hash uses full
// redacted input; truncation cannot turn changed retry arguments into equality.
func boundObject(a map[string]any) map[string]any {
	out := make(map[string]any, len(a))
	for k, v := range a {
		switch x := v.(type) {
		case string:
			out[k] = boundText(x, 16384)
		case map[string]any:
			out[k] = boundObject(x)
		case []any:
			y := make([]any, len(x))
			for i, z := range x {
				switch z := z.(type) {
				case string:
					y[i] = boundText(z, 16384)
				case map[string]any:
					y[i] = boundObject(z)
				default:
					y[i] = z
				}
			}
			out[k] = y
		default:
			out[k] = v
		}
	}
	return out
}

// JSON-RPC IDs are opaque correlation, not installed or native identity.
// Their only use beyond echoing the response is FallbackOpID's one-way hash;
// neither Call nor a sealed receipt contains the raw ID.
func validRPCID(raw []byte) bool { return daemon.ValidRPCID(raw) }
