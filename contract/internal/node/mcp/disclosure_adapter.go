package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

// ProofSource is installed authority. It must authenticate the local peer and
// drain its pending signals before returning an owned copy of a kernel proof.
// Hello fields and request metadata alone are never proof of a credential.
// The adapter clears Token after authentication; sources must not lend buffers.
type ProofSource interface {
	Proof(context.Context, ipc.Hello) (disclosure.CredentialProof, error)
}

// DisclosureAdapter uses only fixed commands and the opaque release boundary.
// It cannot access a SQLite transaction, sign a record or render memory text.
type DisclosureAdapter struct {
	mu          sync.Mutex
	service     *disclosure.Service
	source      ProofSource
	closeStore  func() error
	closed      bool
	ready       atomic.Bool
	unavailable string
	connections map[string]adapterConnection
}

type adapterConnection struct {
	client     *disclosure.Connection
	proofHash  [32]byte
	credential string
}

func NewDisclosure(service *disclosure.Service, source ProofSource, closeStore func() error) *Backend {
	a := &DisclosureAdapter{service: service, source: source, closeStore: closeStore, connections: map[string]adapterConnection{}}
	a.ready.Store(service != nil && source != nil)
	return &Backend{disclosure: a}
}

func (a *DisclosureAdapter) close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	a.ready.Store(false)
	// Close runs after in-flight calls under the same mutex. Retire every
	// retained kernel handle before closing its authority and storage.
	for key, connection := range a.connections {
		_ = connection.client.Close()
		delete(a.connections, key)
	}
	if a.service != nil {
		if err := a.service.Close(); err != nil {
			return err
		}
	}
	if a.closeStore != nil {
		return a.closeStore()
	}
	return nil
}

func (a *DisclosureAdapter) call(ctx context.Context, hello ipc.Hello, meta Metadata, req daemon.Request, tool string, raw json.RawMessage) Result {
	// Serializing the adapter also keeps close from destroying owned material
	// while a request is between Execute and Release.
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.service == nil || a.source == nil {
		if a.unavailable != "" {
			return result(a.unavailable, true)
		}
		return result("store_unavailable", true)
	}
	if daemon.ConnectionID(ctx) == "" {
		return result("identity_unavailable", true)
	}
	command, budget, err := translateCommand(tool, raw)
	if err != nil {
		return result(adapterError(err), true)
	}
	proof, err := a.source.Proof(ctx, hello)
	if err != nil {
		clear(proof.Token)
		return result("identity_unavailable", true)
	}
	// Cache only identified scopes on the daemon-minted transport identity.
	// Refuse new connections at the bound rather than silently evict retry identity.
	identified := meta.Handle != ""
	key := daemon.ConnectionID(ctx)
	digest := sha256.Sum256(proof.Token)
	cached, found := a.connections[key]
	var connection *disclosure.Connection
	if identified && found {
		if cached.credential != proof.CredentialID || cached.proofHash != digest {
			clear(proof.Token)
			return result("identity_unavailable", true)
		}
		connection = cached.client
	} else {
		if identified && len(a.connections) >= 128 {
			clear(proof.Token)
			return result("connection_limit", true)
		}
		connection, err = a.service.Authenticate(ctx, proof)
		if err == nil && identified {
			a.connections[key] = adapterConnection{connection, digest, proof.CredentialID}
		}
	}
	clear(proof.Token)
	if err != nil {
		return result(adapterError(err), true)
	}
	// Every unidentified invocation owns its handle, including early refusals.
	// Close reclaims live kernel quota without discarding durable settlement.
	if !identified {
		defer connection.Close()
	}
	input := disclosure.IdentityInput{ConversationHandle: meta.Handle}
	// Native metadata has no trusted observation ingress in this kernel. Never
	// drop it and fall back to a weaker conversation or transport identity.
	if meta.Native != nil {
		return result("scope_resolution_unsupported", true)
	}
	if meta.ProtocolVersion != daemon.LatestProtocolVersion && meta.Handle == "" {
		input.LegacySessionID = meta.Legacy
		input.ShimInstanceID = hello.Shim
	}
	scope, err := connection.Resolve(ctx, input)
	if err != nil {
		// Resolve closes a refused facade connection. Do not retain an unusable
		// cache entry for the rest of a healthy transport's lifetime.
		if identified {
			delete(a.connections, key)
		}
		return result(adapterError(err), true)
	}
	reply, err := connection.Execute(ctx, scope, disclosure.CallIdentity{SuppliedOpID: meta.OpID, JSONRPCID: req.CorrelationID()}, command, budget)
	if err != nil {
		return result(adapterError(err), true)
	}
	released, err := reply.Release(ctx)
	if err != nil {
		return result(adapterError(err), true)
	}
	if len(released.Content) != 1 || released.Content[0].Type != "text" {
		return result("render_unavailable", true)
	}
	return result(released.Content[0].Text, released.IsError)
}

// issueTokens exposes only committed receiver-issued tokens. It installs no
// grant and retains no connection scope or correlation from initialize.
func (a *DisclosureAdapter) issueTokens(ctx context.Context, hello ipc.Hello) ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.service == nil || a.source == nil {
		return nil, errors.New("runtime_authority_unavailable")
	}
	if daemon.ConnectionID(ctx) == "" {
		return nil, errors.New("unauthorized")
	}
	proof, err := a.source.Proof(ctx, hello)
	defer clear(proof.Token)
	if err != nil {
		return nil, errors.New("unauthorized")
	}
	connection, err := a.service.Authenticate(ctx, proof)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	return connection.IssueOperationTokens(ctx)
}

func adapterError(err error) string {
	switch err.Error() {
	case "op_conflict", "not_found", "ambiguous_id", "read_only", "unsupported_filter", "unsupported_argument", "unsupported_tool", "invalid_arguments", "argument_limit", "missing_argument", "invalid_budget", "scope_resolution_unsupported", "unsafe_identity", "unauthorized", "credential_revoked", "stale_credential", "read_not_permitted", "write_not_permitted", "owner_blocked", "scope_limit", "connection_limit", "cursor_expired", "op_schema_unavailable", "privacy_hold_required", "lineage_evaluation_required", "runtime_authority_unavailable", "unissued_operation", "unsafe_operation_identity", "request_limit", "disclosure_unavailable":
		return err.Error()
	}
	return "storage_error"
}

var errUnsupportedArgument = errors.New("unsupported_argument")

// translateCommand retains original JSON numbers for the kernel's exact decimal
// validation. No argument hash or response cache is maintained by the adapter.
func translateCommand(tool string, raw json.RawMessage) (disclosure.Command, disclosure.ByteBudget, error) {
	var empty disclosure.Command
	budget := disclosure.ByteBudget{MaxBytes: 4000}
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	checked, err := arguments(tool, raw)
	if err != nil {
		return empty, budget, err
	}
	var args map[string]json.RawMessage
	if json.Unmarshal(raw, &args) != nil {
		return empty, budget, errArguments
	}
	if raw, ok := args["max_tokens"]; ok {
		n, err := exactByteBudget(raw)
		if err != nil {
			return empty, budget, err
		}
		budget.MaxBytes = n
	}
	if budget.MaxBytes < 2048 {
		return empty, budget, errors.New("invalid_budget")
	}
	delete(args, "max_tokens")
	out := map[string]json.RawMessage{}
	copyFields := func(names ...string) {
		for _, name := range names {
			if v, ok := args[name]; ok {
				out[name] = v
				delete(args, name)
			}
		}
	}
	local := ""
	switch tool {
	case "telara_task_create":
		local = "local.create_task"
		copyFields("goal", "name")
		if v, ok := args["anchors"]; ok {
			var anchors map[string]json.RawMessage
			if json.Unmarshal(v, &anchors) != nil {
				return empty, budget, errArguments
			}
			for k, v := range anchors {
				if k != "file_paths" {
					return empty, budget, errUnsupportedArgument
				}
				out["file_paths"] = v
			}
			delete(args, "anchors")
		}
	case "telara_task_checkpoint":
		local = "local.checkpoint_task"
		copyFields("task_id", "milestone", "next_steps", "knowledge_refs", "task_tree")
	case "telara_task_pause":
		local = "local.pause_task"
		copyFields("task_id", "resume_context", "progress_notes", "handoff_hint", "token_estimate")
	case "telara_task_complete":
		local = "local.complete_task"
		copyFields("task_id", "final_summary", "changes_made", "token_estimate")
	case "telara_task_resume":
		local = "local.resume_task"
		copyFields("task_id")
	case "telara_task_list":
		local = "local.list_tasks"
		id, _ := checked["task_id"].(string)
		q, _ := checked["query"].(string)
		if id == "" && record.IsUUID(strings.TrimSpace(q)) {
			id = q
		}
		if id != "" {
			// A list-to-resume alias would let the same supplied op cross two public
			// tool names without op_conflict. The kernel has no original-tool identity
			// parameter, so exact list lookup cannot preserve that boundary today.
			return empty, budget, errUnsupportedArgument
		}
		copyFields("include_completed", "limit", "mode", "query")
		if v, ok := checked["include_receipts"]; ok && v == true {
			return empty, budget, errUnsupportedArgument
		}
		delete(args, "include_receipts")
	case "telara_knowledge_search":
		local = "local.lexical_search"
		copyFields("query", "limit", "resource_types")
		if v, ok := checked["resource_types"]; ok {
			kinds := v.([]any)
			mapped := make([]string, 0, len(kinds))
			seen := map[string]bool{}
			for _, v := range kinds {
				k := v.(string)
				if k == "conclusion" {
					k = "task_summary"
				}
				if k != "checkpoint" && k != "task_summary" && k != "session" && k != "evidence" {
					return empty, budget, errFilter
				}
				if !seen[k] {
					mapped = append(mapped, k)
					seen[k] = true
				}
			}
			if len(mapped) == 0 {
				// MCP defines [] as no restriction. The kernel installs its
				// supported default kinds only when this field is absent.
				delete(out, "resource_types")
			} else {
				out["resource_types"], _ = json.Marshal(mapped)
			}
		}
		for _, k := range []string{"people", "integration_types", "entity_concepts", "topic_concepts", "example_resource_id", "min_similarity", "cursor"} {
			if v, ok := checked[k]; ok && meaningful(v) {
				return empty, budget, errFilter
			}
			delete(args, k)
		}
	case "telara_get_context":
		local = "local.lookup_record"
		out["record_id"] = args["entity_id"]
		delete(args, "entity_id")
		kind := checked["entity_type"].(string)
		// Search-only projections have no exact record-kind equivalent.
		if kind == "task_summary" || kind == "evidence" {
			return empty, budget, errFilter
		}
		out["record_kind"], _ = json.Marshal(kind)
		delete(args, "entity_type")
		// The public tool defaults to metadata only, unlike local lookup.
		out["include_content"] = json.RawMessage("false")
		copyFields("include_content")
		for _, key := range []string{"edge_types", "focus_query"} {
			if meaningful(checked[key]) {
				return empty, budget, errFilter
			}
			delete(args, key)
		}
		// No graph neighborhood is implemented. Do not silently drop a limit.
		if _, ok := args["max_related"]; ok {
			return empty, budget, errFilter
		}
	default:
		return empty, budget, errors.New("unsupported_tool")
	}
	if len(args) != 0 {
		return empty, budget, errUnsupportedArgument
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return empty, budget, errArguments
	}
	cmd, err := disclosure.DecodeCommand(local, encoded)
	return cmd, budget, err
}

// exactByteBudget validates original decimal spelling before float64 schema
// rounding can turn a fractional request into an integer. Numeric work is
// bounded independently of the public JSON envelope.
func exactByteBudget(raw []byte) (int, error) {
	if len(raw) == 0 || len(raw) > 64 {
		return 0, errors.New("invalid_budget")
	}
	value := strings.TrimSpace(string(raw))
	if at := strings.IndexAny(value, "eE"); at >= 0 {
		exponent, err := strconv.ParseInt(value[at+1:], 10, 16)
		if err != nil || exponent < -128 || exponent > 128 {
			return 0, errors.New("invalid_budget")
		}
	}
	n, ok := new(big.Rat).SetString(value)
	if !ok || !n.IsInt() || !n.Num().IsInt64() {
		return 0, errors.New("invalid_budget")
	}
	v := n.Num().Int64()
	if v < 2048 || v > 20000 {
		return 0, errors.New("invalid_budget")
	}
	return int(v), nil
}
