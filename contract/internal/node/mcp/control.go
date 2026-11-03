package mcp

import (
	"context"
	"sync"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/capture"
	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/disclosure"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/store"
)

// ScrubWait bounds how long one control request retries a physical scrub that
// is busy. A pending scrub stays durable and is reported, never claimed clean.
const ScrubWait = 15 * time.Second

// ownerControl serves owner lifecycle commands that need the device signing
// key: erasure and physical scrub retry. It is reachable only from direct
// control connections, never from forwarded MCP requests.
type ownerControl struct {
	dir     string
	vault   disclosure.SecretVault
	service *disclosure.Service
	mu      sync.Mutex
	st      *store.Store
	signer  *capture.PreloadedKeyMaterial
}

func newOwnerControl(st *store.Store, keys capture.PreloadedKeyMaterial) *ownerControl {
	c := &ownerControl{st: st}
	if keys.KeyID() != "" {
		c.signer = new(capture.PreloadedKeyMaterial)
		*c.signer = keys
	}
	return c
}

func (c *ownerControl) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.signer != nil {
		c.signer.Clear()
	}
	c.st = nil
}

// ScrubState is the physical outcome of one control's scrub job.
type ScrubState struct {
	Control    string `json:"control"`
	State      string `json:"state"`
	Generation int64  `json:"generation,omitempty"`
	Error      string `json:"error,omitempty"`
}

// EraseResult is the control response for an erasure request.
type EraseResult struct {
	Receipt store.EraseReceipt `json:"receipt"`
	Scrub   ScrubState         `json:"scrub"`
}

// Control handles owner control methods. The boolean is false for methods it
// does not own, so the daemon reports them as unsupported.
func (b *Backend) Control(ctx context.Context, req daemon.Request) (daemon.Response, bool) {
	if req.Method != "erase" && req.Method != "scrub" && req.Method != "repository_inspect" && req.Method != "repository_enroll" && req.Method != "repository_revoke" {
		return daemon.Response{}, false
	}
	c := b.control
	if c == nil {
		return daemon.Error(req.ID, "store_unavailable"), true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return daemon.Error(req.ID, "store_unavailable"), true
	}
	out := daemon.Response{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "repository_inspect":
		if len(req.Params) > 0 && string(req.Params) != "{}" {
			return daemon.Error(req.ID, "invalid_arguments"), true
		}
		result, err := c.st.InspectRepositories(ctx)
		if err != nil {
			return daemon.Error(req.ID, store.Code(err)), true
		}
		out.Result = result
	case "repository_enroll":
		var p struct {
			Observation string `json:"observation"`
			ProjectRoot string `json:"project_root"`
			Remote      string `json:"remote"`
		}
		if ipc.DecodeStrict(req.Params, &p) != nil {
			return daemon.Error(req.ID, "invalid_arguments"), true
		}
		if c.service == nil || c.vault == nil {
			return daemon.Error(req.ID, "runtime_authority_unavailable"), true
		}
		admin, err := c.service.Administration(ctx)
		if err != nil {
			return daemon.Error(req.ID, "runtime_authority_unavailable"), true
		}
		result, err := disclosure.EnrollRepositoryContext(ctx, c.dir, c.st, admin, c.vault, store.RepositoryEnrollment{Observation: p.Observation, ProjectRoot: p.ProjectRoot, Remote: p.Remote})
		if err != nil {
			return daemon.Error(req.ID, store.Code(err)), true
		}
		out.Result = result
	case "repository_revoke":
		var p struct {
			Binding string `json:"binding"`
		}
		if ipc.DecodeStrict(req.Params, &p) != nil {
			return daemon.Error(req.ID, "invalid_arguments"), true
		}
		if c.signer == nil || c.vault == nil {
			return daemon.Error(req.ID, "runtime_authority_unavailable"), true
		}
		controls, err := disclosure.RetireRepositoryContext(ctx, c.dir, p.Binding, c.st, c.vault, c.signer)
		if err != nil {
			return daemon.Error(req.ID, store.Code(err)), true
		}
		out.Result = map[string]any{"binding": p.Binding, "controls": controls, "state": "retired"}

	case "erase":
		var p struct {
			IDs    []string `json:"ids"`
			Reason string   `json:"reason,omitempty"`
		}
		if ipc.DecodeStrict(req.Params, &p) != nil {
			return daemon.Error(req.ID, "invalid_arguments"), true
		}
		if c.signer == nil {
			return daemon.Error(req.ID, "signing_unavailable"), true
		}
		receipt, err := c.st.EraseExact(ctx, store.EraseRequest{IDs: p.IDs, Reason: p.Reason}, c.signer)
		if err != nil {
			return daemon.Error(req.ID, store.Code(err)), true
		}
		state := scrubUntil(ctx, c.st, receipt.Control, ScrubWait)
		receipt.Physical = state.State
		out.Result = EraseResult{Receipt: receipt, Scrub: state}
	case "scrub":
		if len(req.Params) > 0 && string(req.Params) != "{}" {
			return daemon.Error(req.ID, "invalid_arguments"), true
		}
		pending, err := c.st.PendingScrubs(ctx)
		if err != nil {
			return daemon.Error(req.ID, store.Code(err)), true
		}
		states := []ScrubState{}
		for _, control := range pending {
			states = append(states, scrubUntil(ctx, c.st, control, ScrubWait/time.Duration(max(len(pending), 1))))
		}
		out.Result = map[string]any{"jobs": states}
	}
	return out, true
}

// scrubUntil retries a busy scrub with bounded backoff. A blocked scrub means
// an erasure or projection hold remains and retrying cannot clear it.
func scrubUntil(ctx context.Context, st *store.Store, control string, wait time.Duration) ScrubState {
	deadline := time.Now().Add(wait)
	delay := 20 * time.Millisecond
	for {
		r, err := st.Scrub(ctx, control)
		if err != nil {
			return ScrubState{Control: control, State: "pending", Error: store.Code(err)}
		}
		if r.State == "complete" || r.State == "blocked" {
			return ScrubState{Control: control, State: r.State, Generation: r.Generation}
		}
		if time.Now().Add(delay).After(deadline) {
			return ScrubState{Control: control, State: r.State}
		}
		select {
		case <-ctx.Done():
			return ScrubState{Control: control, State: r.State, Error: "cancelled"}
		case <-time.After(delay):
		}
		delay = min(delay*2, time.Second)
	}
}
