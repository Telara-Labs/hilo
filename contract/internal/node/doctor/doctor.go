// Package doctor assembles a read-only diagnostic report of one installed
// node. It reads states, counts and identifiers only: never record bodies,
// transcript text, spool contents, credentials or key material.
package doctor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/syncnode"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/vault"
)

// Config selects what to inspect. Paths left empty come from the receipt.
type Config struct {
	InstallDir string // installation receipt directory; empty skips receipt checks
	DataDir    string
	RunDir     string
	Home       string // client home for hook status; empty uses the user's home
	Executable string // node executable named by client snippets
	Now        func() time.Time
	// ProbeTimeout bounds the daemon reachability check.
	ProbeTimeout time.Duration
}

type Daemon struct {
	Reachable  bool              `json:"reachable"`
	State      string            `json:"state"`
	PID        int               `json:"pid,omitempty"`
	StoreWired bool              `json:"store_wired"`
	Capture    map[string]uint64 `json:"capture_counters,omitempty"`
	Error      string            `json:"error,omitempty"`
}

type KeyStore struct {
	Backend          string `json:"backend"`
	Location         string `json:"location"`
	CustodyRecord    string `json:"custody_record"`
	InstalledProfile string `json:"installed_identity"`
	RuntimeAuthority string `json:"runtime_authority"` // loaded | unavailable | unknown
}

type Signing struct {
	Backlog         int64            `json:"backlog"`
	SignatureStates map[string]int64 `json:"signature_states"`
}

type Gap struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

type Hook struct {
	Client       string   `json:"client"`
	Installation string   `json:"installation"`
	MCP          string   `json:"mcp"`
	Hooks        string   `json:"hooks"`
	Trust        string   `json:"trust"` // review_required | not_required
	Gaps         []string `json:"gaps"`
	CaptureGaps  []Gap    `json:"capture_gaps"`
	Error        string   `json:"error,omitempty"`
}

type Spool struct {
	New int `json:"new"`
	Tmp int `json:"tmp"`
}

type Capture struct {
	Incomplete   bool             `json:"incomplete"`
	Reasons      []string         `json:"reasons"`
	PendingSpool int              `json:"pending_spool"`
	Spool        map[string]Spool `json:"spool"`
}

type Store struct {
	State      string `json:"state"` // ok | no_database | error
	Generation int64  `json:"generation,omitempty"`
	Records    int64  `json:"records,omitempty"`
	Error      string `json:"error,omitempty"`
}

type Sync struct {
	Configured bool             `json:"configured"`
	Enabled    bool             `json:"enabled"`
	Enrolled   bool             `json:"enrolled"`
	Blockers   []string         `json:"blockers"`
	Outbox     map[string]int64 `json:"outbox,omitempty"`
	LastRound  int64            `json:"last_round,omitempty"`
	Error      string           `json:"error,omitempty"`
}

// Report is the complete doctor output. Problems summarizes every section
// condition that needs attention, in a stable order.
type Report struct {
	Install  *install.ReceiptReport  `json:"install,omitempty"`
	DataDir  string                  `json:"data_dir"`
	Daemon   Daemon                  `json:"daemon"`
	KeyStore KeyStore                `json:"key_store"`
	Signing  Signing                 `json:"signing"`
	Hooks    []Hook                  `json:"hooks"`
	Capture  Capture                 `json:"capture"`
	Store    Store                   `json:"store"`
	Policy   store.PolicyDiagnostics `json:"policy"`
	Scrub    store.ScrubDiagnostics  `json:"scrub"`
	Sync     Sync                    `json:"sync"`
	Problems []string                `json:"problems"`
}

var ErrPaths = errors.New("invalid_paths")

var allClients = []clients.Client{clients.Claude, clients.Codex, clients.Cursor, clients.Pi}

// Run builds the report. Only unusable paths are an error; every section
// failure is reported inside the report.
func Run(ctx context.Context, cfg Config) (Report, error) {
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	r := Report{Hooks: []Hook{}, Problems: []string{}}
	data, run := cfg.DataDir, cfg.RunDir
	if cfg.InstallDir != "" {
		receipt := install.Inspect(ctx, cfg.InstallDir)
		r.Install = &receipt
		if data == "" && run == "" {
			data, run = receipt.DataDir, receipt.RunDir
		}
		if receipt.State != "verified" {
			r.Problems = append(r.Problems, "install_"+receipt.State)
		}
		if receipt.Manager != "" && receipt.Manager != "registered" {
			r.Problems = append(r.Problems, "install_manager_"+receipt.Manager)
		}
	}
	// Empty paths resolve to the default profile, as every other command does.
	p, err := ipc.Resolve(data, run)
	if err != nil {
		return r, ErrPaths
	}
	r.DataDir = p.Data
	r.Daemon = probe(ctx, p, cfg.ProbeTimeout)
	if !r.Daemon.Reachable {
		r.Problems = append(r.Problems, "daemon_unreachable")
	} else if !r.Daemon.StoreWired {
		r.Problems = append(r.Problems, "runtime_authority_unavailable")
	}
	r.KeyStore = keyStore(p.Data, r.Daemon)
	if r.KeyStore.Backend == "unavailable" {
		r.Problems = append(r.Problems, "key_store_unavailable")
	}
	diag, err := store.Inspect(ctx, p.Data)
	switch {
	case errors.Is(err, store.ErrNoDatabase):
		r.Store.State = "no_database"
		r.Problems = append(r.Problems, "store_no_database")
	case err != nil:
		r.Store.State, r.Store.Error = "error", store.Code(err)
		r.Problems = append(r.Problems, "store_"+r.Store.Error)
	default:
		r.Store = Store{State: "ok", Generation: diag.Generation, Records: diag.Records}
	}
	r.Signing = Signing{Backlog: diag.SigningBacklog, SignatureStates: diag.SignatureState}
	if r.Signing.Backlog > 0 {
		r.Problems = append(r.Problems, "signing_backlog")
	}
	r.Policy, r.Scrub = diag.Policy, diag.Scrub
	if r.Policy.Installed && r.Policy.Stale {
		r.Problems = append(r.Problems, "policy_"+r.Policy.Freshness)
	}
	if r.Policy.EvaluationCode != "" {
		r.Problems = append(r.Problems, "policy_"+r.Policy.EvaluationCode)
	}
	if r.Policy.KillSync || r.Policy.KillCapture || r.Policy.KillWithdraw {
		r.Problems = append(r.Problems, "policy_kill_switch")
	}
	if r.Scrub.Pending > 0 {
		r.Problems = append(r.Problems, "scrub_pending")
	}
	if r.Scrub.ErasurePending > 0 {
		r.Problems = append(r.Problems, "erasure_pending")
	}
	if r.Scrub.ProjectionHolds > 0 || r.Scrub.PrivacyBarriers > 0 {
		r.Problems = append(r.Problems, "privacy_hold")
	}
	for _, c := range allClients {
		r.Hooks = append(r.Hooks, hook(ctx, c, cfg, p.Data))
	}
	for _, h := range r.Hooks {
		if h.Trust == "review_required" {
			r.Problems = append(r.Problems, "hook_trust_review_"+h.Client)
		}
	}
	r.Capture = capture(p.Data, r)
	if r.Capture.Incomplete {
		r.Problems = append(r.Problems, "capture_incomplete")
	}
	r.Sync = syncState(ctx, p.Data, r.Policy, now())
	for _, b := range r.Sync.Blockers {
		r.Problems = append(r.Problems, "sync_blocked:"+b)
	}
	return r, nil
}

func probe(ctx context.Context, p ipc.Paths, timeout time.Duration) Daemon {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	live, err := daemon.Probe(ctx, p)
	if err != nil {
		return Daemon{State: "unreachable", Error: publicIPC(err)}
	}
	fields, _ := live.Result.(map[string]any)
	out := Daemon{Reachable: true, State: "running"}
	if pid, ok := fields["pid"].(float64); ok {
		out.PID = int(pid)
	}
	out.StoreWired, _ = fields["store_wired"].(bool)
	if counters, ok := fields["capture"].(map[string]any); ok {
		out.Capture = map[string]uint64{}
		for k, v := range counters {
			if n, ok := v.(float64); ok && n >= 0 {
				out.Capture[k] = uint64(n)
			}
		}
	}
	return out
}

func publicIPC(err error) string {
	switch {
	case errors.Is(err, ipc.ErrUnsafe):
		return "unsafe_path"
	case errors.Is(err, ipc.ErrPeer):
		return "peer_identity"
	case errors.Is(err, ipc.ErrFrame):
		return "invalid_frame"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	return "daemon_unavailable"
}

func keyStore(data string, d Daemon) KeyStore {
	k := KeyStore{Backend: vault.Backend(), Location: vault.Location(), CustodyRecord: vault.CustodyRecord(data), InstalledProfile: "absent", RuntimeAuthority: "unknown"}
	if _, _, err := store.InstalledIdentity(data); err == nil {
		k.InstalledProfile = "present"
	} else if _, statErr := os.Lstat(filepath.Join(data, "installed-authority.json")); statErr == nil {
		k.InstalledProfile = "unreadable"
	}
	if d.Reachable {
		k.RuntimeAuthority = "unavailable"
		if d.StoreWired {
			k.RuntimeAuthority = "loaded"
		}
	}
	return k
}

func hook(ctx context.Context, c clients.Client, cfg Config, data string) Hook {
	h := Hook{Client: string(c), Gaps: []string{}, CaptureGaps: []Gap{}, Trust: "not_required"}
	exe := cfg.Executable
	if exe == "" {
		exe, _ = os.Executable()
	}
	r, err := clients.Status(ctx, clients.Options{Client: c, Home: cfg.Home, Executable: exe, StateDir: data})
	if err != nil {
		h.Error = clientCode(err)
	}
	h.Installation, h.MCP, h.Hooks = r.Installation.State, r.MCP, r.Capture
	h.Gaps = append(h.Gaps, r.Gaps...)
	for _, g := range r.CaptureGaps {
		h.CaptureGaps = append(h.CaptureGaps, Gap{Code: string(g.Code), State: string(g.State)})
		if g.Code == clients.HookTrustReviewRequired {
			h.Trust = "review_required"
		}
	}
	return h
}

func clientCode(err error) string {
	for _, e := range []error{clients.ErrOptions, clients.ErrUnsafe, clients.ErrConflict, clients.ErrMalformed, clients.ErrBusy} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return "client_status_error"
}

// capture counts spool file names only; it never opens a spool file.
func capture(data string, r Report) Capture {
	c := Capture{Reasons: []string{}, Spool: map[string]Spool{}}
	for _, client := range allClients {
		var s Spool
		s.New = countJSON(filepath.Join(data, "spool", string(client), "new"))
		s.Tmp = countJSON(filepath.Join(data, "spool", string(client), "tmp"))
		if s.New+s.Tmp > 0 {
			c.Spool[string(client)] = s
		}
		c.PendingSpool += s.New
	}
	if !r.Daemon.Reachable {
		c.Reasons = append(c.Reasons, "daemon_stopped")
		if c.PendingSpool > 0 {
			c.Reasons = append(c.Reasons, "spool_pending_without_daemon")
		}
	} else if !r.Daemon.StoreWired {
		c.Reasons = append(c.Reasons, "store_not_wired")
	}
	if r.Install != nil && r.Install.Manager == "autostart_unavailable" {
		c.Reasons = append(c.Reasons, "autostart_unavailable")
	}
	if r.Policy.KillCapture {
		c.Reasons = append(c.Reasons, "policy_kill_capture")
	}
	missing := map[string]bool{}
	for _, h := range r.Hooks {
		for _, g := range h.CaptureGaps {
			if g.State == string(clients.Missing) {
				missing[h.Client+":"+g.Code] = true
			}
		}
	}
	keys := make([]string, 0, len(missing))
	for k := range missing {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c.Reasons = append(c.Reasons, "capture_gap:"+k)
	}
	c.Incomplete = len(c.Reasons) > 0
	return c
}

func countJSON(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n
}

func syncState(ctx context.Context, data string, pol store.PolicyDiagnostics, now time.Time) Sync {
	s := Sync{Blockers: []string{}}
	if _, err := os.Lstat(filepath.Join(data, store.SyncProfileName)); os.IsNotExist(err) {
		return s
	}
	st, err := syncnode.Status(ctx, data)
	if err != nil {
		s.Error = syncCode(err)
		s.Blockers = append(s.Blockers, s.Error)
		return s
	}
	s.Configured, s.Enabled, s.Enrolled, s.Outbox, s.LastRound = st.Configured, st.Enabled, st.Enrolled, st.Outbox, st.LastRound
	s.Blockers = append(s.Blockers, syncnode.Blockers(st, now)...)
	if s.Configured && pol.KillSync {
		s.Blockers = append(s.Blockers, "policy_kill_sync")
	}
	if s.Configured && pol.Installed && pol.FailClosed {
		s.Blockers = append(s.Blockers, "policy_"+pol.Freshness)
	}
	return s
}

func syncCode(err error) string {
	for _, e := range []error{syncnode.ErrProfile, syncnode.ErrNotEnrolled, syncnode.ErrIdentity, syncnode.ErrCredential, syncnode.ErrUnsupported} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	if c := store.Code(err); c != "storage_error" {
		return c
	}
	return "sync_state_unavailable"
}
