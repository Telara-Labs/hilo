//go:build e2e && darwin

package clients_test

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/peer"
)

// Deliberately closed fields. No errors, hello metadata, credentials, tokens,
// arguments, request/response bodies, process argv or environment are logged.
type proofDiagnostic struct {
	At                  time.Time         `json:"at"`
	Stage               string            `json:"stage"`
	Outcome             string            `json:"outcome"`
	ConnectionIDPresent bool              `json:"connection_id_present"`
	PeerPID             int               `json:"peer_pid"`
	HelloPIDMatches     bool              `json:"hello_pid_matches"`
	PeerExecutable      string            `json:"peer_executable,omitempty"`
	ReceiptExecutable   string            `json:"receipt_executable,omitempty"`
	ImageMatches        bool              `json:"image_matches"`
	DrainWired          bool              `json:"drain_wired"`
	DrainState          string            `json:"drain_state"`
	CaptureStats        map[string]uint64 `json:"capture_stats,omitempty"`
}

func diagnostic(cfg installedConfig, d proofDiagnostic) {
	if !cfg.Debug {
		return
	}
	d.At = time.Now().UTC()
	// Only paths in the disposable installation can leave this function.
	// A foreign executable is reported as foreign, never copied into evidence.
	for _, p := range []*string{&d.PeerExecutable, &d.ReceiptExecutable} {
		if *p != "" && !under(cfg.Install, *p) {
			*p = "foreign_or_unavailable"
		}
	}
	// Diagnostic writes must not change product proof success or refusal.
	_ = evidence(cfg.Data, "debug", d)
}

func bindInstalled(cfg installedConfig) func(context.Context, net.Conn) (context.Context, func(), error) {
	return func(ctx context.Context, conn net.Conn) (context.Context, func(), error) {
		pid, _ := ipc.Peer(conn)
		bound, release, err := peer.BindConnection(ctx, conn)
		outcome := "PASS"
		if err != nil {
			outcome = "REFUSED"
		}
		d := proofDiagnostic{Stage: "kernel_binding", Outcome: outcome, PeerPID: pid, DrainState: "not_reached"}
		if cfg.Debug {
			d.PeerExecutable = diagnosticPeerExe(ctx, cfg, pid)
			if v, err := install.VerifiedExecutable(cfg.Install); err == nil {
				d.ReceiptExecutable = v.Path
				d.ImageMatches = d.PeerExecutable == v.Path
				v.Close()
			}
		}
		diagnostic(cfg, d)
		return bound, release, err
	}
}

func diagnosticPeerExe(ctx context.Context, cfg installedConfig, pid int) string {
	if pid <= 0 {
		return "unavailable"
	}
	// proc_pidpath is the public macOS API used by product peer verification.
	// The tiny native utility returns only an executable path, never process argv.
	out, err := run(ctx, cfg.Home, isolatedEnv(cfg.Home, cfg.ClientConfig, specFor(cfg.Client)), nil, filepath.Join(cfg.Root, "keychain-helper"), "peer-exe", strconv.Itoa(pid))
	defer clear(out)
	if err != nil || len(out) > 4096 || strings.ContainsAny(string(out), "\r\n\x00") {
		return "unavailable"
	}
	return string(out)
}

type diagnosticAuthority struct{ cfg installedConfig }

func (a diagnosticAuthority) VerifyAndDrain(ctx context.Context, h ipc.Hello, credential string) error {
	cfg := a.cfg
	authority := peer.Authority{InstallDir: cfg.Install, DataDir: cfg.Data}
	if !cfg.Debug {
		return authority.VerifyAndDrain(ctx, h, credential)
	}
	d := proofDiagnostic{Stage: "peer_proof", Outcome: "REFUSED", ConnectionIDPresent: daemon.ConnectionID(ctx) != "", PeerPID: daemon.AuthenticatedPeerPID(ctx), HelloPIDMatches: h.PID > 0 && daemon.AuthenticatedPeerPID(ctx) == h.PID, DrainState: "not_reached"}
	d.PeerExecutable = diagnosticPeerExe(ctx, cfg, h.PID)
	r, err := install.VerifyRunning(cfg.Install)
	if err == nil {
		d.ReceiptExecutable = r.Executable
		d.ImageMatches = d.PeerExecutable == r.Executable
	}
	// This exported check reproduces the exact retained binding + installed image
	// verification without draining or manufacturing any proof/context state.
	lifecycle := err == nil && peer.VerifyLifecycle(ctx, r) == nil
	authority.Drain = func(ctx context.Context, id string) error {
		wired, err := daemon.DrainCapture(ctx, id)
		d.DrainWired = wired
		if !wired {
			d.DrainState = "unwired_empty_spool_PASS"
			// Preserve Authority's public empty-spool compatibility fallback.
			// This nested check has no custom drain and cannot recurse here.
			err = (peer.Authority{InstallDir: cfg.Install, DataDir: cfg.Data}).VerifyAndDrain(ctx, h, id)
			if err != nil {
				d.DrainState = "unwired_REFUSED"
			}
			return err
		}
		d.DrainState = "PASS"
		if err != nil {
			d.DrainState = "REFUSED"
		}
		return err
	}
	err = authority.VerifyAndDrain(ctx, h, credential)
	switch {
	case err == nil:
		d.Outcome = "PASS"
	case !d.HelloPIDMatches:
		d.Stage = "peer_pid"
	case !d.ImageMatches:
		d.Stage = "installed_image"
	case !lifecycle:
		d.Stage = "kernel_binding_or_image_lifetime"
	case d.DrainState != "PASS":
		d.Stage = "capture_drain"
	default:
		d.Stage = "post_drain_peer_recheck"
	}
	diagnostic(cfg, d)
	return err
}

func readDiagnostics(t *testing.T, data string) []proofDiagnostic {
	t.Helper()
	var out []proofDiagnostic
	paths, err := filepath.Glob(filepath.Join(data, "observations", "debug-*.json"))
	if err != nil {
		t.Error("diagnostic inventory failed")
		return nil
	}
	for _, path := range paths {
		raw, err := privateRead(path, 16384)
		var d proofDiagnostic
		if err != nil || json.Unmarshal(raw, &d) != nil {
			t.Error("diagnostic read failed")
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

func TestHarnessDiagnosticsArePrivateAndOptional(t *testing.T) {
	root := canonicalTemp(t)
	cfg := installedConfig{Root: root, Install: filepath.Join(root, "install"), Data: filepath.Join(root, "data")}
	d := proofDiagnostic{Stage: "kernel_binding", Outcome: "REFUSED", PeerExecutable: "/Users/operator/" + canary, ReceiptExecutable: "/Users/operator/private", DrainState: "not_reached"}
	diagnostic(cfg, d)
	paths, _ := filepath.Glob(filepath.Join(cfg.Data, "observations", "*.json"))
	if len(paths) != 0 {
		t.Fatal("disabled diagnostics wrote evidence")
	}
	cfg.Debug = true
	diagnostic(cfg, d)
	got := readDiagnostics(t, cfg.Data)
	if len(got) != 1 || got[0].PeerExecutable != "foreign_or_unavailable" || got[0].ReceiptExecutable != "foreign_or_unavailable" {
		t.Fatal("foreign process path disclosed")
	}
	calls, hooks := readEvidence(t, cfg.Data)
	if len(calls) != 0 || len(hooks) != 0 {
		t.Fatal("diagnostic parsed as tool or hook proof")
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_, release, err := bindInstalled(cfg)(context.Background(), left)
	defer release()
	if err == nil {
		t.Fatal("non-kernel connection accepted")
	}
	got = readDiagnostics(t, cfg.Data)
	if len(got) != 2 || got[1].Stage != "kernel_binding" || got[1].Outcome != "REFUSED" {
		t.Fatal("binding refusal missing")
	}
	// Missing daemon PID/binding is the original harness failure. The diagnostic
	// wrapper must keep refusing it, with debug both on and off.
	for _, enabled := range []bool{false, true} {
		cfg.Debug = enabled
		if err = (diagnosticAuthority{cfg}).VerifyAndDrain(context.Background(), ipc.Hello{}, "synthetic-fixture-credential"); err == nil {
			t.Fatal("missing authenticated peer accepted")
		}
	}
	got = readDiagnostics(t, cfg.Data)
	if len(got) != 3 || got[2].Stage != "peer_pid" || got[2].DrainState != "not_reached" {
		t.Fatal("peer PID refusal missing")
	}
	if err := verifyShimImage(cfg, mustExecutable()); err == nil {
		t.Fatal("shim without receipt accepted")
	}
}

func TestHarnessCustodyDiagnosticWithholdsHandle(t *testing.T) {
	root := canonicalTemp(t)
	cfg := installedConfig{Root: root, Data: filepath.Join(root, "data"), Install: filepath.Join(root, "install"), Debug: true}
	// Rejected before native access. The secret and handle must never be serialized.
	secret := []byte(canary)
	_, err := (isolatedVault{cfg: cfg}).operation(context.Background(), 2, canary, secret)
	if err == nil {
		t.Fatal("invalid isolated vault accepted")
	}
	got := readDiagnostics(t, cfg.Data)
	if len(got) != 1 || got[0].Stage != "custody_read" || got[0].Outcome != "REFUSED" {
		t.Fatal("custody refusal missing")
	}
	paths, _ := filepath.Glob(filepath.Join(cfg.Data, "observations", "debug-*.json"))
	raw, err := privateRead(paths[0], 16384)
	if err != nil || strings.Contains(string(raw), canary) || strings.Contains(string(raw), "vault_handle") {
		t.Fatal("custody diagnostic leaked input")
	}
}
