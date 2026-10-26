//go:build e2e && darwin

package clients_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/Telara-Labs/TAP-Runtime/discover/redact"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/clients"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/daemon"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosure"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/mcp"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/peer"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/shim"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/vault"
)

type installedConfig struct {
	Root, Home, Data, Run, Install, Keychain, ClientConfig, Client string
	Timeout                                                        time.Duration
	Debug                                                          bool
}

func loadInstalled(data string) (installedConfig, error) {
	var cfg installedConfig
	b, err := privateRead(filepath.Join(data, "harness.json"), 16384)
	if err != nil {
		return cfg, err
	}
	if err = json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	root, err := filepath.EvalSymlinks(cfg.Root)
	if err != nil || root != cfg.Root || cfg.Data != data {
		return cfg, reasonPathCanonicalization
	}
	if cfg.Timeout <= 0 || cfg.Timeout > 5*time.Minute {
		return cfg, reasonHelperConfiguration
	}
	for _, p := range []string{cfg.Home, cfg.Data, cfg.Run, cfg.Install, cfg.Keychain, cfg.ClientConfig} {
		if !under(root, p) || !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return cfg, reasonPathCanonicalization
		}
	}
	var spec *clientSpec
	for index := range specs {
		if specs[index].name == cfg.Client {
			spec = &specs[index]
		}
	}
	if spec == nil || cfg.Home != filepath.Join(root, "home") || cfg.Data != filepath.Join(root, "data") || cfg.Run != filepath.Join(root, "run") || cfg.Install != filepath.Join(root, "install") || cfg.Keychain != filepath.Join(root, "probe.keychain") || cfg.ClientConfig != filepath.Join(cfg.Home, spec.configRelative) {
		return cfg, errors.New("helper configuration differs from isolated layout")
	}
	return cfg, nil
}

func phase(data string) string {
	b, _ := privateRead(filepath.Join(data, "phase"), 8)
	return string(b)
}
func evidence(data, kind string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return privateWrite(filepath.Join(data, "observations", kind+"-"+nonce()+".json"), []byte(redact.Redact(string(b))))
}

type observedBackend struct {
	*mcp.Backend
	data string
}

func (b *observedBackend) Handle(ctx context.Context, h ipc.Hello, req daemon.Request) daemon.Response {
	res := b.Backend.Handle(ctx, h, req)
	if cfg, err := loadInstalled(b.data); err == nil && cfg.Debug && req.Method == "tools/call" {
		stage, outcome := "adapter_call", "PASS"
		if res.Error != nil {
			outcome = "REFUSED"
		}
		if result, ok := res.Result.(mcp.Result); ok && result.IsError {
			outcome = "REFUSED"
		}
		if daemon.ConnectionID(ctx) == "" {
			stage = "connection_id"
			outcome = "REFUSED"
		}
		diagnostic(cfg, proofDiagnostic{Stage: stage, Outcome: outcome, ConnectionIDPresent: daemon.ConnectionID(ctx) != "", PeerPID: daemon.AuthenticatedPeerPID(ctx), HelloPIDMatches: h.PID > 0 && h.PID == daemon.AuthenticatedPeerPID(ctx), DrainState: "see_peer_proof", CaptureStats: b.Backend.CaptureStats()})
	}
	if req.Method == "tools/call" {
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if json.Unmarshal(req.Params, &p) == nil {
			raw, _ := json.Marshal(res)
			ok := res.Error == nil
			if result, yes := res.Result.(mcp.Result); yes {
				ok = ok && !result.IsError
			} else {
				ok = false
			}
			if err := evidence(b.data, "call", observation{At: time.Now().UTC(), Phase: phase(b.data), Tool: p.Name, Arguments: p.Arguments, Response: raw, Success: ok}); err != nil {
				return daemon.Error(req.ID, "observation_write_failed")
			}
		}
	}
	return res
}

// All process modes live in the test binary. It is installed and verified by the
// real installer. This proves package integration, not cmd release packaging.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "export-native-helper-source" {
		if err := privateWrite(os.Args[2], []byte(keychainSource)); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if vault.RunHelper(os.Args[1:], os.Stdin, os.Stdout) {
		os.Exit(0)
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "managed-daemon", "shim", "hook", "clients", "sandbox-probe", "bootstrap":
			if err := helperMain(os.Args[1:]); err != nil {
				fmt.Fprintln(os.Stderr, helperFailureCode(err))
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func helperMain(args []string) (result error) {
	// Collapse every untyped product/OS error to a fixed stage code. Neither
	// Error() nor the stderr dispatcher can disclose input paths or secrets.
	stage := reasonHelperArguments
	defer func() {
		if result != nil {
			if _, ok := result.(helperReason); !ok {
				result = stage
			}
		}
	}()
	if len(args) == 0 {
		return reasonHelperArguments
	}
	fs := flag.NewFlagSet("isolated-helper", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o clients.Options
	var dir, runDir string
	manual := fs.Bool("manual", false, "")
	fs.StringVar(&o.StateDir, "data-dir", "", "")
	fs.StringVar(&o.StateDir, "state-dir", "", "")
	fs.StringVar(&o.Home, "home", "", "")
	fs.StringVar(&o.ConfigRoot, "config-root", "", "")
	fs.StringVar(&o.Executable, "executable", "", "")
	client := fs.String("client", "", "")
	fs.StringVar(&dir, "install-dir", "", "")
	fs.StringVar(&runDir, "run-dir", "", "")
	mode := args[0]
	switch mode {
	case "managed-daemon", "shim", "hook", "clients", "sandbox-probe", "bootstrap":
	default:
		return reasonHelperArguments
	}
	rest := args[1:]
	action := ""
	if mode == "clients" {
		if len(rest) < 1 {
			return errors.New("missing action")
		}
		action, rest = rest[0], rest[1:]
	}
	if fs.Parse(rest) != nil || fs.NArg() != 0 {
		return errors.New("invalid helper flags")
	}
	if mode == "managed-daemon" {
		stage = reasonHelperInstall
		r, err := install.VerifyRunning(dir)
		if err != nil {
			return err
		}
		o.StateDir = r.DataDir
	}
	stage = reasonHelperConfiguration
	cfg, err := loadInstalled(o.StateDir)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	ctx, deadline := context.WithTimeout(ctx, cfg.Timeout)
	defer deadline()
	o.Client = clients.Client(*client)
	if (mode == "hook" || mode == "clients") && (o.Home != cfg.Home || o.ConfigRoot != cfg.ClientConfig || string(o.Client) != cfg.Client) {
		return errors.New("adapter helper escaped isolated options")
	}
	stage = reasonPathCanonicalization
	p, err := isolatedPaths(cfg)
	if err != nil {
		return err
	}
	switch mode {
	case "sandbox-probe":
		v := isolatedVault{cfg: cfg, exe: mustExecutable()}
		return checkSandboxProbe(ctx, cfg, sandboxProbeIO{
			read: os.ReadFile,
			create: func(path string) error {
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err == nil {
					_ = f.Close()
				}
				return err
			},
			write: privateWrite,
			get:   v.Get,
		})
	case "clients":
		stage = reasonHelperClients
		var r clients.Report
		if action == "install" {
			r, err = clients.Install(ctx, o)
		} else if action == "uninstall" {
			r, err = clients.Uninstall(ctx, o)
		} else {
			return errors.New("invalid action")
		}
		if err == nil {
			err = json.NewEncoder(os.Stdout).Encode(r)
		}
		return err
	case "hook":
		b, e := io.ReadAll(io.LimitReader(os.Stdin, (1<<20)+1))
		if e != nil {
			return nil
		}
		var h struct {
			Event        string `json:"hook_event_name"`
			Session      string `json:"session_id"`
			Conversation string `json:"conversation_id"`
		}
		_ = json.Unmarshal(b, &h)
		if h.Session == "" {
			h.Session = h.Conversation
		}
		result := clients.RunHook(ctx, o, bytes.NewReader(b))
		_ = evidence(cfg.Data, "hook", hookObservation{At: time.Now().UTC(), Phase: phase(cfg.Data), Client: string(o.Client), Event: h.Event, Session: h.Session, Result: result})
		return nil
	case "bootstrap":
		stage = reasonHelperBootstrap
		if _, err := install.VerifyRunning(cfg.Install); err != nil {
			return err
		}
		lock, err := ipc.Lock(filepath.Join(cfg.Data, "db.lock"))
		if err != nil {
			return err
		}
		defer lock.Close()
		return disclosure.BootstrapInstalled(ctx, cfg.Data, "Disposable client probe", disclosure.Grant{Repos: disclosure.AllLocalRepos(), Channels: []disclosure.Channel{disclosure.S, disclosure.P, disclosure.E}}, disclosure.TaskWriteGrant{Repos: disclosure.AllLocalRepos(), AllowUnscoped: true, Actions: []disclosure.TaskMutation{disclosure.Create}}, isolatedVault{cfg, mustExecutable()})
	case "shim":
		stage = reasonHelperShim
		if _, err := install.VerifyRunning(cfg.Install); err != nil {
			return err
		}
		return shim.Run(ctx, os.Stdin, os.Stdout, shim.Config{Paths: p})
	case "managed-daemon":
		stage = reasonHelperDaemon
		if _, e := os.Lstat(filepath.Join(cfg.Data, "pending")); !os.IsNotExist(e) && !*manual {
			return nil
		}
		v := isolatedVault{cfg: cfg, exe: mustExecutable()}
		provider := mcp.InstalledRuntimeProvider{Provider: disclosure.InstalledProvider{Dir: cfg.Data, Vault: peer.GuardVault(v), Peers: diagnosticAuthority{cfg: cfg}}, CaptureHome: cfg.Home}
		err = daemon.Run(ctx, daemon.Config{Paths: p, BindConnection: bindInstalled(cfg), Verify: func() error { _, e := install.VerifyRunning(cfg.Install); return e }, Open: func(ctx context.Context) (daemon.Backend, error) {
			b, e := mcp.Open(ctx, cfg.Data, provider)
			if e != nil {
				return nil, e
			}
			return &observedBackend{b, cfg.Data}, nil
		}})
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	return errors.New("unknown helper mode")
}
func mustExecutable() string {
	p, err := os.Executable()
	if err != nil {
		panic(err)
	}
	return p
}

// The production vault already exports its bounded helper dispatcher but not
// createIsolated. Duplicate only its pipe protocol, always with a nonempty
// dedicated keychain path. No request can select the default/login keychain.
type isolatedVault struct {
	cfg installedConfig
	exe string
}

func (v isolatedVault) operation(ctx context.Context, op byte, h string, secret []byte) (value []byte, operationErr error) {
	if v.cfg.Debug && op == 2 {
		defer func() {
			outcome := "PASS"
			if operationErr != nil {
				outcome = "REFUSED"
			}
			diagnostic(v.cfg, proofDiagnostic{Stage: "custody_read", Outcome: outcome, ConnectionIDPresent: daemon.ConnectionID(ctx) != "", PeerPID: daemon.AuthenticatedPeerPID(ctx), DrainState: "not_applicable"})
		}()
	}
	if len(h) != 32 || v.cfg.Keychain == "" || !under(v.cfg.Root, v.cfg.Keychain) || len(v.cfg.Keychain) > 4096 || len(secret) > 2560 {
		return nil, errors.New("invalid isolated vault input")
	}
	raw := make([]byte, 35+len(v.cfg.Keychain)+len(secret))
	defer clear(raw)
	raw[0] = op
	copy(raw[1:33], h)
	binary.BigEndian.PutUint16(raw[33:35], uint16(len(v.cfg.Keychain)))
	copy(raw[35:], v.cfg.Keychain)
	copy(raw[35+len(v.cfg.Keychain):], secret)
	out, err := run(ctx, v.cfg.Home, isolatedEnv(v.cfg.Home, v.cfg.ClientConfig, specFor(v.cfg.Client)), raw, v.exe, "native-vault-operation")
	defer clear(out)
	if err != nil || len(out) < 1 || len(out) > 2561 {
		return nil, vault.ErrUnavailable
	}
	switch out[0] {
	case 0:
		return append([]byte(nil), out[1:]...), nil
	case 1:
		return nil, vault.ErrExists
	case 2:
		return nil, vault.ErrNotFound
	default:
		return nil, vault.ErrUnavailable
	}
}
func (v isolatedVault) Put(ctx context.Context, h string, b []byte) error {
	_, err := v.operation(ctx, 1, h, b)
	return err
}
func (v isolatedVault) Get(ctx context.Context, h string) ([]byte, error) {
	return v.operation(ctx, 2, h, nil)
}
func (v isolatedVault) Delete(ctx context.Context, h string) error {
	_, err := v.operation(ctx, 3, h, nil)
	return err
}
func specFor(name string) clientSpec {
	for _, s := range specs {
		if s.name == name {
			return s
		}
	}
	panic("unknown client")
}

// SecKeychainCreate is the same dedicated native creation used by vault tests.
// Explicit native paths and stdin avoid security CLI defaults and password argv.
// Go does not support cgo in _test.go. Compile this minimal native test utility
// inside the disposable root, rather than adding a product helper or dependency.
const keychainSource = `
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <unistd.h>
#include <string.h>
#include <libproc.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv) {
  if (argc != 3) return 2;
  if (!strcmp(argv[1], "peer-exe")) {
    char *end = NULL; long pid = strtol(argv[2], &end, 10);
    if (!end || *end || pid <= 0 || pid > 2147483647) return 2;
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (proc_pidpath((int)pid, path, sizeof(path)) <= 0) return 1;
    fputs(path, stdout); return 0;
  }
  SecKeychainSetUserInteractionAllowed(false);
  SecKeychainRef kc = NULL; OSStatus s;
  if (!strcmp(argv[1], "create")) {
    unsigned char password[32]; size_t n = 0; ssize_t r;
    while (n < sizeof(password) && (r = read(0, password+n, sizeof(password)-n)) > 0) n += r;
    if (n != sizeof(password)) return 3;
    s = SecKeychainCreate(argv[2], sizeof(password), password, false, NULL, &kc);
    memset_s(password, sizeof(password), 0, sizeof(password));
  } else if (!strcmp(argv[1], "delete")) {
    s = SecKeychainOpen(argv[2], &kc);
    if (!s) s = SecKeychainDelete(kc);
  } else return 2;
  if (kc) CFRelease(kc);
  return s == errSecSuccess ? 0 : 1;
}
`

type installation struct {
	cfg             installedConfig
	record          install.Record
	v               isolatedVault
	manual          *exec.Cmd
	cancel          context.CancelFunc
	keychainTool    string
	keychainCreated bool
	label           string
}

func setupInstallation(ctx context.Context, cfg installedConfig) (*installation, error) {
	i := &installation{cfg: cfg, label: "dev.memory.clientprobe." + nonce()}
	// Caller owns cleanup even when any later step fails.
	return i, i.setup(ctx)
}
func (i *installation) setup(ctx context.Context) error {
	cfg := i.cfg
	env := isolatedEnv(cfg.Home, cfg.ClientConfig, specFor(cfg.Client))
	p, err := isolatedPaths(cfg)
	if err != nil {
		return err
	}
	if err = p.Prepare(); err != nil {
		return err
	}
	if err = os.Mkdir(filepath.Join(cfg.Data, "observations"), 0700); err != nil {
		return err
	}
	b, _ := json.Marshal(cfg)
	if err = privateWrite(filepath.Join(cfg.Data, "harness.json"), b); err != nil {
		return err
	}
	if err = privateWrite(filepath.Join(cfg.Data, "pending"), []byte("pending")); err != nil {
		return err
	}
	src := filepath.Join(cfg.Root, "keychain.c")
	i.keychainTool = filepath.Join(cfg.Root, "keychain-helper")
	if err = privateWrite(src, []byte(keychainSource)); err != nil {
		return err
	}
	if *prebuiltNativeHelper != "" || *prebuiltNativeHelperSHA != "" {
		if err = copyNativeHelper(*prebuiltNativeHelper, *prebuiltNativeHelperSHA, i.keychainTool); err != nil {
			return err
		}
	} else if _, err = run(ctx, cfg.Home, env, nil, "/usr/bin/clang", "-Wno-deprecated-declarations", src, "-framework", "Security", "-framework", "CoreFoundation", "-o", i.keychainTool); err != nil {
		return err
	}
	var password [32]byte
	if _, err = rand.Read(password[:]); err != nil {
		return err
	}
	_, err = run(ctx, cfg.Home, env, password[:], i.keychainTool, "create", cfg.Keychain)
	clear(password[:])
	if err != nil {
		return fmt.Errorf("dedicated native keychain creation failed: %w", err)
	}
	i.keychainCreated = true
	source, err := filepath.EvalSymlinks(mustExecutable())
	if err != nil {
		return err
	}
	image, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	// Go builds on this Mac carry an ad hoc signature. Preserve the exact image;
	// no certificate, signing operation or signing-keychain access is needed.
	stagedImage := filepath.Join(cfg.Root, "test-image")
	if err = privateWrite(stagedImage, image); err != nil {
		return err
	}
	clear(image)
	if err = os.Chmod(stagedImage, 0700); err != nil {
		return err
	}
	image, err = os.ReadFile(stagedImage)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(image)
	clear(image)
	lock, err := ipc.Lock(filepath.Join(cfg.Data, "db.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	r, err := install.Install(ctx, install.Config{Dir: cfg.Install, Home: cfg.Home, Label: i.label, Executable: stagedImage, SHA256: hex.EncodeToString(hash[:]), Version: "client-e2e", DataDir: cfg.Data, RunDir: cfg.Run})
	i.record = r.Record
	if err != nil && !errors.Is(err, install.ErrUnavailable) {
		return err
	}
	if r.Record.Executable == "" {
		return errors.New("installer did not publish a receipt")
	}
	i.v = isolatedVault{cfg, r.Record.Executable}
	if err = lock.Close(); err != nil {
		return err
	}
	if _, err = run(ctx, cfg.Home, env, nil, r.Record.Executable, "bootstrap", "--data-dir", cfg.Data); err != nil {
		return fmt.Errorf("isolated bootstrap through installed target failed: %w", err)
	}
	// Registered job exits successfully while pending. Start explicitly using the
	// verified installed image, like the existing installed-authority integration.
	daemonCtx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	i.cancel = cancel
	i.manual = command(daemonCtx, cfg.Home, env, r.Record.Executable, "managed-daemon", "--install-dir", cfg.Install, "--manual")
	i.manual.Stdout, i.manual.Stderr = io.Discard, io.Discard
	if err = i.manual.Start(); err != nil {
		return err
	}
	for {
		probe, stop := context.WithTimeout(ctx, 200*time.Millisecond)
		status, e := daemon.Probe(probe, p)
		stop()
		if e == nil && status.Error == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-daemonCtx.Done():
			return daemonCtx.Err()
		case <-time.After(30 * time.Millisecond):
		}
	}
}

func isolatedPaths(cfg installedConfig) (ipc.Paths, error) {
	p, err := ipc.Resolve(cfg.Data, cfg.Run)
	if err != nil {
		return p, err
	}
	if p.Run != cfg.Run || !under(cfg.Root, p.Endpoint) {
		return p, errors.New("IPC path fallback would escape isolation; choose a shorter -e2e-temp-parent")
	}
	return p, nil
}

func (i *installation) cleanup() error {
	ctx, cancel := context.WithTimeout(context.Background(), *childTimeout)
	defer cancel()
	var errs []error
	// Quiesce, then stop and reap the manually started process before uninstall.
	// Termination is registered even for failed readiness and partial setup.
	if i.manual != nil && i.manual.Process != nil {
		p, e := ipc.Resolve(i.cfg.Data, i.cfg.Run)
		if e == nil {
			e = daemon.Quiesce(ctx, p)
		}
		if e != nil {
			errs = append(errs, errors.New("daemon quiesce failed"))
		}
		_ = i.manual.Cancel()
		_ = i.manual.Wait()
	}
	if i.cancel != nil {
		i.cancel()
	}
	if _, err := os.Lstat(filepath.Join(i.cfg.Install, "install.json")); err == nil {
		err = install.Uninstall(ctx, i.cfg.Install, func(ctx context.Context) error {
			lock, e := ipc.Lock(filepath.Join(i.cfg.Data, "db.lock"))
			if e != nil {
				return e
			}
			defer lock.Close()
			if _, e = os.Lstat(filepath.Join(i.cfg.Data, "installed-authority.json")); os.IsNotExist(e) {
				return nil
			}
			if i.v.exe == "" {
				return errors.New("vault unavailable for partial install cleanup")
			}
			return disclosure.DeleteInstalledSecret(ctx, i.cfg.Data, i.v)
		})
		if err != nil {
			errs = append(errs, errors.New("native uninstall failed"))
			// A partial native failure must still attempt to remove only this
			// invocation's unique job. Keep the failure in the receipt even when
			// this last-resort bootout succeeds; it is not settlement evidence.
			_, _ = run(ctx, i.cfg.Home, isolatedEnv(i.cfg.Home, i.cfg.ClientConfig, specFor(i.cfg.Client)), nil, "/bin/launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+i.label)
		}
	}
	if i.keychainCreated {
		_, err := run(ctx, i.cfg.Home, isolatedEnv(i.cfg.Home, i.cfg.ClientConfig, specFor(i.cfg.Client)), nil, i.keychainTool, "delete", i.cfg.Keychain)
		if err != nil {
			errs = append(errs, errors.New("dedicated keychain deletion failed"))
		}
	}
	return errors.Join(errs...)
}

// Both flags are explicit operator inputs from one authenticated CI artifact.
// A missing or mismatched digest refuses the run, without a compile fallback.
func copyNativeHelper(source, digest, dest string) error {
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || len(digest) != 64 {
		return errors.New("invalid precompiled native utility")
	}
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil || resolved != source {
		return errors.New("invalid precompiled native utility")
	}
	raw, err := privateRead(source, 4<<20)
	defer clear(raw)
	if err != nil {
		return errors.New("invalid precompiled native utility")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != digest {
		return errors.New("native utility digest mismatch")
	}
	if err = privateWrite(dest, raw); err != nil {
		return err
	}
	return os.Chmod(dest, 0700)
}
