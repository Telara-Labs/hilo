//go:build e2e && darwin

package clients_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/vault"
)

// This is a closed vocabulary. Never serialize error strings, paths or substrings
// copied from child output, even after redaction.
type helperReason string

const (
	reasonHelperArguments      helperReason = "E2E_HELPER_ARGUMENTS"
	reasonHelperConfiguration  helperReason = "E2E_HELPER_CONFIGURATION"
	reasonHelperInstall        helperReason = "E2E_HELPER_INSTALL_VERIFICATION"
	reasonHelperClients        helperReason = "E2E_HELPER_CLIENT_ADAPTER"
	reasonHelperBootstrap      helperReason = "E2E_HELPER_BOOTSTRAP"
	reasonHelperShim           helperReason = "E2E_HELPER_SHIM"
	reasonHelperDaemon         helperReason = "E2E_HELPER_DAEMON"
	reasonPathCanonicalization helperReason = "E2E_PATH_CANONICALIZATION"
	reasonDeniedReadProbe      helperReason = "E2E_SANDBOX_DENIED_READ_PROBE"
	reasonProtectedWriteProbe  helperReason = "E2E_SANDBOX_PROTECTED_WRITE_PROBE"
	reasonWritableHomeProbe    helperReason = "E2E_SANDBOX_WRITABLE_HOME_PROBE"
	reasonWritableTempProbe    helperReason = "E2E_SANDBOX_WRITABLE_TEMP_PROBE"
	reasonKeychainRefusalProbe helperReason = "E2E_SANDBOX_KEYCHAIN_REFUSAL_PROBE"
	reasonSandboxProfileParse  helperReason = "E2E_SANDBOX_PROFILE_PARSE"
	reasonSandboxApply         helperReason = "E2E_SANDBOX_APPLY"
	reasonChildFailure         helperReason = "E2E_CHILD_FAILURE_UNCLASSIFIED"
	reasonChildOutputLimit     helperReason = "E2E_CHILD_OUTPUT_LIMIT"
)

var helperReasons = []helperReason{
	reasonHelperArguments, reasonHelperConfiguration, reasonHelperInstall,
	reasonHelperClients, reasonHelperBootstrap, reasonHelperShim, reasonHelperDaemon,
	reasonPathCanonicalization, reasonDeniedReadProbe, reasonProtectedWriteProbe,
	reasonWritableHomeProbe, reasonWritableTempProbe, reasonKeychainRefusalProbe,
	reasonSandboxProfileParse, reasonSandboxApply, reasonChildFailure, reasonChildOutputLimit,
}

func (r helperReason) Error() string { return helperFailureCodeValue(r) }

func helperFailureCodeValue(r helperReason) string {
	for _, allowed := range helperReasons {
		if r == allowed {
			return string(allowed)
		}
	}
	return string(reasonChildFailure)
}

func helperFailureCode(err error) string {
	var r helperReason
	if errors.As(err, &r) {
		return helperFailureCodeValue(r)
	}
	return string(reasonChildFailure)
}

// Match whole stderr lines against the closed vocabulary. stdout is never
// inspected. Only sandbox-exec's own known parse/apply markers are classified;
// their variable suffixes are discarded and cannot enter logs or receipts.
func childFailureCodes(exe string, stderr []byte) []string {
	seen := map[string]bool{}
	var codes []string
	add := func(code helperReason) {
		fixed := helperFailureCodeValue(code)
		if !seen[fixed] {
			codes = append(codes, fixed)
			seen[fixed] = true
		}
	}
	// Scan in place. Splitting an 8 MiB stream of newlines into a slice would
	// amplify bounded child output into hundreds of MiB of parser allocations.
	for len(stderr) > 0 {
		line, rest, _ := bytes.Cut(stderr, []byte{'\n'})
		stderr = rest
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if bytes.HasPrefix(line, []byte("E2E_")) {
			for _, code := range helperReasons {
				if bytes.Equal(line, []byte(code)) {
					add(code)
				}
			}
		}
		if exe == "/usr/bin/sandbox-exec" {
			if bytes.Equal(line, []byte("sandbox-exec: profile compilation failed")) || bytes.HasPrefix(line, []byte("sandbox-exec: error in profile:")) {
				add(reasonSandboxProfileParse)
			}
			if bytes.HasPrefix(line, []byte("sandbox-exec: sandbox_apply:")) {
				add(reasonSandboxApply)
			}
		}
	}
	if len(codes) == 0 {
		add(reasonChildFailure)
	}
	return codes
}

type childFailure struct {
	Codes    []string
	Debug    bool
	TimedOut bool
}

func (e *childFailure) Error() string {
	if e.Debug {
		return fmt.Sprintf("child failed (output withheld), timeout=%v, reason_codes=%s", e.TimedOut, strings.Join(e.Codes, ","))
	}
	return fmt.Sprintf("child failed (output withheld), timeout=%v", e.TimedOut)
}

func recordFailureCodes(t *testing.T, r *receipt, err error) {
	t.Helper()
	if !*debugRun || err == nil {
		return
	}
	var failure *childFailure
	if !errors.As(err, &failure) {
		return
	}
	for _, code := range failure.Codes {
		found := false
		for _, prior := range r.FailureCodes {
			found = found || prior == code
		}
		if !found {
			r.FailureCodes = append(r.FailureCodes, code)
		}
	}
	t.Logf("child failure reason codes %s", strings.Join(failure.Codes, ","))
}

type sandboxProbeIO struct {
	read   func(string) ([]byte, error)
	create func(string) error
	write  func(string, []byte) error
	get    func(context.Context, string) ([]byte, error)
}

func sandboxDenied(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

func checkSandboxProbe(ctx context.Context, cfg installedConfig, ops sandboxProbeIO) error {
	b, err := ops.read(filepath.Join(cfg.Root, "denied-read", "canary"))
	clear(b)
	if !sandboxDenied(err) {
		return reasonDeniedReadProbe
	}
	for _, path := range []string{filepath.Join(cfg.Data, "write-probe"), filepath.Join(cfg.Root, "write-probe")} {
		if !sandboxDenied(ops.create(path)) {
			return reasonProtectedWriteProbe
		}
	}
	if err := ops.write(filepath.Join(cfg.Home, "sandbox-allow-probe"), []byte("synthetic")); err != nil {
		return reasonWritableHomeProbe
	}
	if err := ops.write(filepath.Join(cfg.Home, "tmp", "sandbox-allow-probe"), []byte("synthetic")); err != nil {
		return reasonWritableTempProbe
	}
	// The caller planted keychainCanaryHandle in the isolated keychain before the
	// sandbox started. A refused lookup returns no bytes; macOS reports a blocked
	// keychain as not found as often as unavailable, so either error is a refusal.
	b, err = ops.get(ctx, keychainCanaryHandle)
	leaked := len(b) > 0
	clear(b)
	if leaked || err == nil || !(errors.Is(err, vault.ErrUnavailable) || errors.Is(err, vault.ErrNotFound)) {
		return reasonKeychainRefusalProbe
	}
	return nil
}

// keychainCanaryHandle names a synthetic item planted outside the sandbox.
const keychainCanaryHandle = "c0ffee00c0ffee00c0ffee00c0ffee00"

var keychainCanaryValue = []byte("synthetic keychain canary")

func TestHarnessSandboxProbeReasonCodes(t *testing.T) {
	cfg := installedConfig{Root: "/private/probe", Data: "/private/probe/data", Home: "/private/probe/home"}
	for _, tc := range []struct {
		name string
		edit func(*sandboxProbeIO)
		want helperReason
	}{
		{"pass", func(*sandboxProbeIO) {}, ""},
		{"read_allowed", func(o *sandboxProbeIO) { o.read = func(string) ([]byte, error) { return []byte(canary), nil } }, reasonDeniedReadProbe},
		{"read_missing", func(o *sandboxProbeIO) { o.read = func(string) ([]byte, error) { return nil, syscall.ENOENT } }, reasonDeniedReadProbe},
		{"write_allowed", func(o *sandboxProbeIO) { o.create = func(string) error { return nil } }, reasonProtectedWriteProbe},
		{"write_exists", func(o *sandboxProbeIO) { o.create = func(string) error { return syscall.EEXIST } }, reasonProtectedWriteProbe},
		{"root_write_allowed", func(o *sandboxProbeIO) {
			o.create = func(p string) error {
				if filepath.Dir(p) == cfg.Root {
					return nil
				}
				return syscall.EPERM
			}
		}, reasonProtectedWriteProbe},
		{"home_denied", func(o *sandboxProbeIO) { o.write = func(string, []byte) error { return syscall.EACCES } }, reasonWritableHomeProbe},
		{"temp_denied", func(o *sandboxProbeIO) {
			o.write = func(p string, _ []byte) error {
				if filepath.Dir(p) == filepath.Join(cfg.Home, "tmp") {
					return syscall.EACCES
				}
				return nil
			}
		}, reasonWritableTempProbe},
		{"keychain_accessible", func(o *sandboxProbeIO) {
			o.get = func(context.Context, string) ([]byte, error) { return []byte(canary), nil }
		}, reasonKeychainRefusalProbe},
		{"keychain_success_without_error", func(o *sandboxProbeIO) {
			o.get = func(context.Context, string) ([]byte, error) { return nil, nil }
		}, reasonKeychainRefusalProbe},
		{"keychain_canary_with_error", func(o *sandboxProbeIO) {
			o.get = func(context.Context, string) ([]byte, error) { return keychainCanaryValue, vault.ErrNotFound }
		}, reasonKeychainRefusalProbe},
		{"keychain_not_found_is_refusal", func(o *sandboxProbeIO) {
			o.get = func(context.Context, string) ([]byte, error) { return nil, vault.ErrNotFound }
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := sandboxProbeIO{
				read:   func(string) ([]byte, error) { return nil, syscall.EACCES },
				create: func(string) error { return syscall.EPERM },
				write:  func(string, []byte) error { return nil },
				get:    func(context.Context, string) ([]byte, error) { return nil, vault.ErrUnavailable },
			}
			tc.edit(&o)
			err := checkSandboxProbe(context.Background(), cfg, o)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err != tc.want {
				t.Fatalf("reason got %v want %v", err, tc.want)
			}
		})
	}
}

func TestHarnessChildReasonAllowlist(t *testing.T) {
	for _, tc := range []struct {
		exe, raw string
		want     []string
	}{
		{"/client", "E2E_SANDBOX_DENIED_READ_PROBE\n" + canary + "\nE2E_SANDBOX_DENIED_READ_PROBE\r\n", []string{string(reasonDeniedReadProbe)}},
		{"/client", canary + " E2E_HELPER_SHIM\nE2E_HELPER_SHIM " + canary + "\n\x1b[31mE2E_HELPER_SHIM\n", []string{string(reasonChildFailure)}},
		{"/usr/bin/sandbox-exec", "sandbox-exec: error in profile: " + canary + "\n", []string{string(reasonSandboxProfileParse)}},
		{"/usr/bin/sandbox-exec", "sandbox-exec: profile compilation failed\n" + canary, []string{string(reasonSandboxProfileParse)}},
		{"/usr/bin/sandbox-exec", "sandbox-exec: sandbox_apply: " + canary + "\n", []string{string(reasonSandboxApply)}},
		{"/client", "sandbox-exec: error in profile: " + canary, []string{string(reasonChildFailure)}},
	} {
		got := childFailureCodes(tc.exe, []byte(tc.raw))
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("unexpected fixed classification %v", got)
		}
	}
	for _, code := range helperReasons {
		if helperFailureCode(fmt.Errorf("%s: %w", canary, code)) != string(code) {
			t.Fatal("wrapped fixed reason lost")
		}
	}
	if helperFailureCode(helperReason(canary)) != string(reasonChildFailure) || helperFailureCode(errors.New(canary)) != string(reasonChildFailure) {
		t.Fatal("unknown error escaped allowlist")
	}
}

func TestHarnessRunWithholdsRawDiagnostics(t *testing.T) {
	root := canonicalTemp(t)
	original := *debugRun
	defer func() { *debugRun = original }()
	for _, enabled := range []bool{false, true} {
		*debugRun = enabled
		out, err := run(context.Background(), root, []string{"HOME=" + root}, nil, mustExecutable(), "-test.run=^TestHarnessDiagnosticChild$")
		if err == nil || len(out) != 0 || strings.Contains(err.Error(), canary) {
			t.Fatal("raw child output leaked")
		}
		if strings.Contains(err.Error(), string(reasonHelperShim)) != enabled {
			t.Fatal("debug logging gate failed")
		}
		var r receipt
		recordFailureCodes(t, &r, err)
		if enabled {
			if !reflect.DeepEqual(r.FailureCodes, []string{string(reasonHelperShim)}) {
				t.Fatal("receipt omitted fixed reason")
			}
			if err := writeReceipt(root, r); err != nil {
				t.Fatal(err)
			}
			files, _ := filepath.Glob(filepath.Join(root, "clients-e2e-*.json"))
			raw, err := privateRead(files[0], 16384)
			if err != nil || bytes.Contains(raw, []byte(canary)) || !bytes.Contains(raw, []byte(reasonHelperShim)) {
				t.Fatal("receipt diagnostics invalid")
			}
		} else if len(r.FailureCodes) != 0 {
			t.Fatal("disabled receipt diagnostics leaked")
		}
	}
}

func TestHarnessDiagnosticChild(t *testing.T) {
	if len(os.Args) == 2 && os.Args[1] == "-test.run=^TestHarnessDiagnosticChild$" {
		fmt.Fprintln(os.Stdout, reasonDeniedReadProbe)
		fmt.Fprintln(os.Stderr, canary)
		fmt.Fprintln(os.Stderr, string(reasonHelperDaemon)+" "+canary)
		fmt.Fprintln(os.Stderr, reasonHelperShim)
		os.Exit(1)
	}
}

func TestHarnessEveryHelperFailureIsFixed(t *testing.T) {
	// IPC has the same short-path requirement as the installed harness. The
	// testing package's long per-test directory would fail before mode dispatch.
	parent, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(parent, "mc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	cfg := installedConfig{Root: root, Home: filepath.Join(root, "home"), Data: filepath.Join(root, "data"), Run: filepath.Join(root, "run"), Install: filepath.Join(root, "install"), Keychain: filepath.Join(root, "probe.keychain"), Client: "claude", Timeout: time.Second}
	cfg.ClientConfig = filepath.Join(cfg.Home, ".claude")
	b, _ := json.Marshal(cfg)
	if err := privateWrite(filepath.Join(cfg.Data, "harness.json"), b); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args []string
		want helperReason
	}{
		{nil, reasonHelperArguments},
		{[]string{"clients"}, reasonHelperArguments},
		{[]string{"unknown-mode"}, reasonHelperArguments},
		{[]string{"shim", "--unknown=" + canary}, reasonHelperArguments},
		{[]string{"hook", "--data-dir", cfg.Data}, reasonHelperConfiguration},
		{[]string{"shim", "--data-dir", cfg.Data}, reasonHelperShim},
		{[]string{"bootstrap", "--data-dir", cfg.Data}, reasonHelperBootstrap},
		{[]string{"managed-daemon", "--install-dir", cfg.Install}, reasonHelperInstall},
		{[]string{"clients", "invalid", "--client", "claude", "--home", cfg.Home, "--config-root", cfg.ClientConfig, "--data-dir", cfg.Data}, reasonHelperClients},
		{[]string{"sandbox-probe", "--data-dir", cfg.Data}, reasonDeniedReadProbe}, // absent canary cannot prove denial
	}
	for _, tc := range cases {
		if err := helperMain(tc.args); err != tc.want {
			t.Fatalf("helper reason got %v want %v", err, tc.want)
		}
	}
	// Run the real stderr dispatcher, without sandbox-exec or native keychain.
	_, err = run(context.Background(), root, []string{"HOME=" + root}, nil, mustExecutable(), "shim", "--data-dir", cfg.Data)
	var failure *childFailure
	if !errors.As(err, &failure) || !reflect.DeepEqual(failure.Codes, []string{string(reasonHelperShim)}) {
		t.Fatal("helper stderr lost fixed reason")
	}
	cfg.Root = filepath.Join(root, "missing", canary)
	b, _ = json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(cfg.Data, "harness.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := helperMain([]string{"shim", "--data-dir", cfg.Data}); err != reasonPathCanonicalization {
		t.Fatal("path canonicalization reason missing")
	}
}

func TestHarnessProfilesAllowClientRuntime(t *testing.T) {
	home := "/Users/operator"
	binaries := map[string]string{
		"claude": home + "/.local/share/claude/versions/2.1.304",
		"codex":  "/opt/homebrew/Caskroom/codex/0.161.0/bin/codex",
		"cursor": home + "/.local/share/cursor-agent/versions/2026.10.22/cursor-agent",
		"pi":     home + "/.npm-global/lib/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js",
	}
	for _, spec := range specs {
		t.Run(spec.name, func(t *testing.T) {
			cfg := installedConfig{Root: "/private/probe", Home: "/private/probe/home", Data: "/private/probe/data", Install: "/private/probe/install"}
			cfg.ClientConfig = filepath.Join(cfg.Home, spec.configRelative)
			profile := clientProfile(home, binaries[spec.name], cfg)
			q := func(p string) string { b, _ := json.Marshal(p); return string(b) }
			for _, rule := range []string{
				`(allow file-read* file-map-executable (subpath ` + q(codeRoot(binaries[spec.name])) + `))`,
				`(allow file-read* file-map-executable (subpath ` + q(cfg.Install) + `))`,
				`(subpath "/System/Library")`, `(subpath "/usr/lib")`, `(subpath "/opt/homebrew")`,
				`(allow process-exec process-fork)`, `(allow network*)`,
				`(allow file-read* file-write* (subpath ` + q(cfg.Home) + `))`,
				`(allow file-read* file-write* (subpath ` + q(cfg.ClientConfig) + `) (subpath ` + q(filepath.Join(cfg.Home, "tmp")) + `))`,
				`(deny file-read* file-write* (subpath ` + q(home) + `) (subpath "/private/probe/denied-read"))`,
				`(deny file-write* (subpath "/private/probe"))`,
				`(deny mach-lookup (global-name "com.apple.securityd") (global-name "com.apple.secd") (global-name "com.apple.security.agent"))`,
				`(deny file-read* file-write* (subpath "/Library/Keychains"))`,
				`(deny file-read* file-write* (literal ` + q(cfg.Keychain) + `) (literal ` + q(cfg.Keychain+"-db") + `))`,
			} {
				if !strings.Contains(profile, rule) {
					t.Fatalf("missing required rule %s", rule)
				}
			}
			if strings.Contains(profile, `"com.apple.SecurityServer"`) {
				t.Fatal("SecurityServer denied: clients lose TLS trust")
			}
			if strings.Contains(profile, `(allow file-read* (subpath "/Users/operator"))`) {
				t.Fatal("real-home content reads reopened")
			}
			if strings.Index(profile, `(deny file-write* (subpath "/private/probe"))`) > strings.Index(profile, `(allow file-read* file-write*`) {
				t.Fatal("write allowance shadowed by later deny")
			}
			for p := filepath.Dir(codeRoot(binaries[spec.name])); p == home || under(home, p); p = filepath.Dir(p) {
				if !strings.Contains(profile, `(allow file-read-metadata (literal `+q(p)+`))`) {
					t.Fatal("install traversal metadata missing")
				}
			}
		})
	}
}

func TestHarnessReasonParserBounds(t *testing.T) {
	// A hostile child can fill the output cap with empty lines. Parsing must
	// keep allocation count bounded independently of the number of lines.
	raw := bytes.Repeat([]byte{'\n'}, 8<<20)
	raw = append(raw, []byte(reasonHelperShim)...)
	allocations := testing.AllocsPerRun(1, func() {
		got := childFailureCodes("/client", raw)
		if !reflect.DeepEqual(got, []string{string(reasonHelperShim)}) {
			t.Fatal("bounded parser lost fixed code")
		}
	})
	if allocations > 64 {
		t.Fatalf("diagnostic parser amplified line count into allocations %.0f", allocations)
	}
}

func TestHarnessRunOutputLimitReason(t *testing.T) {
	root := canonicalTemp(t)
	original := *debugRun
	*debugRun = true
	defer func() { *debugRun = original }()
	out, err := run(context.Background(), root, []string{"HOME=" + root}, nil, mustExecutable(), "-test.run=^TestHarnessNoisyDiagnosticChild$")
	var failure *childFailure
	if len(out) != 0 || !errors.As(err, &failure) || strings.Contains(err.Error(), canary) {
		t.Fatal("overflow did not withhold raw output")
	}
	var r receipt
	recordFailureCodes(t, &r, err)
	if !reflect.DeepEqual(r.FailureCodes, []string{string(reasonHelperShim), string(reasonChildOutputLimit)}) {
		t.Fatal("overflow dropped fixed reason codes")
	}
}

func TestHarnessNoisyDiagnosticChild(t *testing.T) {
	if len(os.Args) == 2 && os.Args[1] == "-test.run=^TestHarnessNoisyDiagnosticChild$" {
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), (8<<20)+1))
		fmt.Fprintln(os.Stderr, canary)
		fmt.Fprintln(os.Stderr, reasonHelperShim)
		os.Exit(1)
	}
}
