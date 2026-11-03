//go:build e2e && linux

package clients_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/jcs"
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/releaseauth"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

var standaloneHome = flag.String("e2e-standalone-dedicated-home", "", "Explicit unused dedicated Linux test-user home; enables real CLI acceptance")
var standaloneCLI = flag.String("e2e-standalone-cli", "", "Exact source-built actual Hilo CLI")
var standaloneDigest = flag.String("e2e-standalone-sha256", "", "Independently authenticated build artifact SHA256")
var standaloneResults = flag.String("e2e-standalone-results", "", "Existing private directory for the execution receipt")
var standaloneUser = flag.String("e2e-standalone-user", "", "Dedicated runner username bound by operator provisioning receipt")
var standaloneMachine = flag.String("e2e-standalone-machine-id", "", "Exact disposable runner machine-id bound by operator provisioning receipt")
var standaloneProvisioning = flag.String("e2e-standalone-provisioning-receipt", "", "Independent root-owned disposable runner provisioning receipt")
var standaloneRelease = flag.String("e2e-standalone-release-dir", "", "Optional signed release directory; uses actual CLI release verification/install")
var standaloneFDHelper = flag.String("e2e-standalone-fd-executable", "", "Internal non-mutating fd-exec path probe")

func TestStandaloneFDExecutablePathHelper(t *testing.T) {
	if *standaloneFDHelper == "" {
		t.Skip("fd-exec helper only")
	}
	actual, err := os.Executable()
	if err != nil || actual != *standaloneFDHelper {
		t.Fatal("fd launch lost original executable path")
	}
}

func standaloneFDProbe(ctx context.Context) error {
	image, err := os.Executable()
	if err != nil {
		return err
	}
	f, err := os.Open(image)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "-test.run=^TestStandaloneFDExecutablePathHelper$", "-e2e-standalone-fd-executable="+image)
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = standaloneEnvironment()
	var out standaloneOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	clear(out.Bytes())
	if err != nil || out.overflow {
		return errors.New("fd_executable_path_probe_failed")
	}
	return nil
}

func TestStandaloneFDLaunchPreservesExecutablePath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := standaloneFDProbe(ctx); err != nil {
		t.Fatal(err)
	}
}

type standaloneRun struct {
	t         *testing.T
	env       []string
	image     string
	data, run string
}

// Forward only existing operating-system session variables. HOME contents and
// manager isolation require independent runner evidence beyond this allowlist.
func standaloneEnvironment() []string {
	var out []string
	for _, key := range []string{"HOME", "PATH", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if value, ok := os.LookupEnv(key); ok {
			out = append(out, key+"="+value)
		}
	}
	return out
}

type standaloneOutput struct {
	bytes.Buffer
	overflow bool
}

// Pin every existing ancestor with openat/no-follow. Other principals cannot
// replace a path component between inspection and opening the final image.
func standaloneOpen(path string, directory, missing bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("unsafe_path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if e != nil {
			if missing && errors.Is(e, unix.ENOENT) {
				return nil, nil
			}
			return nil, e
		}
		fd = next
		var st unix.Stat_t
		if e = unix.Fstat(fd, &st); e != nil || (st.Uid != 0 && st.Uid != uint32(os.Getuid())) || st.Mode&0022 != 0 {
			unix.Close(fd)
			return nil, errors.New("unsafe_path_owner_or_mode")
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func standaloneImage(path, digest string) (*os.File, error) {
	f, err := standaloneOpen(path, false, false)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 512<<20 {
		f.Close()
		return nil, errors.New("unsafe_image")
	}
	h := sha256.New()
	_, err = io.Copy(h, io.LimitReader(f, (512<<20)+1))
	if err != nil || hex.EncodeToString(h.Sum(nil)) != digest {
		f.Close()
		return nil, errors.New("image_digest_changed")
	}
	if _, err = f.Seek(0, 0); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (b *standaloneOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (4 << 20) - b.Len()
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	b.Buffer.Write(p)
	return n, nil
}

func (r *standaloneRun) command(ctx context.Context, image string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, image, args...)
	if image == r.image {
		pinned, err := standaloneImage(image, *standaloneDigest)
		if err != nil {
			return nil, err
		}
		defer pinned.Close()
		cmd = exec.CommandContext(ctx, "/proc/self/fd/3", args...)
		cmd.ExtraFiles = []*os.File{pinned}
	}
	cmd.Env = r.env
	var out, stderr standaloneOutput
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	clear(stderr.Bytes())
	if out.overflow || stderr.overflow || ctx.Err() != nil {
		clear(out.Bytes())
		return nil, errors.New("bounded_command_incomplete")
	}
	return out.Bytes(), err
}

func standalonePrivateDir(path string) bool {
	f, err := standaloneOpen(path, true, false)
	if err != nil {
		return false
	}
	defer f.Close()
	resolved, err := filepath.EvalSymlinks(path)
	st, se := os.Lstat(path)
	return err == nil && se == nil && resolved == path && filepath.IsAbs(path) && st.IsDir() && st.Mode().Perm()&0077 == 0
}

func (r *standaloneRun) verifyDedicatedSession(ctx context.Context, home string) error {
	account, err := user.Current()
	if err != nil || account.Username != *standaloneUser || account.HomeDir != home || account.Uid != fmtUID() {
		return errors.New("dedicated_account_unverified")
	}
	proof, err := standaloneOpen(*standaloneProvisioning, false, false)
	if err != nil {
		return errors.New("provisioning_receipt_unavailable")
	}
	defer proof.Close()
	var proofStat unix.Stat_t
	if unix.Fstat(int(proof.Fd()), &proofStat) != nil || proofStat.Uid != 0 || proofStat.Mode&0022 != 0 || proofStat.Size > 16384 {
		return errors.New("provisioning_receipt_not_independent")
	}
	// Every receipt ancestor must also be root-owned. A root-owned file in a
	// test-user-writable directory would not be independent evidence.
	for parent := filepath.Dir(*standaloneProvisioning); parent != "/"; parent = filepath.Dir(parent) {
		f, e := standaloneOpen(parent, true, false)
		if e != nil {
			return errors.New("provisioning_ancestor_unverified")
		}
		var st unix.Stat_t
		e = unix.Fstat(int(f.Fd()), &st)
		f.Close()
		if e != nil || st.Uid != 0 {
			return errors.New("provisioning_ancestor_not_independent")
		}
	}
	var provision struct {
		Machine         string `json:"machine_id"`
		Username        string `json:"username"`
		UID             int    `json:"uid"`
		Home            string `json:"home"`
		Runtime         string `json:"runtime_dir"`
		Bus             string `json:"bus_address"`
		NoCloudIdentity bool   `json:"no_cloud_identity"`
		ExclusiveUID    bool   `json:"no_untrusted_same_uid_processes"`
	}
	d := json.NewDecoder(io.LimitReader(proof, 16385))
	if d.Decode(&provision) != nil || d.Decode(new(any)) != io.EOF || provision.Machine != *standaloneMachine || provision.Username != account.Username || provision.UID != os.Getuid() || provision.Home != home || !provision.NoCloudIdentity || !provision.ExclusiveUID {
		return errors.New("provisioning_binding_mismatch")
	}
	machine, err := os.ReadFile("/etc/machine-id")
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(*standaloneMachine) || strings.TrimSpace(string(machine)) != *standaloneMachine {
		return errors.New("dedicated_machine_unverified")
	}
	runtimeDir := "/run/user/" + account.Uid
	if provision.Runtime != runtimeDir || provision.Bus != "unix:path="+runtimeDir+"/bus" {
		return errors.New("provisioning_session_mismatch")
	}
	if os.Getenv("XDG_RUNTIME_DIR") != runtimeDir || os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "unix:path="+runtimeDir+"/bus" || !standalonePrivateDir(runtimeDir) {
		return errors.New("dedicated_bus_path_unverified")
	}
	bus, err := dbus.Connect(os.Getenv("DBUS_SESSION_BUS_ADDRESS"))
	if err != nil {
		return errors.New("dedicated_bus_unavailable")
	}
	defer bus.Close()
	var managerPID uint32
	for _, name := range []string{"org.freedesktop.systemd1", "org.freedesktop.secrets"} {
		var owner string
		var uid uint32
		if bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, name).Store(&owner) != nil || bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", 0, owner).Store(&uid) != nil || uid != uint32(os.Getuid()) {
			return errors.New("dedicated_native_service_owner_unverified")
		}
		if name == "org.freedesktop.systemd1" && (bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixProcessID", 0, owner).Store(&managerPID) != nil || managerPID == 0) {
			return errors.New("dedicated_manager_pid_unverified")
		}
	}
	out, err := r.command(ctx, "/usr/bin/systemctl", "--user", "show", "init.scope", "--property=ControlGroup", "--value")
	defer clear(out)
	if err != nil || strings.TrimSpace(string(out)) != "/user.slice/user-"+account.Uid+".slice/user@"+account.Uid+".service/init.scope" {
		return errors.New("dedicated_user_manager_unverified")
	}
	out, err = r.command(ctx, "/usr/bin/systemctl", "--user", "show-environment")
	if err != nil {
		return errors.New("manager_environment_unavailable")
	}
	defer clear(out)
	allowed := map[string]bool{}
	for _, key := range []string{"HOME", "LOGNAME", "USER", "SHELL", "PATH", "LANG", "LC_ALL", "LC_CTYPE", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "XDG_DATA_DIRS", "XDG_CONFIG_DIRS", "XDG_SESSION_CLASS", "QT_ACCESSIBILITY", "SYSTEMD_EXEC_PID"} {
		allowed[key] = true
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !allowed[key] || (key == "HOME" && value != home) || (key == "XDG_RUNTIME_DIR" && value != runtimeDir) || (key == "DBUS_SESSION_BUS_ADDRESS" && value != "unix:path="+runtimeDir+"/bus") {
			return errors.New("manager_environment_not_allowlisted")
		}
		// These pre-existing OS values were observed in the actual manager.
		// They are read and verified, never introduced or set by this test.
		if (key == "QT_ACCESSIBILITY" && value != "0" && value != "1") || (key == "SYSTEMD_EXEC_PID" && value != strconv.FormatUint(uint64(managerPID), 10)) {
			return errors.New("manager_environment_identity_mismatch")
		}
	}
	return nil
}

func fmtUID() string { return strconv.Itoa(os.Getuid()) }

func standaloneAbsent(ctx context.Context, r *standaloneRun, label string) error {
	out, err := r.command(ctx, "/usr/bin/systemctl", "--user", "show", label+".service", "--property=LoadState", "--value")
	defer clear(out)
	if strings.TrimSpace(string(out)) != "not-found" {
		return errors.New("service_absence_unproven")
	}
	// systemctl may return 0 or 1 for a missing unit. A timeout/overflow has no
	// output, and every other failure is conservatively refused.
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			return errors.New("service_absence_unproven")
		}
	}
	return nil
}

func standaloneReceipt(raw []byte) (install.Record, error) {
	var found install.Record
	s := bufio.NewScanner(bytes.NewReader(raw))
	s.Buffer(make([]byte, 4096), 1<<20)
	for s.Scan() {
		var line struct {
			Record install.Record `json:"record"`
		}
		if _, err := jcs.Canonicalize(s.Bytes()); err != nil {
			return found, err
		}
		if json.Unmarshal(s.Bytes(), &line) != nil {
			return found, errors.New("receipt_json")
		}
		if line.Record.Schema != 0 {
			if found.Schema != 0 {
				return found, errors.New("duplicate_receipt")
			}
			found = line.Record
		}
	}
	if s.Err() != nil || found.Schema != 1 || !install.ValidExecutablePath(found) {
		return found, errors.New("missing_receipt")
	}
	return found, nil
}

func (r *standaloneRun) call(ctx context.Context, name string, args map[string]any) []byte {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	pinned, err := standaloneImage(r.image, *standaloneDigest)
	if err != nil {
		r.t.Fatal("MCP image identity changed")
	}
	defer pinned.Close()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "shim", "--data-dir", r.data, "--run-dir", r.run)
	cmd.ExtraFiles = []*os.File{pinned}
	cmd.Env = r.env
	in, err := cmd.StdinPipe()
	if err != nil {
		r.t.Fatal("MCP stdin unavailable")
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		r.t.Fatal("MCP stdout unavailable")
	}
	var stderr standaloneOutput
	cmd.Stderr = &stderr
	if cmd.Start() != nil {
		r.t.Fatal("MCP product launch failed")
	}
	defer func() { in.Close(); cancel(); cmd.Wait(); clear(stderr.Bytes()) }()
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": args, "_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": daemon.LatestProtocolVersion, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}})
	if ipc.WriteFrame(in, daemon.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params}) != nil {
		r.t.Fatal("MCP write failed")
	}
	raw, err := ipc.ReadFrame(bufio.NewReader(out))
	if err != nil {
		r.t.Fatal("MCP read failed")
	}
	var response struct {
		ID     json.RawMessage `json:"id"`
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError bool                          `json:"isError"`
			Content []struct{ Type, Text string } `json:"content"`
		} `json:"result"`
	}
	if _, err := jcs.Canonicalize(raw); err != nil {
		r.t.Fatal("noncanonical MCP response")
	}
	if json.Unmarshal(raw, &response) != nil || string(response.ID) != "1" || (len(response.Error) > 0 && string(response.Error) != "null") || response.Result.IsError || len(response.Result.Content) == 0 || stderr.overflow {
		r.t.Fatal("actual MCP tool refused or malformed")
	}
	var text bytes.Buffer
	for _, c := range response.Result.Content {
		if c.Type == "text" {
			text.WriteString(c.Text)
			text.WriteByte('\n')
		}
	}
	if text.Len() == 0 {
		r.t.Fatal("MCP tool returned no text evidence")
	}
	return text.Bytes()
}

// This gate writes only through the actual installed product. No transcript,
// signed record, vault, peer, daemon or service-manager double is supplied.
// Native vendor capture remains a separate NOT_RUN gate without operator auth.
func TestStandaloneLinuxActualCLI(t *testing.T) {
	if *standaloneHome == "" {
		t.Skip("explicit dedicated Linux home required")
	}
	home, err := os.UserHomeDir()
	if err != nil || home != *standaloneHome || *standaloneUser == "" || !standalonePrivateDir(home) || os.Getuid() == 0 || os.Getuid() != os.Geteuid() || !standalonePrivateDir(*standaloneResults) {
		t.Fatal("dedicated private unprivileged environment required")
	}
	if !record.IsHex64(*standaloneDigest) || !filepath.IsAbs(*standaloneCLI) {
		t.Fatal("authenticated actual CLI artifact required")
	}
	canonical, err := filepath.EvalSymlinks(*standaloneCLI)
	if err != nil || canonical != *standaloneCLI {
		t.Fatal("CLI path must be canonical")
	}
	f, err := standaloneImage(*standaloneCLI, *standaloneDigest)
	if err != nil {
		t.Fatal("CLI unavailable")
	}
	info, err := buildinfo.Read(f)
	f.Close()
	if err != nil || info.Path != "github.com/Telara-Labs/hilo/contract/internal/node/cmd/hilo" {
		t.Fatal("actual product CLI build identity required")
	}
	version, installMode := "standalone-acceptance", "AUTHENTICATED_SOURCE_DIGEST"
	if *standaloneRelease != "" {
		f, e := standaloneOpen(*standaloneRelease, true, false)
		if e != nil {
			t.Fatal("signed release directory unsafe")
		}
		f.Close()
		target, digest, releaseVersion, e := releaseauth.Target(*standaloneRelease, runtime.GOOS, runtime.GOARCH)
		if e != nil || target != *standaloneCLI || digest != *standaloneDigest {
			t.Fatal("signed release target does not match actual CLI artifact")
		}
		version, installMode = releaseVersion, "SIGNED_RELEASE_DIRECTORY"
	}
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := install.DefaultDir()
	if err != nil {
		t.Fatal("install discovery refused")
	}
	paths, err := ipc.Resolve("", filepath.Join(home, ".cache", "hilo-accept-run"))
	if err != nil {
		t.Fatal("profile paths refused")
	}
	for _, path := range []string{dir, paths.Data, paths.Run, filepath.Join(config, "telara-memory"), filepath.Join(config, "telara-memory-install")} {
		if !strings.HasPrefix(path, home+string(os.PathSeparator)) {
			t.Fatal("profile escaped dedicated home")
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("preexisting profile preserved")
		}
		f, e := standaloneOpen(path, true, true)
		if f != nil {
			f.Close()
		}
		if e != nil {
			t.Fatal("unsafe profile ancestor preserved")
		}
	}
	r := standaloneRun{t: t, env: standaloneEnvironment(), image: *standaloneCLI, data: paths.Data, run: paths.Run}
	planned, err := install.PlannedRecord(install.Config{Dir: dir, Home: home, Executable: r.image, SHA256: *standaloneDigest, Version: version, DataDir: r.data, RunDir: r.run})
	if err != nil {
		t.Fatal("install plan refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err = r.verifyDedicatedSession(ctx, home); err != nil {
		t.Fatal(err)
	}
	if err = standaloneFDProbe(ctx); err != nil {
		t.Fatal(err)
	}
	if err = standaloneAbsent(ctx, &r, planned.Label); err != nil {
		t.Fatal("current service must be absent before mutation")
	}
	if err = standaloneAbsent(ctx, &r, "dev.telara.memory"); err != nil {
		t.Fatal("legacy service must be absent before mutation")
	}
	checks := map[string]string{"native_transcript_capture": "NOT_RUN_NO_OPERATOR_AUTH", "hosted": "DEFERRED", "network_isolation": "REQUIRES_INDEPENDENT_RUNNER_EGRESS_RECEIPT", "home_credential_inventory": "REQUIRES_INDEPENDENT_RUNNER_PROVISIONING_RECEIPT", "dedicated_user": *standaloneUser, "dedicated_machine_id": *standaloneMachine, "source_cli_sha256": *standaloneDigest, "go_version": info.GoVersion}
	checks["installation_mode"] = installMode
	checks["installation_version"] = version
	var installed bool
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if installed {
			var raw []byte
			f, e := standaloneOpen(filepath.Join(dir, "install.json"), false, false)
			if e == nil {
				raw, e = io.ReadAll(io.LimitReader(f, 16385))
				f.Close()
				if len(raw) > 16384 {
					e = errors.New("cleanup_receipt_oversized")
				}
			}
			var current install.Record
			if e != nil || json.Unmarshal(raw, &current) != nil || current != planned {
				t.Error("cleanup receipt changed; preserve profile")
				checks["cleanup"] = "FAIL_PRESERVED"
				installed = false
			}
		}
		if installed {
			// Verify receipt/image ownership before issuing the exact uninstall.
			v, e := install.VerifiedExecutable(dir)
			if e != nil {
				t.Error("cleanup image authority unverified")
				checks["cleanup"] = "FAIL_PRESERVED"
			} else {
				if v.Path != planned.Executable || v.SHA256 != planned.SHA256 {
					v.Close()
					t.Error("cleanup image binding changed")
					checks["cleanup"] = "FAIL_PRESERVED"
				} else {
					v.Close()
					out, e := r.command(cleanup, r.image, "uninstall", "--install-dir", dir)
					clear(out)
					if e != nil || standaloneAbsent(cleanup, &r, planned.Label) != nil {
						t.Error("owned product uninstall failed")
						checks["cleanup"] = "FAIL_PRESERVED"
					} else {
						checks["cleanup"] = "PASS_PRODUCT_UNINSTALL"
					}
				}
			}
		}
		checks["verdict"] = "PASS_ACTUAL_CLI_MCP_STORAGE_NATIVE_CAPTURE_NOT_RUN"
		if t.Failed() {
			checks["verdict"] = "FAIL"
		}
		var nonce [16]byte
		rand.Read(nonce[:])
		raw, _ := json.MarshalIndent(checks, "", "  ")
		f, e := os.OpenFile(filepath.Join(*standaloneResults, "standalone-"+hex.EncodeToString(nonce[:])+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Error("receipt create failed")
		} else {
			_, e = f.Write(append(raw, '\n'))
			ce := f.Close()
			if e != nil || ce != nil {
				t.Error("receipt write failed")
			}
		}
	}()
	installed = true // Partial installation must also be settled, never silently removed.
	installArgs := []string{"install", "--data-dir", r.data, "--run-dir", r.run, "--install-dir", dir}
	if *standaloneRelease != "" {
		installArgs = append(installArgs, "--release-dir", *standaloneRelease)
	} else {
		installArgs = append(installArgs, "--source", r.image, "--sha256", *standaloneDigest, "--version", planned.Version)
	}
	out, err := r.command(ctx, r.image, installArgs...)
	actual, parseErr := standaloneReceipt(out)
	clear(out)
	if err != nil || parseErr != nil || actual != planned {
		t.Fatal("actual native install/receipt failed")
	}
	r.image = actual.Executable
	checks["install"] = "PASS_ACTUAL_NATIVE_MANAGER_AND_VAULT"
	if v, e := install.VerifiedExecutable(dir); e != nil {
		t.Fatal("installed image verification failed")
	} else {
		v.Close()
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	marker := "hilo-standalone-" + hex.EncodeToString(nonce[:])
	canary := "ghp_" + strings.Repeat("A", 36)
	created := r.call(ctx, "telara_task_create", map[string]any{"name": marker, "goal": marker + " " + canary})
	ids := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`).FindAllString(string(created), -1)
	if len(ids) == 0 || bytes.Contains(created, []byte(canary)) {
		t.Fatal("create lacks task identity or leaks canary")
	}
	task := ids[0]
	for _, id := range ids {
		if id != task {
			t.Fatal("ambiguous created task identity")
		}
	}
	r.call(ctx, "telara_task_checkpoint", map[string]any{"task_id": task, "milestone": marker + " persisted across real MCP processes"})
	r.call(ctx, "telara_task_complete", map[string]any{"task_id": task, "final_summary": marker + " complete", "token_estimate": 0})
	for _, stage := range []string{"stop", "start"} {
		out, e := r.command(ctx, r.image, stage, "--install-dir", dir)
		clear(out)
		if e != nil {
			t.Fatal("actual daemon restart failed")
		}
	}
	for _, tool := range []string{"telara_task_list", "telara_knowledge_search"} {
		args := map[string]any{"query": marker}
		if tool == "telara_task_list" {
			args["include_completed"] = true
			args["mode"] = "detail"
		}
		text := r.call(ctx, tool, args)
		if !bytes.Contains(text, []byte(marker)) || bytes.Contains(text, []byte(canary)) {
			t.Fatal("durable cross-process MCP retrieval failed")
		}
	}
	checks["mcp_lifecycle_restart_retrieval"] = "PASS"
	u := url.URL{Scheme: "file", Path: filepath.Join(r.data, "memory.sqlite"), RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal("readonly SQLite unavailable")
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, "SELECT r.id,r.header,b.body,r.state,r.sig_status FROM record r JOIN record_body b ON b.id=r.id ORDER BY r.id")
	if err != nil {
		t.Fatal("SQLite records unavailable")
	}
	defer rows.Close()
	matched := 0
	for rows.Next() {
		var id, state, status string
		var header, body []byte
		if rows.Scan(&id, &header, &body, &state, &status) != nil {
			t.Fatal("SQLite scan failed")
		}
		if bytes.Contains(body, []byte(canary)) {
			t.Fatal("unredacted canary persisted")
		}
		parsed, e := record.Parse(header, body, id)
		if e != nil {
			t.Fatal("invalid content-addressed stored record")
		}
		if parsed.Header.Subj.TaskID == task {
			if state != "live" || status != "verified" {
				t.Fatal("task record not verified live")
			}
			matched++
		}
	}
	if rows.Err() != nil || matched < 3 {
		t.Fatal("actual product task lifecycle records missing")
	}
	checks["sqlite_verified_product_records_redaction"] = "PASS"
	checks["task_id"] = task
	rows.Close()
	db.Close()
	out, err = r.command(ctx, r.image, "stop", "--install-dir", dir)
	clear(out)
	if err != nil {
		t.Fatal("physical redaction stop failed")
	}
	for _, name := range []string{"memory.sqlite", "memory.sqlite-wal", "memory.sqlite-shm"} {
		path := filepath.Join(r.data, name)
		f, e := standaloneOpen(path, false, false)
		if errors.Is(e, os.ErrNotExist) && name != "memory.sqlite" {
			continue
		}
		if e != nil {
			t.Fatal("database physical read refused")
		}
		raw, e := io.ReadAll(io.LimitReader(f, (128<<20)+1))
		f.Close()
		leaked := bytes.Contains(raw, []byte(canary))
		oversized := len(raw) > 128<<20
		clear(raw)
		if e != nil || oversized || leaked {
			t.Fatal("physical database redaction failed")
		}
	}
	checks["physical_database_canary_absence"] = "PASS"
	// Restore start intent so normal product uninstall can verify its image.
	out, err = r.command(ctx, r.image, "start", "--install-dir", dir)
	clear(out)
	if err != nil {
		t.Fatal("post-inspection restart failed")
	}
}
