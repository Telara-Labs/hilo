package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

// Config contains explicit install inputs. SHA256 must come from an authenticated
// release manifest, not from hashing an untrusted download and trusting the result.
// This package neither downloads releases nor trusts a shim-supplied upgrade path.
type Config struct {
	Dir, Home, Label            string
	Executable, SHA256, Version string
	DataDir, RunDir             string
}

type Record struct {
	Schema     int    `json:"schema"`
	Dir        string `json:"dir"`
	Home       string `json:"home"`
	Label      string `json:"label"`
	Platform   string `json:"platform"`
	UserID     string `json:"user_id"`
	Executable string `json:"executable"`
	SHA256     string `json:"sha256"`
	Version    string `json:"version"`
	DataDir    string `json:"data_dir"`
	RunDir     string `json:"run_dir"`
}

type Report struct {
	State  string `json:"state"`
	Record Record `json:"record"`
}
type intent struct {
	Mode    string `json:"mode"`
	SHA256  string `json:"sha256"`
	Version string `json:"version"`
	Session string `json:"session"`
}

// DefaultDir is shared by the command installer and shim. It is independent of
// the memory database so erasure and uninstall cannot delete each other's state.
func DefaultDir() (string, error) {
	base, e := os.UserConfigDir()
	if e != nil {
		return "", e
	}
	return defaultDirAt(base)
}

// defaultDirAt receives the already resolved OS base. Keeping discovery here
// permits deterministic private-directory checks without environment overrides.
func defaultDirAt(base string) (string, error) {
	current := filepath.Join(base, "hilo-install")
	legacy := filepath.Join(base, "telara-memory-install")
	_, ce := os.Lstat(current)
	_, le := os.Lstat(legacy)
	if ce != nil && !os.IsNotExist(ce) {
		return "", ce
	}
	if le != nil && !os.IsNotExist(le) {
		return "", le
	}
	if ce == nil && le == nil {
		return "", ErrUnverified
	}
	if le == nil {
		// Read only a validated owner receipt and digest-pinned executable.
		// Explicit upgrade preserves its manager label, profile and custody.
		r, err := readReceipt(legacy)
		if err != nil {
			return "", err
		}
		// Discovery authenticates bytes without evaluating start/stop intent.
		// Explicit start/uninstall must remain possible for a stopped install.
		v, err := verify(r.Executable, r.SHA256)
		if err != nil {
			return "", err
		}
		if err := v.Close(); err != nil {
			return "", err
		}
		return legacy, nil
	}
	if ce == nil {
		if err := checkDir(current, true); err != nil {
			return "", err
		}
	}
	return current, nil
}

func randomName() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return ".install-" + hex.EncodeToString(b[:]), e
}
func absolute(s string) bool { return filepath.IsAbs(s) && filepath.Clean(s) == s && cleanValue(s) }
func imagePath(dir, digest string) string {
	return namedImagePath(dir, digest, "hilo")
}

func namedImagePath(dir, digest, name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(dir, "bin", digest, name)
}

// ValidExecutablePath shares the platform-specific installed image convention.
func ValidExecutablePath(r Record) bool {
	return validDigest(r.SHA256) && absolute(r.Dir) && (r.Executable == imagePath(r.Dir, r.SHA256) || r.Executable == namedImagePath(r.Dir, r.SHA256, "telara-memory"))
}

func validateRecord(r Record, dir string) error {
	b, e := json.Marshal(r)
	if e != nil || len(b) >= 16384 {
		return ErrUnverified
	}
	if r.Schema != 1 || r.Dir != dir || !absolute(dir) || !absolute(r.Home) || !absolute(r.DataDir) || !absolute(r.RunDir) ||
		!labelPattern.MatchString(r.Label) || !validDigest(r.SHA256) || !cleanValue(r.Version) || len(r.Version) > 128 || r.Platform != runtime.GOOS || r.UserID != userID() || !ValidExecutablePath(r) {
		return ErrUnverified
	}
	return nil
}
func readPrivate(path string, out any) error {
	if e := checkDir(filepath.Dir(path), true); e != nil {
		return e
	}
	f, release, e := openTrusted(path, true)
	if e != nil {
		return e
	}
	defer release()
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(b) > 16384 {
		return ErrUnverified
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrUnverified
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrUnverified
	}
	return nil
}
func readReceipt(dir string) (Record, error) {
	var r Record
	if !absolute(dir) {
		return r, unsafePath("readReceipt", dir, "absolute clean path with no control characters required", nil)
	}
	if e := readPrivate(filepath.Join(dir, "install.json"), &r); e != nil {
		return r, e
	}
	return r, validateRecord(r, dir)
}
func writeJSON(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return writeAtomic(path, append(b, '\n'), 0600)
}
func writeIntent(dir string, r Record, mode, session string) error {
	return writeJSON(filepath.Join(dir, "intent.json"), intent{mode, r.SHA256, r.Version, session})
}
func checkIntent(dir string, r Record) error {
	var v intent
	if e := readPrivate(filepath.Join(dir, "intent.json"), &v); e != nil {
		return ErrUnverified
	}
	return intentState(v, r, func() (string, error) { return loginSession(context.Background()) })
}

func intentState(v intent, r Record, session func() (string, error)) error {
	if v.SHA256 != r.SHA256 || v.Version != r.Version {
		return ErrUnverified
	}
	switch v.Mode {
	case "start", "upgrade":
		return nil
	case "stop":
		if v.Session == "" {
			return ErrStopped
		}
		s, e := session()
		if e != nil {
			return ErrStopped
		}
		if v.Session == s {
			return ErrStopped
		}
		return nil
	default:
		return ErrUnverified
	}
}

// PlannedRecord validates all receipt inputs and their serialized size before
// any filesystem, authority, service-manager or native-vault mutation.
func PlannedRecord(c Config) (Record, error) {
	if c.Home == "" {
		c.Home, _ = os.UserHomeDir()
	}
	if c.Label == "" {
		c.Label = "dev.telara.hilo"
	}
	r := Record{1, c.Dir, c.Home, c.Label, runtime.GOOS, userID(), imagePath(c.Dir, c.SHA256), c.SHA256, c.Version, c.DataDir, c.RunDir}
	if e := validateRecord(r, c.Dir); e != nil {
		return Record{}, e
	}
	return r, nil
}

// Install creates a new immutable, digest-addressed executable and owner-only
// receipt. Existing installs require Upgrade; no implicit reinstall/downgrade.
// Manager absence is persisted and returned as a distinct capture blocker.
func Install(ctx context.Context, c Config) (Report, error) {
	return install(ctx, c, false)
}

// InstallDeferred registers Linux autostart without starting it while the
// caller holds bootstrap writer admission. The caller must start it afterwards.
func InstallDeferred(ctx context.Context, c Config) (Report, error) {
	return install(ctx, c, true)
}

func install(ctx context.Context, c Config, deferLinuxStart bool) (Report, error) {
	r, e := PlannedRecord(c)
	if e != nil {
		return Report{}, e
	}
	if e := ensureDir(c.Dir, true); e != nil {
		return Report{}, e
	}
	lock, e := lockInstall(c.Dir)
	if e != nil {
		return Report{}, e
	}
	defer lock.Close()
	if _, e = readReceipt(c.Dir); !errors.Is(e, os.ErrNotExist) {
		return Report{}, ErrUpgrade
	}
	if e = copyImage(c.Executable, r); e != nil {
		return Report{}, e
	}
	if e = writeIntent(c.Dir, r, "start", ""); e != nil {
		return Report{}, e
	}
	if e = writeJSON(filepath.Join(c.Dir, "install.json"), r); e != nil {
		return Report{}, e
	}
	return register(ctx, r, deferLinuxStart)
}

func copyImage(source string, r Record) error {
	v, e := verify(source, r.SHA256)
	if e != nil {
		return e
	}
	defer v.Close()
	if e = ensureDir(filepath.Dir(r.Executable), true); e != nil {
		return e
	}
	// Content-addressed targets are never overwritten, even by the installer.
	if _, e = os.Lstat(r.Executable); e == nil {
		x, e := verify(r.Executable, r.SHA256)
		if e != nil {
			return e
		}
		return x.Close()
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	b, e := io.ReadAll(io.LimitReader(v.file, 512<<20+1))
	if e != nil || len(b) > 512<<20 {
		return ErrUnverified
	}
	if e = writeAtomic(r.Executable, b, 0700); e != nil {
		return e
	}
	x, e := verify(r.Executable, r.SHA256)
	if e != nil {
		return e
	}
	return x.Close()
}

func register(ctx context.Context, r Record, deferLinuxStart bool) (Report, error) {
	if e := managerAvailable(ctx, r); e != nil {
		if e = writeJSON(filepath.Join(r.Dir, "manager.json"), Report{State: "autostart_unavailable", Record: r}); e != nil {
			return Report{}, e
		}
		return Report{"autostart_unavailable", r}, ErrUnavailable
	}
	// Check the actual manager before creating or trusting a local definition.
	if e := registered(ctx, r); e != nil && !errors.Is(e, errAbsent) {
		return Report{}, e
	}
	b, e := Definition(r.Platform, r)
	if e != nil {
		return Report{}, e
	}
	path := definitionPath(r)
	if e = ensureDir(filepath.Dir(path), false); e != nil {
		return Report{}, e
	}
	// Do not overwrite any preexisting user service definition.
	if _, e = os.Lstat(path); e == nil {
		if e = verifyDefinition(r); e != nil {
			return Report{}, e
		}
		if managerStatus(ctx, r) == nil {
			return Status(ctx, r.Dir)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return Report{}, e
	}
	if e = writeAtomic(path, b, 0600); e != nil {
		return Report{}, e
	}
	if e = managerInstallMode(ctx, r, deferLinuxStart); e != nil {
		if se := writeJSON(filepath.Join(r.Dir, "manager.json"), Report{"autostart_unavailable", r}); se != nil {
			return Report{}, se
		}
		return Report{"autostart_unavailable", r}, ErrUnavailable
	}
	report, e := Status(ctx, r.Dir)
	if e != nil {
		return report, e
	}
	if e = writeJSON(filepath.Join(r.Dir, "manager.json"), report); e != nil {
		return Report{}, e
	}
	return report, nil
}

// Register retries registration after an unavailable manager. It accepts only
// the exact owner-only definition for the verified installation, never replaces
// an unrelated preexisting service file.
func Register(ctx context.Context, dir string) (Report, error) {
	return registerInstalled(ctx, dir, false)
}

// RegisterDeferred retries Linux registration without launching during bootstrap.
func RegisterDeferred(ctx context.Context, dir string) (Report, error) {
	return registerInstalled(ctx, dir, true)
}

func registerInstalled(ctx context.Context, dir string, deferLinuxStart bool) (Report, error) {
	lock, e := lockInstall(dir)
	if e != nil {
		return Report{}, e
	}
	defer lock.Close()
	r, e := readReceipt(dir)
	if e != nil {
		return Report{}, e
	}
	v, e := VerifiedExecutable(dir)
	if e != nil {
		return Report{}, e
	}
	defer v.Close()
	return register(ctx, r, deferLinuxStart)
}

// Status verifies bytes and queries the real service manager on every call.
// 'registered' proves the definition exists, not daemon readiness or capture.
func Status(ctx context.Context, dir string) (Report, error) {
	r, e := readReceipt(dir)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return Report{}, ErrUnverified
		}
		return Report{}, e
	}
	v, e := verify(r.Executable, r.SHA256)
	if e != nil {
		return Report{}, e
	}
	v.Close()
	if e = checkIntent(dir, r); e != nil {
		if errors.Is(e, ErrStopped) {
			// This is autostart intent, not proof that a prior process exited.
			return Report{"autostart_stopped", r}, nil
		}
		return Report{}, e
	}
	if e = managerAvailable(ctx, r); e != nil {
		return Report{"autostart_unavailable", r}, ErrUnavailable
	}
	if e = verifyDefinition(r); e != nil {
		return Report{}, e
	}
	if e = managerStatus(ctx, r); e != nil {
		if !errors.Is(e, errAbsent) && !errors.Is(e, ErrUnavailable) {
			return Report{}, e
		}
		return Report{"autostart_unavailable", r}, ErrUnavailable
	}
	return Report{"registered", r}, nil
}

// Start uses the installed service manager. It never falls back to detached
// execution. Explicit start clears stop intent; shim autostart must use Autostart.
func Start(ctx context.Context, dir string) error     { return start(ctx, dir, true) }
func Autostart(ctx context.Context, dir string) error { return start(ctx, dir, false) }
func start(ctx context.Context, dir string, explicit bool) error {
	lock, e := lockInstall(dir)
	if e != nil {
		return e
	}
	defer lock.Close()
	r, e := readReceipt(dir)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return ErrUnverified
		}
		return e
	}
	v, e := verify(r.Executable, r.SHA256)
	if e != nil {
		return e
	}
	defer v.Close()
	if !explicit {
		if e = checkIntent(dir, r); e != nil {
			return e
		}
	}
	if e = verifyDefinition(r); e != nil {
		return e
	}
	if e = managerAvailable(ctx, r); e != nil {
		return ErrUnavailable
	}
	if explicit {
		if e = writeIntent(dir, r, "start", ""); e != nil {
			return e
		}
	}
	return managerStart(ctx, r)
}

// Quiesce must stop admission, settle transactions, close storage and prove the
// old process released db.lock. On any error the manager is left untouched.
type Quiesce func(context.Context) error

func Stop(ctx context.Context, dir string, quiesce Quiesce) error {
	lock, e := lockInstall(dir)
	if e != nil {
		return e
	}
	defer lock.Close()
	r, e := readReceipt(dir)
	if e != nil {
		return e
	}
	return stop(ctx, r, quiesce)
}
func stop(ctx context.Context, r Record, q Quiesce) error {
	if q == nil {
		return ErrUpgrade
	}
	if e := verifyDefinition(r); e != nil {
		return e
	}
	if e := registered(ctx, r); e != nil && !errors.Is(e, errAbsent) {
		return e
	}

	s, e := loginSession(ctx)
	if e != nil {
		return ErrUnavailable
	}
	if e = writeIntent(r.Dir, r, "stop", s); e != nil {
		return e
	}
	if e = q(ctx); e != nil {
		return ErrUpgrade
	}
	return managerStop(ctx, r)
}

// Upgrade is explicitly invoked with independently authenticated release inputs.
// The old process must have settled before an atomic receipt/manager change.
// Any partial failure leaves stop intent or a mismatching intent (fail closed).
func Upgrade(ctx context.Context, dir, source, digest, version string, q Quiesce) (Report, error) {
	lock, e := lockInstall(dir)
	if e != nil {
		return Report{}, e
	}
	defer lock.Close()
	if e = reconcileUpgrade(ctx, dir); e != nil {
		return Report{}, e
	}
	r, e := readReceipt(dir)
	if e != nil {
		return Report{}, e
	}
	old, e := verify(r.Executable, r.SHA256)
	if e != nil {
		return Report{}, e
	}
	defer old.Close()
	next := r
	next.SHA256 = digest
	next.Version = version
	// Preserve the exact basename of a verified legacy installation for the
	// old retained custody helper. Fresh installations always use hilo.
	next.Executable = imagePath(dir, digest)
	if r.Executable == namedImagePath(dir, r.SHA256, "telara-memory") {
		next.Executable = namedImagePath(dir, digest, "telara-memory")
	}
	if e = validateRecord(next, dir); e != nil {
		return Report{}, e
	}
	if next == r {
		return Status(ctx, dir)
	}
	// Bound the recovery journal before copying images or stopping the source.
	if b, err := json.Marshal(upgradePublication{1, r, next}); err != nil || len(b) >= 16384 {
		return Report{}, ErrUnverified
	}
	if e = verifyDefinition(r); e != nil {
		return Report{}, e
	}
	if e = copyImage(source, next); e != nil {
		return Report{}, e
	}
	if e = stop(ctx, r, q); e != nil {
		return Report{}, e
	}
	if e = ipc.ValidateDir(r.DataDir, true); e != nil {
		return Report{}, e
	}
	writer, e := ipc.Lock(filepath.Join(r.DataDir, "db.lock"))
	if e != nil {
		return Report{}, e
	}
	defer writer.Close()
	publication := upgradePublication{1, r, next}
	if e = writeJSON(filepath.Join(dir, upgradePublicationFile), publication); e != nil {
		return Report{}, e
	}
	if e = publishUpgrade(ctx, publication); e != nil {
		return Report{"upgrade_failed", next}, e
	}
	if e = writer.Close(); e != nil {
		return Report{}, e
	}
	if e = removeOwned(filepath.Join(dir, upgradePublicationFile)); e != nil {
		return Report{}, e
	}

	return Status(ctx, dir)
}

// Uninstall removes only this receipt's exact service definition and controls.
// It preserves the executable, data, logs, and every unrelated user service.
func Uninstall(ctx context.Context, dir string, q Quiesce) error {
	lock, e := lockInstall(dir)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = reconcileUpgrade(ctx, dir); e != nil {
		return e
	}
	r, e := readReceipt(dir)
	if e != nil {
		return e
	}
	if _, e = os.Lstat(definitionPath(r)); errors.Is(e, os.ErrNotExist) {
		// A manager that was unavailable at first install never received a
		// definition. Remove only our receipt, without touching any service.
		var prior Report
		if e = readPrivate(filepath.Join(dir, "manager.json"), &prior); e != nil || prior.State != "autostart_unavailable" || prior.Record != r {
			return ErrUnverified
		}
		if q == nil {
			return ErrUpgrade
		}
		if e = writeIntent(dir, r, "stop", ""); e != nil {
			return e
		}
		if e = q(ctx); e != nil {
			return ErrUpgrade
		}
		return removeOwned(filepath.Join(dir, "install.json"))
	}
	if e = verifyDefinition(r); e != nil {
		return e
	}
	if e = stop(ctx, r, q); e != nil {
		return e
	}
	if e = managerUninstall(ctx, r); e != nil {
		return e
	}
	if e = removeOwned(definitionPath(r)); e != nil {
		return e
	}
	return removeOwned(filepath.Join(dir, "install.json"))
}
