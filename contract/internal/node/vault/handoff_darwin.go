//go:build darwin && cgo

package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
)

const handoffFile = "custody-upgrade.json"

type custodyHandoff struct {
	Version  int            `json:"version"`
	Source   install.Record `json:"source"`
	Target   string         `json:"target_sha256"`
	Handle   string         `json:"handle"`
	Keychain string         `json:"keychain"`
	Phase    string         `json:"phase"`
	Legacy   bool           `json:"legacy_source_slot"`
}

func digestValid(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}
func handoffTarget(r install.Record, digest string) string {
	return filepath.Join(r.Dir, "bin", digest, "telara-memory")
}

func privateRead(path string) ([]byte, error) {
	if ipc.ValidateDir(filepath.Dir(path), false) != nil {
		return nil, ErrUnavailable
	}
	before, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !trustedCustodyStat(before, true, false) || !custodyACLReadOnly(path, true) || before.Size() > 16384 {
		return nil, ErrUnavailable
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) {
		return nil, ErrUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(b) > 16384 {
		return nil, ErrUnavailable
	}
	return b, nil
}
func readHandoff(data string) (custodyHandoff, error) {
	var m custodyHandoff
	b, e := privateRead(filepath.Join(data, handoffFile))
	if e != nil {
		return m, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || m.Version != 1 || !digestValid(m.Source.SHA256) || !digestValid(m.Target) ||
		m.Source.Executable != handoffTarget(m.Source, m.Source.SHA256) || m.Source.DataDir != data ||
		!filepath.IsAbs(m.Source.Dir) || filepath.Clean(m.Source.Dir) != m.Source.Dir ||
		valid(context.Background(), m.Handle) != nil || (m.Phase != "prepared" && m.Phase != "ready") ||
		(m.Keychain != "" && (!filepath.IsAbs(m.Keychain) || filepath.Clean(m.Keychain) != m.Keychain)) {
		return custodyHandoff{}, ErrUnavailable
	}
	return m, nil
}
func syncHandoffDir(data string) error {
	f, e := os.Open(data)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func writeHandoff(m custodyHandoff) error {
	if ipc.ValidateDir(m.Source.DataDir, false) != nil {
		return ErrUnavailable
	}
	b, e := json.Marshal(m)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(m.Source.DataDir, ".custody-upgrade-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Rename(f.Name(), filepath.Join(m.Source.DataDir, handoffFile)); e != nil {
		return e
	}
	return syncHandoffDir(m.Source.DataDir)
}
func installedHandle(data string) (string, error) {
	b, e := privateRead(filepath.Join(data, "installed-authority.json"))
	if e != nil {
		return "", e
	}
	var m struct {
		Version    int    `json:"version"`
		Owner      string `json:"owner"`
		Machine    string `json:"machine"`
		Credential string `json:"credential"`
		Handle     string `json:"vault_handle"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || m.Version != 1 || valid(context.Background(), m.Handle) != nil {
		return "", ErrUnavailable
	}
	return m.Handle, nil
}

// pinHandoffImage checks every ancestor and retains the exact inode during
// launch. Same-owner executable modification/injection is outside containment.
func pinHandoffImage(path, digest string) (*os.File, error) {
	if !digestValid(digest) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, install.ErrUnverified
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		st, e := os.Lstat(dir)
		if e != nil || !trustedCustodyStat(st, false, true) || !custodyACLReadOnly(dir, false) {
			return nil, install.ErrUnverified
		}
		if dir == "/" {
			break
		}
	}
	before, e := os.Lstat(path)
	if e != nil || !trustedCustodyStat(before, false, false) || !custodyACLReadOnly(path, false) || before.Mode().Perm()&0100 == 0 || before.Size() > 512<<20 {
		return nil, install.ErrUnverified
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil || !os.SameFile(before, st) {
		f.Close()
		return nil, install.ErrUnverified
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (512<<20)+1))
	if e != nil || n > 512<<20 || hex.EncodeToString(h.Sum(nil)) != digest {
		f.Close()
		return nil, install.ErrUnverified
	}
	return f, nil
}

func (v *Vault) imageOperation(ctx context.Context, path, digest string, op byte, handle string, secret []byte) ([]byte, error) {
	if valid(ctx, handle) != nil || len(secret) > maxSecret || len(v.keychainPath) > 4096 {
		return nil, ErrInvalid
	}
	f, e := pinHandoffImage(path, digest)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	raw := make([]byte, 35+len(v.keychainPath)+len(secret))
	defer clear(raw)
	raw[0] = op
	copy(raw[1:33], handle)
	binary.BigEndian.PutUint16(raw[33:35], uint16(len(v.keychainPath)))
	copy(raw[35:], v.keychainPath)
	copy(raw[35+len(v.keychainPath):], secret)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, helperArg)
	cmd.WaitDelay = time.Second
	cmd.Stdin = bytes.NewReader(raw)
	// Fixed storage refuses unbounded output from even an authenticated image.
	output := &custodyOutput{}
	defer clear(output.b[:])
	cmd.Stdout = output
	if e = cmd.Run(); e != nil {
		return nil, ErrUnavailable
	}
	after, e := os.Lstat(path)
	before, se := f.Stat()
	if e != nil || se != nil || !os.SameFile(before, after) || output.n < 1 {
		return nil, ErrUnavailable
	}
	switch output.b[0] {
	case 0:
		if (op == 2 || op == 9) && output.n == 1 {
			return nil, ErrUnavailable
		}
		return append([]byte(nil), output.b[1:output.n]...), nil
	case 1:
		return nil, ErrExists
	case 2:
		return nil, ErrNotFound
	default:
		return nil, ErrUnavailable
	}
}

type custodyOutput struct {
	b [maxSecret + 1]byte
	n int
}

func (b *custodyOutput) Write(p []byte) (int, error) {
	if len(p) > len(b.b)-b.n {
		return 0, ErrUnavailable
	}
	copy(b.b[b.n:], p)
	b.n += len(p)
	return len(p), nil
}

// checkTargetCapabilities authenticates the target image before a nonmutating
// protocol exchange. No native location or authority is sent during this probe.
func checkTargetCapabilities(ctx context.Context, path, digest string) error {
	f, e := pinHandoffImage(path, digest)
	if e != nil {
		return e
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, capabilityArg)
	cmd.WaitDelay = time.Second
	cmd.Stdin = bytes.NewReader(capabilityRequest)
	out := &custodyOutput{}
	cmd.Stdout = out
	if cmd.Run() != nil {
		return ErrUnavailable
	}
	before, se := f.Stat()
	after, ae := os.Lstat(path)
	if se != nil || ae != nil || !os.SameFile(before, after) || !compatibleCapabilities(out.b[:out.n]) {
		return ErrUnavailable
	}
	return nil
}

// CheckUpgradeTarget lets a newer lifecycle caller reject an incompatible
// successor before asking an older installed daemon to prepare any transfer.
func CheckUpgradeTarget(ctx context.Context, source install.Record, target string) error {
	if ctx == nil || !digestValid(target) {
		return ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	report, e := install.Status(ctx, source.Dir)
	if (e != nil && !errors.Is(e, install.ErrUnavailable)) || report.Record != source {
		return install.ErrUnverified
	}
	return checkTargetCapabilities(ctx, handoffTarget(source, target), target)
}

// abortUnpublished authenticates the still-current source and proves its custody
// before removing a historical incompatible-target marker. Metadata enumeration
// refuses unexplained foreign slots even when a target cannot run any helper.
// Caller holds custody-upgrade.lock and lifecycle/db writer admission.
func (v *Vault) abortUnpublished(ctx context.Context, current install.Record, m custodyHandoff) error {
	report, e := install.Status(ctx, current.Dir)
	if (e != nil && !errors.Is(e, install.ErrUnavailable)) || report.Record != current || current != m.Source || m.Keychain != v.keychainPath {
		return install.ErrUnverified
	}
	h, e := installedHandle(current.DataDir)
	if e != nil || h != m.Handle {
		return ErrUnavailable
	}
	f, e := pinHandoffImage(handoffTarget(current, m.Target), m.Target)
	if e != nil {
		return e
	}
	f.Close()
	secret, e := v.imageOperation(ctx, current.Executable, current.SHA256, 2, h, nil)
	if e != nil {
		return e
	}
	clear(secret)
	own, e := v.imageOperation(ctx, current.Executable, current.SHA256, 5, h, nil)
	if e != nil {
		return e
	}
	if m.Legacy {
		own = []byte(service)
	}
	probe := func() error {
		b, e := v.operation(ctx, "foreign-slots", h, own)
		if e != nil || len(b) != 1 || b[0] != 0 {
			return ErrUnavailable
		}
		return nil
	}
	if probe() != nil {
		// Older helpers can lack the handshake yet still support exact-slot cleanup.
		target, e := v.imageOperation(ctx, handoffTarget(current, m.Target), m.Target, 5, h, nil)
		if e != nil {
			return e
		}
		if m.Legacy {
			own = []byte(service)
		}
		if string(own) != string(target) {
			if _, e = v.imageOperation(ctx, handoffTarget(current, m.Target), m.Target, 6, h, nil); e != nil {
				return e
			}
		}
		if e = probe(); e != nil {
			return e
		}
	}
	if e = os.Remove(filepath.Join(current.DataDir, handoffFile)); e != nil {
		return e
	}
	return syncHandoffDir(current.DataDir)
}

// PrepareUpgrade runs in the old verified daemon before quiescence. The install
// lifecycle lock has already authenticated and staged Target. Secrets go only
// through bounded anonymous pipes into that exact image's native helper.
func (v *Vault) PrepareUpgrade(ctx context.Context, source install.Record, target string) error {
	if ctx == nil {
		return ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if v == nil || v.closed || !digestValid(target) || source.Executable != handoffTarget(source, source.SHA256) {
		return ErrInvalid
	}
	self, e := os.Executable()
	if e != nil || self != source.Executable {
		return install.ErrUnverified
	}
	r, e := install.Status(ctx, source.Dir)
	if (e != nil && !errors.Is(e, install.ErrUnavailable)) || r.Record != source {
		return install.ErrUnverified
	}
	if e = v.bindCustody(ctx, source.DataDir, false); e != nil {
		return e
	}
	targetImage, e := pinHandoffImage(handoffTarget(source, target), target)
	if e != nil {
		return e
	}
	defer targetImage.Close()
	// Refuse incompatible targets before even creating the transfer lock file.
	if e = checkTargetCapabilities(ctx, handoffTarget(source, target), target); e != nil {
		return e
	}
	lock, e := ipc.Lock(filepath.Join(source.DataDir, "custody-upgrade.lock"))
	if e != nil {
		return e
	}
	defer lock.Close()
	handle, e := installedHandle(source.DataDir)
	if e != nil {
		return e
	}
	m, e := readHandoff(source.DataDir)
	if e == nil && m.Source == source && m.Handle == handle && m.Keychain == v.keychainPath &&
		(m.Target != target || checkTargetCapabilities(ctx, handoffTarget(source, m.Target), m.Target) != nil) {
		if e = v.abortUnpublished(ctx, source, m); e != nil {
			return e
		}
		e = os.ErrNotExist
	}
	if os.IsNotExist(e) {
		slot, e := v.operation(ctx, "legacy-slot", handle, nil)
		if e != nil || len(slot) != 1 || slot[0] > 1 {
			return ErrUnavailable
		}
		m = custodyHandoff{1, source, target, handle, v.keychainPath, "prepared", slot[0] == 1}
		if e = writeHandoff(m); e != nil {
			return e
		}
	} else if e != nil || m.Source != source || m.Target != target || m.Handle != handle || m.Keychain != v.keychainPath {
		return ErrUnavailable
	}
	secret, e := v.Get(ctx, handle)
	if e != nil {
		return e
	}
	defer clear(secret)
	readback, e := v.imageOperation(ctx, handoffTarget(source, target), target, 4, handle, secret)
	defer clear(readback)
	if e != nil || subtle.ConstantTimeCompare(secret, readback) != 1 {
		return ErrUnavailable
	}
	m.Phase = "ready"
	return writeHandoff(m)
}

// RecoverUpgrade runs under db.lock before opening a managed backend. Old receipt
// means old custody remains authoritative. New receipt means verify new readback,
// then retire only the old build's slot and durably remove the pending marker.
func (v *Vault) RecoverUpgrade(ctx context.Context, current install.Record) error {
	if ctx == nil {
		return ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if v == nil || v.closed {
		return ErrUnavailable
	}
	lock, e := ipc.Lock(filepath.Join(current.DataDir, "custody-upgrade.lock"))
	if e != nil {
		return e
	}
	defer lock.Close()
	m, e := readHandoff(current.DataDir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if current == m.Source {
		return nil
	}
	expected := m.Source
	expected.SHA256 = m.Target
	expected.Executable = handoffTarget(m.Source, m.Target)
	expected.Version = current.Version
	self, e := os.Executable()
	if e != nil || current != expected || self != current.Executable || m.Phase != "ready" {
		return install.ErrUnverified
	}
	if e = v.bindCustody(ctx, current.DataDir, false); e != nil {
		return e
	}
	if m.Keychain != v.keychainPath {
		return ErrUnavailable
	}
	handle, e := installedHandle(current.DataDir)
	if e != nil || handle != m.Handle {
		return ErrUnavailable
	}
	secret, e := v.operation(ctx, "get-own", handle, nil)
	if e != nil {
		return e
	}
	defer clear(secret)
	// Probe the old image's namespace before deletion. Stable signed builds share
	// one item, so deleting that namespace would delete the current credential.
	oldService, e := v.imageOperation(ctx, m.Source.Executable, m.Source.SHA256, 5, handle, nil)
	if e != nil {
		return e
	}
	ownService, e := nativeService()
	if e != nil {
		return e
	}
	if m.Legacy {
		oldService = []byte(service)
	}
	if string(oldService) != ownService {
		op := byte(6)
		if m.Legacy {
			op = 7
		}
		if _, e = v.imageOperation(ctx, m.Source.Executable, m.Source.SHA256, op, handle, nil); e != nil {
			return e
		}
	}
	if e = os.Remove(filepath.Join(current.DataDir, handoffFile)); e != nil {
		return e
	}
	return syncHandoffDir(current.DataDir)
}

func UpgradeHandoffRequired() bool { return true }

const resumeArg = "native-custody-upgrade"
const recoverArg = "native-custody-recover"

type resumeRequest struct {
	Source   install.Record `json:"source"`
	Target   string         `json:"target_sha256"`
	Keychain string         `json:"keychain"`
}

func runHandoffHelper(args []string, in io.Reader, out io.Writer) bool {
	if len(args) != 1 || (args[0] != resumeArg && args[0] != recoverArg) {
		return false
	}
	var req resumeRequest
	raw, readErr := io.ReadAll(io.LimitReader(in, 16385))
	if readErr != nil || len(raw) > 16384 {
		_, _ = out.Write([]byte{1})
		return true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
		_, _ = out.Write([]byte{1})
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	v := New()
	var e error
	if req.Keychain != "" {
		v, e = openIsolated(req.Keychain)
		if e == nil {
			defer v.closeIsolated()
		}
	}
	if e == nil {
		if args[0] == resumeArg {
			e = v.PrepareUpgrade(ctx, req.Source, req.Target)
		} else {
			report, re := install.Status(ctx, req.Source.Dir)
			self, se := os.Executable()
			if req.Target != "" || (re != nil && !errors.Is(re, install.ErrUnavailable)) || report.Record != req.Source || se != nil || self != req.Source.Executable {
				e = install.ErrUnverified
			} else {
				e = v.RecoverUpgrade(ctx, req.Source)
			}
		}
	}
	code := byte(0)
	if e != nil {
		code = 1
	}
	_, _ = out.Write([]byte{code})
	return true
}

// ResumeUpgrade uses the retained receipt image after an interrupted transfer.
// It never depends on cached plaintext or launches a shim-supplied executable.
func (v *Vault) ResumeUpgrade(ctx context.Context, source install.Record, target string) error {
	if ctx == nil || !digestValid(target) || source.Executable != handoffTarget(source, source.SHA256) {
		return ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if v == nil || v.closed {
		return ErrUnavailable
	}
	report, e := install.Status(ctx, source.Dir)
	if (e != nil && !errors.Is(e, install.ErrUnavailable)) || report.Record != source {
		return install.ErrUnverified
	}
	if e = checkTargetCapabilities(ctx, handoffTarget(source, target), target); e != nil {
		return e
	}
	if e = v.bindCustody(ctx, source.DataDir, false); e != nil {
		return e
	}
	lock, e := ipc.Lock(filepath.Join(source.DataDir, "custody-upgrade.lock"))
	if e != nil {
		return e
	}
	m, e := readHandoff(source.DataDir)
	if e == nil && (m.Target != target || checkTargetCapabilities(ctx, handoffTarget(source, m.Target), m.Target) != nil) {
		e = v.abortUnpublished(ctx, source, m)
	} else if os.IsNotExist(e) {
		e = nil
	}
	lock.Close()
	if e != nil {
		return e
	}
	return v.lifecycleImage(ctx, source, target, resumeArg)
}

// Keep RecoverUpgrade's startup self-path check. Teardown invoked by another
// build dispatches recovery into the verified current image instead.
func (v *Vault) lifecycleImage(ctx context.Context, source install.Record, target, arg string) error {
	if ctx == nil {
		return ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if v == nil || v.closed || source.Executable != handoffTarget(source, source.SHA256) {
		return ErrInvalid
	}
	report, e := install.Status(ctx, source.Dir)
	if (e != nil && !errors.Is(e, install.ErrUnavailable)) || report.Record != source {
		return install.ErrUnverified
	}
	f, e := pinHandoffImage(source.Executable, source.SHA256)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = v.bindCustody(ctx, source.DataDir, false); e != nil {
		return e
	}
	b, e := json.Marshal(resumeRequest{source, target, v.keychainPath})
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, source.Executable, arg)
	cmd.WaitDelay = time.Second
	cmd.Stdin = bytes.NewReader(b)
	out := &custodyOutput{}
	defer clear(out.b[:])
	cmd.Stdout = out
	if cmd.Run() != nil || out.n != 1 || out.b[0] != 0 {
		return ErrUnavailable
	}
	return nil
}

func trustedCustodyStat(st os.FileInfo, private, directory bool) bool {
	raw, ok := st.Sys().(*syscall.Stat_t)
	if !ok || (raw.Uid != uint32(os.Geteuid()) && (private || raw.Uid != 0)) || st.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || st.Mode().Perm()&0022 != 0 {
		return false
	}
	if private && st.Mode().Perm() != 0600 {
		return false
	}
	if directory {
		return st.IsDir()
	}
	return st.Mode().IsRegular() && raw.Nlink == 1
}

// DeleteForInstall is used only by explicit settled uninstall under db.lock.
// Pending staging custody is removed before deleting the current item's key.
// The recorded executable performs its own deletion even when the uninstall
// command itself belongs to a different build identity.
func (v *Vault) DeleteForInstall(ctx context.Context, current install.Record, handle string) error {
	if ctx == nil {
		return ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if v == nil || v.closed || valid(ctx, handle) != nil {
		return ErrInvalid
	}
	report, e := install.Status(ctx, current.Dir)
	if (e != nil && !errors.Is(e, install.ErrUnavailable)) || report.Record != current {
		return install.ErrUnverified
	}
	if h, e := installedHandle(current.DataDir); e != nil || h != handle {
		return ErrUnavailable
	}
	if e = v.bindCustody(ctx, current.DataDir, false); e != nil {
		return e
	}
	m, e := readHandoff(current.DataDir)
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if e == nil {
		if current != m.Source {
			if e = v.lifecycleImage(ctx, current, "", recoverArg); e != nil {
				return e
			}
		} else {
			lock, e := ipc.Lock(filepath.Join(current.DataDir, "custody-upgrade.lock"))
			if e != nil {
				return e
			}
			defer lock.Close()
			// Recheck after admission to avoid a changed transfer target.
			again, e := readHandoff(current.DataDir)
			if e != nil || again != m || m.Handle != handle || m.Keychain != v.keychainPath {
				return ErrUnavailable
			}
			if checkTargetCapabilities(ctx, handoffTarget(current, m.Target), m.Target) != nil {
				if e = v.abortUnpublished(ctx, current, m); e != nil {
					return e
				}
				_, e = v.imageOperation(ctx, current.Executable, current.SHA256, 3, handle, nil)
				return e
			}
			oldService, e := v.imageOperation(ctx, current.Executable, current.SHA256, 5, handle, nil)
			if e != nil {
				return e
			}
			target := handoffTarget(current, m.Target)
			newService, e := v.imageOperation(ctx, target, m.Target, 5, handle, nil)
			if e != nil {
				return e
			}
			if m.Legacy {
				oldService = []byte(service)
			}
			if string(oldService) != string(newService) {
				if _, e = v.imageOperation(ctx, target, m.Target, 6, handle, nil); e != nil {
					return e
				}
			}
			if e = os.Remove(filepath.Join(current.DataDir, handoffFile)); e != nil {
				return e
			}
			if e = syncHandoffDir(current.DataDir); e != nil {
				return e
			}
		}
	}
	_, e = v.imageOperation(ctx, current.Executable, current.SHA256, 3, handle, nil)
	return e
}

// Resolve the OS default once before transfer and pass that explicit keychain
// to both images. A changed default at recovery refuses before retirement.
func (v *Vault) selectKeychain(ctx context.Context) error {
	if v.keychainPath != "" {
		return nil
	}
	b, e := v.operation(ctx, "default-keychain", "00000000000000000000000000000000", nil)
	if e != nil {
		return e
	}
	path, e := filepath.EvalSymlinks(string(b))
	if e != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 {
		return ErrUnavailable
	}
	v.keychainPath = path
	return nil
}
