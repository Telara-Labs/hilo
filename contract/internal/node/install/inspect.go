package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// ReceiptReport is a read-only verification of the installation receipt.
// It names the receipt state and the service manager state separately.
type ReceiptReport struct {
	Dir      string `json:"dir"`
	State    string `json:"state"` // verified | stopped | unverified | unsafe | absent
	Version  string `json:"version,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	DataDir  string `json:"data_dir,omitempty"`
	RunDir   string `json:"run_dir,omitempty"`
	Manager  string `json:"manager,omitempty"` // registered | autostart_stopped | autostart_unavailable | unverified
	Error    string `json:"error,omitempty"`
	Verified bool   `json:"executable_digest_verified"`
}

// Inspect verifies the receipt, intent and executable digest, then asks the
// service manager for status. It never registers, starts, stops or rewrites.
func Inspect(ctx context.Context, dir string) ReceiptReport {
	out := ReceiptReport{Dir: dir}
	if !absolute(dir) {
		out.State, out.Error = "unsafe", ErrUnsafe.Error()
		return out
	}
	if _, err := os.Lstat(filepath.Join(dir, "install.json")); os.IsNotExist(err) {
		out.State = "absent"
		return out
	}
	r, err := readReceipt(dir)
	if err != nil {
		out.State, out.Error = classify(err), code(err)
		return out
	}
	out.Version, out.SHA256, out.DataDir, out.RunDir = r.Version, r.SHA256, r.DataDir, r.RunDir
	v, err := verify(r.Executable, r.SHA256)
	if err != nil {
		out.State, out.Error = classify(err), code(err)
		return out
	}
	v.Close()
	out.Verified = true
	out.State = "verified"
	if err = checkIntent(dir, r); err != nil {
		if errors.Is(err, ErrStopped) {
			out.State = "stopped"
		} else {
			out.State, out.Error = classify(err), code(err)
			return out
		}
	}
	status, err := Status(ctx, dir)
	switch {
	case status.State != "":
		out.Manager = status.State
	case err != nil:
		out.Manager = code(err)
	}
	return out
}

func classify(err error) string {
	if errors.Is(err, ErrUnsafe) {
		return "unsafe"
	}
	return "unverified"
}

func code(err error) string {
	for _, e := range []error{ErrUnsafe, ErrUnverified, ErrUnavailable, ErrStopped, ErrUpgrade} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return ErrUnverified.Error()
}
