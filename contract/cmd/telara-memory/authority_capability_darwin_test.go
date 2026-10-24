//go:build darwin && cgo

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/ipc"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/vault"
)

// A new lifecycle caller must preflight even if the installed daemon predates
// capability negotiation. These exchanges require no native Keychain access.
func TestCustodyRequestPreflightsOlderDaemonTarget(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	p, e := ipc.Resolve(filepath.Join(root, "data"), filepath.Join(root, "run"))
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Prepare(); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "install")
	home := filepath.Join(root, "home")
	if e = os.Mkdir(home, 0700); e != nil {
		t.Fatal(e)
	}
	publish := func(path string) (string, string) {
		t.Helper()
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(b)
		digest := hex.EncodeToString(sum[:])
		dest := filepath.Join(dir, "bin", digest, "telara-memory")
		if e = os.MkdirAll(filepath.Dir(dest), 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(dest, b, 0700); e != nil {
			t.Fatal(e)
		}
		return dest, digest
	}
	exe, digest := publish(binary)
	r := install.Record{Schema: 1, Dir: dir, Home: home, Label: "dev.memory.capability.fixture", Platform: "darwin", UserID: strconv.Itoa(os.Geteuid()), Executable: exe, SHA256: digest, Version: "fixture", DataDir: p.Data, RunDir: p.Run}
	for name, value := range map[string]any{"install.json": r, "intent.json": map[string]string{"mode": "stop", "sha256": digest, "version": r.Version, "session": ""}} {
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e = writePending(p.Data, pendingProfile{Version: 1, Handle: "0123456789abcdef0123456789abcdef", Phase: "admitted", Creator: &r}); e != nil {
		t.Fatal(e)
	}
	for _, variant := range []string{"static", "older"} {
		path := filepath.Join(root, variant)
		args := []string{"build", "-p", "2", "-o", path, "."}
		if variant == "older" {
			source := filepath.Join(root, "older.go")
			// An older authenticated image understands only helper protocol 0.
			raw := `package main
import("io";"os")
func main(){io.Copy(io.Discard,io.LimitReader(os.Stdin,7));os.Stdout.Write([]byte{'T','M','V','C',0,0,7})}
`
			if e = os.WriteFile(source, []byte(raw), 0600); e != nil {
				t.Fatal(e)
			}
			args[len(args)-1] = source
		}
		cmd := exec.Command("go", args...)
		cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("%s build %v %s", variant, e, b)
		}
		_, target := publish(path)
		before, e := readAuthorityRecord(p.Data)
		if e != nil {
			t.Fatal(e)
		}
		if e = requestCustodyHandoff(context.Background(), p, target); !errors.Is(e, vault.ErrUnavailable) {
			t.Fatalf("%s target reached daemon request instead of capability refusal: %v", variant, e)
		}
		after, e := readAuthorityRecord(p.Data)
		if e != nil || string(before) != string(after) {
			t.Fatal("refusal mutated authority", e)
		}
		if _, e = os.Lstat(filepath.Join(p.Data, "custody-upgrade.json")); !os.IsNotExist(e) {
			t.Fatal("refusal published transfer marker", e)
		}
	}
}
