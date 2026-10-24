//go:build linux || (darwin && cgo)

package peer

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/install"
)

func TestPeerImageHelper(t *testing.T) {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "peer-image-helper" {
		return
	}
	fmt.Fprintln(os.Stdout, "ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// This unit fixture uses the real receipt verifier and kernel process image. It
// does not register a service or claim an installer acceptance test.
func TestVerifiedImageRejectsCopiedAndNonInstalledProcesses(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(b)
	hash := hex.EncodeToString(digest[:])
	dir := filepath.Join(root, "install")
	path := filepath.Join(dir, "bin", hash, "telara-memory")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0700); err != nil {
		t.Fatal(err)
	}
	r := install.Record{Schema: 1, Dir: dir, Home: root, Label: "dev.memory.peer.test", Platform: runtime.GOOS, UserID: strconv.Itoa(os.Geteuid()), Executable: path, SHA256: hash, Version: "test", DataDir: filepath.Join(root, "data"), RunDir: filepath.Join(root, "run")}
	receipt, _ := json.Marshal(r)
	if err := os.WriteFile(filepath.Join(dir, "install.json"), receipt, 0600); err != nil {
		t.Fatal(err)
	}
	intent, _ := json.Marshal(map[string]string{"mode": "start", "sha256": hash, "version": "test", "session": ""})
	if err := os.WriteFile(filepath.Join(dir, "intent.json"), intent, 0600); err != nil {
		t.Fatal(err)
	}
	spawn := func(path string) int {
		cmd := exec.Command(path, "-test.run=^TestPeerImageHelper$", "--", "peer-image-helper")
		in, e := cmd.StdinPipe()
		if e != nil {
			t.Fatal(e)
		}
		out, e := cmd.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		cmd.Stderr = os.Stderr
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			in.Close()
			if e := cmd.Wait(); e != nil {
				t.Error(e)
			}
		})
		if line, e := bufio.NewReader(out).ReadString('\n'); e != nil || line != "ready\n" {
			t.Fatal(line, e)
		}
		return cmd.Process.Pid
	}
	a := Authority{InstallDir: dir}
	pid := spawn(path)
	if err := a.verify(pid); err != nil {
		t.Fatal("installed image refused", err)
	}
	if err := a.verify(os.Getpid()); err == nil {
		t.Fatal("noninstalled executable accepted")
	}
	copy := filepath.Join(root, "copy")
	if err := os.WriteFile(copy, b, 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.verify(spawn(copy)); err == nil {
		t.Fatal("byte-identical copied executable accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "intent.json"), []byte(`{"mode":"stop","sha256":"`+hash+`","version":"test","session":""}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.verify(pid); err == nil {
		t.Fatal("stopped install accepted")
	}
}
