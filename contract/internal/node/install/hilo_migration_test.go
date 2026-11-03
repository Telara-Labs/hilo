package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
)

func hiloLegacyInstall(t *testing.T, base string) Record {
	t.Helper()
	dir := filepath.Join(base, "telara-memory-install")
	if err := ensureDir(dir, true); err != nil {
		t.Fatal(err)
	}
	source, digest := imageFixture(t, base)
	r := Record{Schema: 1, Dir: dir, Home: base, Label: "dev.telara.memory", Platform: runtime.GOOS, UserID: userID(), Executable: namedImagePath(dir, digest, "telara-memory"), SHA256: digest, Version: "1.2.3", DataDir: filepath.Join(base, "telara-memory"), RunDir: filepath.Join(base, "runtime-v1")}
	for _, path := range []string{r.DataDir, r.RunDir} {
		if err := ensureDir(path, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := copyImage(source, r); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "install.json"), r); err != nil {
		t.Fatal(err)
	}
	if err := writeIntent(dir, r, "start", ""); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestHiloFreshInstallAndClosedExecutableNames(t *testing.T) {
	base := testRoot(t)
	want := filepath.Join(base, "hilo-install")
	if got, err := defaultDirAt(base); err != nil || got != want {
		t.Fatal("fresh discovery did not choose Hilo", got, err)
	}
	if _, err := os.Lstat(want); !os.IsNotExist(err) {
		t.Fatal("discovery installed or created state", err)
	}
	_, digest := imageFixture(t, base)
	r, err := PlannedRecord(Config{Dir: want, Home: base, SHA256: digest, Version: "1.2.3", DataDir: filepath.Join(base, "hilo"), RunDir: filepath.Join(base, "run")})
	if err != nil || r.Label != "dev.telara.hilo" || r.Executable != namedImagePath(want, digest, "hilo") {
		t.Fatal("fresh installation identity mismatch", err)
	}
	for _, name := range []string{"hilo", "telara-memory", "hilo-other", "telara-memory-other"} {
		candidate := r
		candidate.Executable = namedImagePath(r.Dir, digest, name)
		if ValidExecutablePath(candidate) != (name == "hilo" || name == "telara-memory") {
			t.Fatalf("unexpected executable admission for %s", name)
		}
	}
}

func TestHiloLegacyDiscoveryPreservesActiveWriterAndCustody(t *testing.T) {
	base := testRoot(t)
	r := hiloLegacyInstall(t, base)
	sentinel := []byte("synthetic owned custody generation and outbox journal\n")
	journal := filepath.Join(r.DataDir, "custody-generation.fixture")
	if err := os.WriteFile(journal, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	writer, err := ipc.Lock(filepath.Join(r.DataDir, "db.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	paths := []string{filepath.Join(r.Dir, "install.json"), filepath.Join(r.Dir, "intent.json"), r.Executable, journal}
	before := map[string][]byte{}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = b
	}
	got, err := defaultDirAt(base)
	if err != nil || got != r.Dir {
		t.Fatal("valid legacy not discovered", err)
	}
	read, err := readReceipt(got)
	if err != nil || read != r {
		t.Fatal("legacy label/profile/runtime/image identity changed", err)
	}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(b, before[path]) {
			t.Fatal("discovery changed retained bytes", err)
		}
	}
	second, err := ipc.Lock(filepath.Join(r.DataDir, "db.lock"))
	if second != nil {
		second.Close()
	}
	if !errors.Is(err, ipc.ErrBusy) {
		t.Fatal("discovery released active writer", err)
	}
	if _, err := os.Lstat(filepath.Join(base, "hilo-install")); !os.IsNotExist(err) {
		t.Fatal("discovery created a parallel install", err)
	}
}

func TestHiloStoppedLegacyDiscoveryPreservesStopIntent(t *testing.T) {
	base := testRoot(t)
	r := hiloLegacyInstall(t, base)
	if err := writeIntent(r.Dir, r, "stop", ""); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(r.Dir, "intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := defaultDirAt(base); err != nil || got != r.Dir {
		t.Fatal("stopped legacy discovery refused", err)
	}
	if _, err := VerifiedExecutable(r.Dir); !errors.Is(err, ErrStopped) {
		t.Fatal("discovery granted stopped execution", err)
	}
	if err := Autostart(context.Background(), r.Dir); !errors.Is(err, ErrStopped) {
		t.Fatal("stopped installation autostart allowed", err)
	}
	if after, err := os.ReadFile(filepath.Join(r.Dir, "intent.json")); err != nil || !bytes.Equal(after, before) {
		t.Fatal("stopped discovery rewrote intent", err)
	}
}

func TestHiloLegacyDiscoveryRefusesUntrustedAndAmbiguous(t *testing.T) {
	for _, kind := range []string{"digest", "unknown-receipt-field", "trailing-receipt", "ambiguous", "symlink", "loose-mode"} {
		if runtime.GOOS == "windows" && (kind == "symlink" || kind == "loose-mode") {
			continue
		} // Native ACL refusal remains separately exercised on Windows.
		t.Run(kind, func(t *testing.T) {
			base := testRoot(t)
			r := hiloLegacyInstall(t, base)
			receipt := filepath.Join(r.Dir, "install.json")
			switch kind {
			case "digest":
				if err := writeAtomic(r.Executable, []byte("forged image\n"), 0700); err != nil {
					t.Fatal(err)
				}
			case "unknown-receipt-field":
				b, err := os.ReadFile(receipt)
				if err != nil {
					t.Fatal(err)
				}
				b = []byte(strings.Replace(string(b), "{", "{\"unknown\":true,", 1))
				if err := writeAtomic(receipt, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "trailing-receipt":
				b, err := os.ReadFile(receipt)
				if err != nil {
					t.Fatal(err)
				}
				if err := writeAtomic(receipt, append(b, []byte("{}\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			case "ambiguous":
				if err := ensureDir(filepath.Join(base, "hilo-install"), true); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(base, "moved-legacy")
				if err := os.Rename(r.Dir, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, r.Dir); err != nil {
					t.Fatal(err)
				}
			case "loose-mode":
				if err := os.Chmod(r.Dir, 0777); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := defaultDirAt(base); err == nil || got != "" {
				t.Fatal("untrusted or ambiguous legacy accepted")
			}
			if after, err := os.ReadFile(receipt); err != nil || !bytes.Equal(after, before) {
				t.Fatal("refusal rewrote source receipt", err)
			}
			if kind != "ambiguous" {
				if _, err := os.Lstat(filepath.Join(base, "hilo-install")); !os.IsNotExist(err) {
					t.Fatal("refusal created parallel install", err)
				}
			}
		})
	}
}
