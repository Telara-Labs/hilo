package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var updateGolden = flag.Bool("update-install-golden", false, "Update manager definition golden files")
var liveAgent = flag.Bool("live-launchagent", false, "Install and remove a temporary real LaunchAgent")

func testRoot(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if runtime.GOOS != "windows" {
		if e = os.Chmod(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if runtime.GOOS == "windows" {
		p = filepath.Join(p, "private")
	}
	if e = ensureDir(p, true); e != nil {
		t.Fatal(e)
	}
	return p
}
func imageFixture(t *testing.T, dir string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, "source")
	b := []byte("synthetic executable image\n")
	if e := writeAtomic(path, b, 0700); e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(b)
	return path, hex.EncodeToString(h[:])
}
func receiptFixture(t *testing.T) (Record, string) {
	t.Helper()
	dir := testRoot(t)
	src, digest := imageFixture(t, dir)
	r := Record{1, dir, dir, "dev.memory.fixture", runtime.GOOS, userID(), imagePath(dir, digest), digest, "1.2.3", filepath.Join(dir, "data"), filepath.Join(dir, "run")}
	if e := copyImage(src, r); e != nil {
		t.Fatal(e)
	}
	if e := writeJSON(filepath.Join(dir, "install.json"), r); e != nil {
		t.Fatal(e)
	}
	if e := writeIntent(dir, r, "start", ""); e != nil {
		t.Fatal(e)
	}
	return r, src
}

func TestDefinitionsGolden(t *testing.T) {
	r := Record{Label: "dev.memory.test", Dir: "/Users/owner/Memory & stuff/$cash%unit", Executable: "/Users/owner/Memory & stuff/bin/node", UserID: "S-1-5-21-123"}
	for _, platform := range []string{"darwin", "linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			b, e := Definition(platform, r)
			if e != nil {
				t.Fatal(e)
			}
			p := filepath.Join("testdata", platform+".golden")
			if *updateGolden {
				if e = os.WriteFile(p, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			want, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(b, want) {
				t.Fatalf("definition differs\n%s", b)
			}
			if platform != "linux" {
				d := xml.NewDecoder(bytes.NewReader(b))
				for {
					_, e = d.Token()
					if e == io.EOF {
						break
					}
					if e != nil {
						t.Fatal(e)
					}
				}
			}
			if bytes.Contains(b, []byte("lingering")) || bytes.Contains(b, []byte("HighestAvailable")) {
				t.Fatal("elevation/linger")
			}
		})
	}
}
func TestDefinitionRejectsInjection(t *testing.T) {
	for _, r := range []Record{{Label: "../escape", Executable: "/bin/x", Dir: "/safe"}, {Label: "valid", Executable: "/bin/x\nEnvironment=evil", Dir: "/safe"}, {Label: "valid", Executable: "/bin/x", Dir: "/safe\rbad"}} {
		for _, platform := range []string{"darwin", "linux", "windows"} {
			if _, e := Definition(platform, r); e == nil {
				t.Fatal("accepted injection")
			}
		}
	}
	if _, e := Definition("other", Record{Label: "valid", Executable: "/bin/x", Dir: "/safe"}); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if got := windowsArgs([]string{`a\`, `b"c`, ""}); got != `"a\\" "b\"c" ""` {
		t.Fatal(got)
	}
}

func TestVerifiedExecutable(t *testing.T) {
	r, _ := receiptFixture(t)
	v, e := VerifiedExecutable(r.Dir)
	if e != nil {
		t.Fatal(e)
	}
	if v.Path != r.Executable {
		t.Fatal(v.Path)
	}
	if e = v.Close(); e != nil {
		t.Fatal(e)
	}
	if e = v.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = v.Start(context.Background()); !errors.Is(e, ErrUnverified) {
		t.Fatal(e)
	}
	if _, e = verify(r.Executable, strings.Repeat("0", 64)); !errors.Is(e, ErrUnverified) {
		t.Fatal(e)
	}
	for _, d := range []string{"", "abc", strings.Repeat("A", 64)} {
		if _, e = verify(r.Executable, d); !errors.Is(e, ErrUnverified) {
			t.Fatal(e)
		}
	}
	if _, e = VerifyRunning(r.Dir); !errors.Is(e, ErrUnverified) {
		t.Fatalf("test process adopted install: %v", e)
	}
}

func TestManagedEntryHelper(t *testing.T) {
	if flag.NArg() == 0 {
		return
	}
	dir := flag.Arg(0)
	if _, e := VerifyRunning(dir); e != nil {
		t.Fatal(e)
	}
	if flag.NArg() > 1 && flag.Arg(1) == "wait" {
		time.Sleep(100 * time.Millisecond)
	}
}

func TestRealPinnedLaunchAndRunningIdentity(t *testing.T) {
	dir := testRoot(t)
	source, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	source, e = filepath.EvalSymlinks(source)
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(source)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		t.Fatal(e)
	}
	f.Close()
	digest := hex.EncodeToString(h.Sum(nil))
	r := Record{1, dir, dir, "dev.memory.running", runtime.GOOS, userID(), imagePath(dir, digest), digest, "fixture", filepath.Join(dir, "data"), filepath.Join(dir, "run")}
	if e = copyImage(source, r); e != nil {
		t.Fatal(e)
	}
	if e = writeJSON(filepath.Join(dir, "install.json"), r); e != nil {
		t.Fatal(e)
	}
	if e = writeIntent(dir, r, "start", ""); e != nil {
		t.Fatal(e)
	}
	v, e := VerifiedExecutable(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd, e := v.Start(ctx, "-test.run=^TestManagedEntryHelper$", "--", dir, "wait")
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	if e = cmd.Wait(); e != nil {
		t.Fatalf("actual child rejected installed identity: %v", e)
	}
	if _, e = v.Start(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestStopMarkerSessionBoundary(t *testing.T) {
	r, _ := receiptFixture(t)
	for _, v := range []struct {
		session string
		err     error
		stopped bool
	}{{"same", nil, true}, {"next", nil, false}, {"", ErrUnavailable, true}} {
		i := intent{"stop", r.SHA256, r.Version, "same"}
		e := intentState(i, r, func() (string, error) { return v.session, v.err })
		if errors.Is(e, ErrStopped) != v.stopped {
			t.Fatal(v, e)
		}
	}
	if d, e := DefaultDir(); e != nil || !filepath.IsAbs(d) {
		t.Fatal(d, e)
	}
}
func TestIntentBinding(t *testing.T) {
	r, _ := receiptFixture(t)
	for _, i := range []intent{{"unknown", r.SHA256, r.Version, ""}, {"start", strings.Repeat("f", 64), r.Version, ""}, {"upgrade", r.SHA256, "older", ""}} {
		if e := writeJSON(filepath.Join(r.Dir, "intent.json"), i); e != nil {
			t.Fatal(e)
		}
		if _, e := VerifiedExecutable(r.Dir); !errors.Is(e, ErrUnverified) {
			t.Fatal(e)
		}
	}
	if e := writeIntent(r.Dir, r, "stop", ""); e != nil {
		t.Fatal(e)
	}
	if _, e := VerifiedExecutable(r.Dir); !errors.Is(e, ErrStopped) {
		t.Fatal(e)
	}
	if e := Autostart(context.Background(), r.Dir); !errors.Is(e, ErrStopped) {
		t.Fatal(e)
	}
	if s, e := Status(context.Background(), r.Dir); e != nil || s.State != "autostart_stopped" {
		t.Fatal(s, e)
	}
	if e := writeIntent(r.Dir, r, "upgrade", ""); e != nil {
		t.Fatal(e)
	}
	v, e := VerifiedExecutable(r.Dir)
	if e != nil {
		t.Fatal(e)
	}
	v.Close()
}
func TestReceiptStrict(t *testing.T) {
	r, _ := receiptFixture(t)
	p := filepath.Join(r.Dir, "install.json")
	good, _ := json.Marshal(r)
	for _, b := range [][]byte{append(append([]byte{}, good...), []byte("{}")...), []byte(`{"schema":1,"unexpected":true}`), bytes.Repeat([]byte("x"), 16385)} {
		if e := writeAtomic(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := readReceipt(r.Dir); e == nil {
			t.Fatal("accepted invalid receipt")
		}
	}
	for _, change := range []func(*Record){func(r *Record) { r.Executable = "/bin/true" }, func(r *Record) { r.UserID = "wrong" }, func(r *Record) { r.Schema = 2 }, func(r *Record) { r.Platform = "other" }, func(r *Record) { r.Version = "" }} {
		bad := r
		change(&bad)
		if e := writeJSON(p, bad); e != nil {
			t.Fatal(e)
		}
		if _, e := readReceipt(r.Dir); e == nil {
			t.Fatal("accepted unbound receipt")
		}
	}
}
func TestInstallRefusesExistingAndInvalid(t *testing.T) {
	r, src := receiptFixture(t)
	c := Config{Dir: r.Dir, Home: r.Home, Label: r.Label, Executable: src, SHA256: r.SHA256, Version: r.Version, DataDir: r.DataDir, RunDir: r.RunDir}
	if _, e := Install(context.Background(), c); !errors.Is(e, ErrUpgrade) {
		t.Fatal(e)
	}
	c.Dir = "relative"
	if _, e := Install(context.Background(), c); e == nil {
		t.Fatal("relative dir")
	}
	if e := Stop(context.Background(), r.Dir, nil); !errors.Is(e, ErrUpgrade) {
		t.Fatal(e)
	}
	if _, e := Upgrade(context.Background(), r.Dir, src, "bad", "v2", nil); e == nil {
		t.Fatal("unverified upgrade")
	}
}
func TestDefinitionTamper(t *testing.T) {
	r, _ := receiptFixture(t)
	p := definitionPath(r)
	if e := ensureDir(filepath.Dir(p), false); e != nil {
		t.Fatal(e)
	}
	b, e := Definition(r.Platform, r)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeAtomic(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	if e = verifyDefinition(r); e != nil {
		t.Fatal(e)
	}
	if e = writeAtomic(p, []byte("substituted"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = Start(context.Background(), r.Dir); !errors.Is(e, ErrUnverified) {
		t.Fatal(e)
	}
	if e = Uninstall(context.Background(), r.Dir, func(context.Context) error { return nil }); !errors.Is(e, ErrUnverified) {
		t.Fatal(e)
	}
}

func TestLiveLaunchAgent(t *testing.T) {
	if !*liveAgent {
		t.Skip("explicit -live-launchagent required")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	dir := testRoot(t)
	source := "/usr/bin/true"
	f, e := os.Open(source)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.New()
	io.Copy(h, f)
	f.Close()
	nonce, _ := randomName()
	label := "dev.memory.test." + strings.TrimPrefix(nonce, ".install-")
	c := Config{Dir: filepath.Join(dir, "install"), Home: dir, Label: label, Executable: source, SHA256: hex.EncodeToString(h.Sum(nil)), Version: "fixture", DataDir: filepath.Join(dir, "data"), RunDir: filepath.Join(dir, "run")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, e := Install(ctx, c)
	// Cleanup is unconditional, including partial registration failure.
	r := report.Record
	if r.Label == "" {
		r = Record{Dir: c.Dir, Home: c.Home, Label: c.Label, UserID: userID(), Platform: "darwin"}
	}
	defer func() {
		_, _ = nativeCommand(context.Background(), "darwin", "bootout", service(r))
		cmd := exec.Command("/bin/launchctl", "print", service(r))
		b, e := cmd.CombinedOutput()
		if e == nil {
			t.Error("temporary service still registered")
		} else if !bytes.Contains(b, []byte("Could not find service")) {
			t.Errorf("cleanup absence UNVERIFIED: %v %s", e, b)
		} else {
			t.Log("temporary service absence confirmed by launchctl service-not-found response")
		}
	}()
	if e != nil {
		diagnostic := exec.CommandContext(ctx, "/bin/launchctl", "bootstrap", domain(r), definitionPath(r))
		b, de := diagnostic.CombinedOutput()
		t.Logf("bootstrap diagnostic %v %s", de, b)
		t.Fatalf("real LaunchAgent install failed: %v", e)
	}
	t.Logf("temporary label %s, installed image %s", r.Label, r.Executable)
	deadline := time.Now().Add(10 * time.Second)
	ran := false
	for time.Now().Before(deadline) {
		b, e := nativeCommand(ctx, "darwin", "print", service(r))
		if e == nil && bytes.Contains(b, []byte("last exit code = 0")) {
			ran = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ran {
		t.Fatal("manager did not prove fixture executable exited successfully")
	}
	if e = Stop(ctx, c.Dir, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e = Uninstall(ctx, c.Dir, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Lstat(definitionPath(r)); !os.IsNotExist(e) {
		t.Fatalf("definition not removed: %v", e)
	}
	if _, e = nativeCommand(ctx, "darwin", "print", service(r)); e == nil {
		t.Fatal("registration not removed")
	}
}
