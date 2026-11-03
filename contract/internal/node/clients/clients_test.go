package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"github.com/Telara-Labs/hilo/contract/internal/node/shim"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "shim" {
		// Use the real shim and an intentionally absent daemon. This exercises
		// native clients' failed MCP startup alongside advisory hooks, without
		// mocking a Telara service or accidentally running this test suite again.
		f := flag.NewFlagSet("shim", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		state := f.String("data-dir", "", "")
		if f.Parse(os.Args[2:]) == nil {
			p, e := ipc.Resolve(*state, "")
			if e == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				_ = shim.Run(ctx, os.Stdin, os.Stdout, shim.Config{Paths: p, Start: func() error { return errors.New("daemon_unavailable") }})
				cancel()
			}
		}
		os.Exit(1)
	}
	// Real subprocess helper for vendor hook dispatch and Pi's child process.
	// No environment-variable test mode and no shell-script tests.
	if len(os.Args) > 1 && os.Args[1] == "hook" {
		f := flag.NewFlagSet("hook", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		c := f.String("client", "", "")
		h := f.String("home", "", "")
		s := f.String("state-dir", "", "")
		root := f.String("config-root", "", "")
		if f.Parse(os.Args[2:]) == nil {
			_ = RunHook(context.Background(), Options{Client: Client(*c), Home: *h, StateDir: *s, ConfigRoot: *root}, os.Stdin)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func options(t *testing.T, c Client) Options {
	t.Helper()
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		home = filepath.Join(home, "private")
		if err := ipc.ValidateDir(home, true); err != nil {
			t.Fatal(err)
		}
	}
	// testing.TempDir leaves use 0777 masked by the invoking process umask.
	// This fixture represents an owner-private home independently of that mask.
	if runtime.GOOS != "windows" {
		if e := os.Chmod(home, 0700); e != nil {
			t.Fatal(e)
		}
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	return Options{Client: c, Home: home, Executable: exe, StateDir: filepath.Join(home, "state")}
}
func put(t *testing.T, path string, b []byte) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestLocationsAndGoldenPreviewsEveryClientOS(t *testing.T) {
	paths, e := filepath.Glob("testdata/*.json")
	if e != nil || len(paths) != 12 {
		t.Fatalf("fixtures %v %v", paths, e)
	}
	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			var f struct {
				Client                                                                 Client
				GOOS, Home, Executable, StateDir                                       string
				Location                                                               Location
				MCPBefore, MCPAfter, HooksBefore, HooksAfter, MCPSnippet, HooksSnippet string
			}
			if e := json.Unmarshal(mustRead(t, p), &f); e != nil {
				t.Fatal(e)
			}
			o := Options{Client: f.Client, GOOS: f.GOOS, Home: f.Home, Executable: f.Executable, StateDir: f.StateDir, Print: true}
			o, l, e := resolve(o)
			if e != nil {
				t.Fatal(e)
			}
			if l != f.Location {
				t.Fatalf("location got %#v want %#v", l, f.Location)
			}
			changes := plan(o, l)
			if f.Client == Pi {
				if len(changes) != 1 || changes[0].Action != "create_owned" {
					t.Fatal(changes)
				}
				if !strings.Contains(changes[0].Snippet, "registerMcpServer(\"hilo\"") {
					t.Fatal("no native registration")
				}
				if strings.Contains(changes[0].Snippet, "process.env") {
					t.Fatal("env mutation")
				}
			} else {
				if changes[0].Snippet != f.MCPSnippet || changes[1].Snippet != f.HooksSnippet {
					t.Fatalf("golden preview changed for %s", p)
				}
			}
			if f.MCPBefore != f.MCPAfter || f.HooksBefore != f.HooksAfter {
				t.Fatal("shared config should be byte-preserved")
			}
		})
	}
}

func TestSharedTreesPreservedIncludingConcurrentWriter(t *testing.T) {
	for _, c := range []Client{Claude, Codex, Cursor, Pi} {
		t.Run(string(c), func(t *testing.T) {
			o := options(t, c)
			l, _ := Locations(o)
			before := []byte("{\r\n  \"unrelated\": true, \"mcpServers\": {\"existing\": {\"command\": \"other\", \"env\": {\"TOKEN\": \"fixture-secret\"}}}\r\n}\r\n")
			if c == Codex {
				before = []byte("# retain this comment\r\nmodel = 'fixture'\r\n[mcp_servers.existing]\r\ncommand = 'other'\r\n")
			}
			put(t, l.MCP, before)
			if c != Pi {
				put(t, l.Hooks, []byte("{\"unrelated\":true,\"hooks\":{}}\n"))
			}
			originalHooks := []byte(nil)
			if c != Pi {
				originalHooks = mustRead(t, l.Hooks)
			}
			o.Print = true
			r, e := Install(context.Background(), o)
			if e != nil {
				t.Fatal(e)
			}
			for _, change := range r.Changes {
				if strings.Contains(change.Snippet, "fixture-secret") {
					t.Fatal("unrelated credential in preview")
				}
			}
			if c == Pi {
				if _, e = os.Stat(l.Extension); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("preview mutated")
				}
			}
			// Simulate an external editor after the install preview/final comparison.
			later := append(append([]byte{}, before...), []byte(" \n")...)
			put(t, l.MCP, later)
			o.Print = false
			if _, e = Install(context.Background(), o); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(mustRead(t, l.MCP), later) {
				t.Fatal("lost external edit")
			}
			if _, e = Uninstall(context.Background(), o); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(mustRead(t, l.MCP), later) {
				t.Fatal("uninstall lost external edit")
			}
			if c != Pi && !bytes.Equal(mustRead(t, l.Hooks), originalHooks) {
				t.Fatal("unrelated hooks changed")
			}
		})
	}
}

func TestMalformedConfigsRefusedWithoutMutation(t *testing.T) {
	for _, c := range []Client{Claude, Cursor, Pi} {
		for i, bad := range []string{"", `null`, `[]`, `{"mcpServers":null}`, `{"mcpServers":[]}`, `{"a":1,"a":2}`, `{"a":1} {}`, `{"mcpServers":{`} {
			t.Run(fmt.Sprintf("%s-%d", c, i), func(t *testing.T) {
				o := options(t, c)
				l, _ := Locations(o)
				put(t, l.MCP, []byte(bad))
				_, e := Install(context.Background(), o)
				if !errors.Is(e, ErrMalformed) {
					t.Fatalf("%v", e)
				}
				if string(mustRead(t, l.MCP)) != bad {
					t.Fatal("mutated malformed config")
				}
			})
		}
	}
	// TOML is intentionally never rewritten without a real vendor parser/API.
	o := options(t, Codex)
	l, _ := Locations(o)
	bad := []byte("this is not [valid toml")
	put(t, l.MCP, bad)
	r, e := Install(context.Background(), o)
	if e != nil || r.MCP != "manual_pending" || !strings.Contains(strings.Join(r.Gaps, ","), "toml_existing_config_validation_unverified") {
		t.Fatalf("%+v %v", r, e)
	}
	if !bytes.Equal(mustRead(t, l.MCP), bad) {
		t.Fatal("malformed TOML mutated")
	}
}

func TestConflictsAndStatus(t *testing.T) {
	for _, c := range []Client{Claude, Cursor, Pi} {
		t.Run(string(c), func(t *testing.T) {
			o := options(t, c)
			l, _ := Locations(o)
			put(t, l.MCP, []byte(`{"mcpServers":{"hilo":{"command":"other"}}}`))
			if _, e := Install(context.Background(), o); !errors.Is(e, ErrConflict) {
				t.Fatal(e)
			}
			r, e := Status(context.Background(), o)
			if e != nil {
				t.Fatal(e)
			}
			if c != Pi && r.MCP != "entry_present_runtime_unverified" {
				t.Fatal(r)
			}
			put(t, l.MCP, []byte(`{"mcpServers":{"telara-memory":{"command":"other"}}}`))
			if _, e := Install(context.Background(), o); !errors.Is(e, ErrConflict) {
				t.Fatalf("legacy registration must remain a conflict: %v", e)
			}
			if r, e := Status(context.Background(), o); e != nil || r.MCP != "manual_pending" {
				t.Fatalf("legacy registration must not appear as Hilo: %+v %v", r, e)
			}
			if _, e = Uninstall(context.Background(), o); e != nil {
				t.Fatal(e)
			}
		})
	}
	o := options(t, Pi)
	l, _ := Locations(o)
	put(t, l.Extension, []byte("// user extension\n"))
	if _, e := Install(context.Background(), o); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if _, e := Uninstall(context.Background(), o); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if string(mustRead(t, l.Extension)) != "// user extension\n" {
		t.Fatal("extension changed")
	}
}

func TestPiInstallUninstallRoundTripAndEditedFileRefusal(t *testing.T) {
	o := options(t, Pi)
	l, _ := Locations(o)
	if _, e := Uninstall(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	r, e := Install(context.Background(), o)
	if e != nil || r.MCP != "extension_installed_registration_unverified" {
		t.Fatalf("%+v %v", r, e)
	}
	before := mustRead(t, l.Extension)
	if _, e = Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(mustRead(t, l.Extension), before) {
		t.Fatal("idempotent install changed bytes")
	}
	r, e = Status(context.Background(), o)
	if e != nil || r.Capture != "extension_installed_dispatch_unverified" {
		t.Fatalf("%+v %v", r, e)
	}
	put(t, l.Extension, append(append([]byte{}, before...), []byte("// unrelated edit\n")...))
	if _, e = Uninstall(context.Background(), o); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	put(t, l.Extension, before)
	if _, e = Uninstall(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(l.Extension); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
	if _, e = Uninstall(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	// Crash after receipt publication can resume an absent extension.
	if _, e = Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(l.Extension); e != nil {
		t.Fatal(e)
	}
	r, e = Status(context.Background(), o)
	if e != nil || !strings.Contains(strings.Join(r.Gaps, ","), "extension_install_interrupted") {
		t.Fatalf("%+v %v", r, e)
	}
	if _, e = Install(context.Background(), o); e != nil {
		t.Fatal(e)
	}
}

func TestConcurrentPiInstallers(t *testing.T) {
	o := options(t, Pi)
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := Install(context.Background(), o); errs <- e }()
	}
	wg.Wait()
	close(errs)
	passed := 0
	for e := range errs {
		if e == nil {
			passed++
		} else if !errors.Is(e, ErrBusy) {
			t.Fatal(e)
		}
	}
	if passed == 0 {
		t.Fatal("no installer completed")
	}
	if _, e := Status(context.Background(), o); e != nil {
		t.Fatal(e)
	}
}

func TestOptionsInjectionAndCancellation(t *testing.T) {
	for _, s := range []string{"/tmp/a;touch x", "/tmp/$(id)", "/tmp/a\nb", "/tmp/a'", "/tmp/${env:SECRET}", "/tmp/a\u202eb", "relative", "/tmp/../x", "/tmp/ghp_" + strings.Repeat("a", 36)} {
		o := options(t, Claude)
		o.Executable = s
		if _, e := Install(context.Background(), o); !errors.Is(e, ErrOptions) {
			t.Fatalf("%q %v", s, e)
		}
	}
	if _, e := Locations(Options{Client: "../other", Home: "/tmp/test"}); !errors.Is(e, ErrOptions) {
		t.Fatal(e)
	}
	o := options(t, Claude)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Install(ctx, o); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := Uninstall(ctx, o); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := Status(ctx, o); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	foreign := "windows"
	if runtime.GOOS == "windows" {
		foreign = "linux"
	}
	home := "/home/test"
	if foreign == "windows" {
		home = `C:\Users\test`
	}
	if _, e := Status(context.Background(), Options{Client: Codex, GOOS: foreign, Home: home}); e != nil {
		t.Fatal(e)
	}
}

func TestExplicitDefaultClaudeRootMovesMCPAndRefusalState(t *testing.T) {
	o := options(t, Claude)
	o.ConfigRoot = filepath.Join(o.Home, ".claude")
	l, e := Locations(o)
	if e != nil || l.MCP != filepath.Join(o.ConfigRoot, ".claude.json") {
		t.Fatalf("%+v %v", l, e)
	}
	p := options(t, Pi)
	pl, _ := Locations(p)
	if _, e = Install(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	put(t, pl.Extension, []byte("// edited after install"))
	r, e := Uninstall(context.Background(), p)
	if !errors.Is(e, ErrConflict) || r.MCP != "uninstall_refused" {
		t.Fatalf("%+v %v", r, e)
	}
}
