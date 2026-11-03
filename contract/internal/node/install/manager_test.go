package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func adapted(fn commandAdapter) context.Context {
	return context.WithValue(context.Background(), commandKey{}, fn)
}

// A model of native command replies only. This is unit coverage, never a
// substitute for the real platform-manager acceptance gate.
type managerFixture struct {
	record  Record
	present bool
	calls   [][]string
}

func (m *managerFixture) command(_ context.Context, platform string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, args)
	r := m.record
	if platform == "linux" && strings.Join(args, " ") == "--user daemon-reload" {
		m.present = true
	}
	if platform == "linux-bus" {
		if args[len(args)-1] != "ExecStart" {
			kind := "a(sasbttttuii)"
			if args[len(args)-1] == "EnvironmentFiles" {
				kind = "a(sb)"
			}
			return json.Marshal(map[string]any{"type": kind, "data": []any{}})
		}
		return json.Marshal(map[string]any{"type": "a(sasbttttuii)", "data": [][]any{{r.Executable, []string{r.Executable, "managed-daemon", "--install-dir", r.Dir}, false, 0, 0, 0, 0, 0, 0, 0}}})
	}
	joined := strings.Join(args, " ")
	if platform == "darwin" && len(args) == 2 && args[0] == "print" {
		if args[1] == domain(r) {
			return []byte("asid = 42\n"), nil
		}
		if !m.present {
			return []byte("Bad request.\nCould not find service \"" + r.Label + "\" in domain for user gui: " + r.UserID + "\n"), ErrUnavailable
		}
		return launchRegistration(r), nil
	}
	if strings.Contains(joined, "init.scope") {
		return []byte(strings.Repeat("a", 32)), nil
	}

	if platform == "windows" && joined == "/Query /FO CSV /NH" {
		if m.present {
			return []byte(fmt.Sprintf("\"%s\",Ready\n", `\`+r.Label)), nil
		}
		return nil, nil
	}
	if platform == "windows" && strings.Contains(joined, "/Query /TN") {
		return Definition(platform, r)
	}
	if platform == "linux" && strings.Contains(joined, "--property=LoadState") {
		if !m.present {
			return []byte("LoadState=not-found\n"), nil
		}
		return []byte(fmt.Sprintf("LoadState=loaded\nFragmentPath=%s\nDropInPaths=\nUser=\nEnvironment=\nRootDirectory=\nRootImage=\n", definitionPath(r))), nil
	}
	if len(args) > 0 && (args[0] == "bootstrap" || args[0] == "/Create" || strings.Contains(joined, "enable --now")) {
		m.present = true
	}
	if len(args) > 0 && (args[0] == "bootout" || args[0] == "/Delete") {
		m.present = false
	}
	return []byte("enabled\n"), nil
}
func fixtureManager(r Record) context.Context { return adapted((&managerFixture{record: r}).command) }
func TestManagerPlans(t *testing.T) {
	for _, platform := range []string{"darwin", "linux", "windows", "other"} {
		t.Run(platform, func(t *testing.T) {
			r, _ := receiptFixture(t)
			r.Platform = platform
			m := &managerFixture{record: r}
			ctx := adapted(m.command)
			replace := func(ctx context.Context, r Record) error { return managerReplace(ctx, r, r) }
			for _, fn := range []func(context.Context, Record) error{managerAvailable, managerInstall, managerStatus, managerStart, managerStop, replace, managerUninstall} {
				e := fn(ctx, r)
				if platform == "other" {
					if !errors.Is(e, ErrUnavailable) {
						t.Fatal(e)
					}
				} else if e != nil {
					t.Fatal(e)
				}
			}
			for _, args := range m.calls {
				for _, arg := range args {
					if arg == "--system" || arg == "enable-linger" || arg == "/End" || arg == "-k" {
						t.Fatal(args)
					}
				}
			}
		})
	}
}

func TestLinuxDeferredRegistrationDoesNotStart(t *testing.T) {
	r, _ := receiptFixture(t)
	r.Platform = "linux"
	for _, tc := range []struct {
		deferred bool
		want     string
	}{{true, "--user enable " + service(r)}, {false, "--user enable --now " + service(r)}} {
		m := &managerFixture{record: r}
		if err := managerInstallMode(adapted(m.command), r, tc.deferred); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, args := range m.calls {
			if len(args) > 1 && args[1] == "enable" {
				if got := strings.Join(args, " "); got != tc.want {
					t.Fatalf("deferred=%v command=%q want=%q", tc.deferred, got, tc.want)
				}
				found = true
			}
		}
		if !found {
			t.Fatal("missing enable command")
		}
	}
}

func TestDeferredRegistrationOtherPlatformsAndFailure(t *testing.T) {
	for _, platform := range []string{"darwin", "windows"} {
		r, _ := receiptFixture(t)
		r.Platform = platform
		a, b := &managerFixture{record: r}, &managerFixture{record: r}
		if err := managerInstallMode(adapted(a.command), r, false); err != nil {
			t.Fatal(err)
		}
		if err := managerInstallMode(adapted(b.command), r, true); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a.calls, b.calls) {
			t.Fatalf("%s deferred changed commands", platform)
		}
	}
	r, _ := receiptFixture(t)
	r.Platform = "linux"
	m := &managerFixture{record: r}
	ctx := adapted(func(ctx context.Context, platform string, args ...string) ([]byte, error) {
		if platform == "linux" && len(args) > 1 && args[1] == "enable" {
			return nil, ErrUnavailable
		}
		return m.command(ctx, platform, args...)
	})
	if err := managerInstallMode(ctx, r, true); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("enable failure: %v", err)
	}
}

func TestDeferredRegistrationRetryAfterFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux registration path")
	}
	r, _ := receiptFixture(t)
	m := &managerFixture{record: r}
	enabled, fail := false, true
	command := func(ctx context.Context, platform string, args ...string) ([]byte, error) {
		if platform == "linux" && len(args) > 1 && args[1] == "enable" {
			if fail {
				return nil, ErrUnavailable
			}
			enabled = true
		}
		if platform == "linux" && len(args) > 1 && args[1] == "is-enabled" && !enabled {
			return nil, ErrUnavailable
		}
		return m.command(ctx, platform, args...)
	}
	ctx := adapted(command)
	if _, err := RegisterDeferred(ctx, r.Dir); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("initial failure: %v", err)
	}
	fail = false
	if report, err := RegisterDeferred(ctx, r.Dir); err != nil || report.State != "registered" || !enabled {
		t.Fatalf("retry: %+v %v", report, err)
	}
	for _, args := range m.calls {
		if strings.Contains(strings.Join(args, " "), "--now") {
			t.Fatalf("retry started service: %v", args)
		}
	}
}
func TestManagerErrorsAndSessions(t *testing.T) {
	ctx := adapted(func(context.Context, string, ...string) ([]byte, error) { return nil, ErrUnavailable })
	for _, p := range []string{"darwin", "linux", "windows"} {
		r := Record{Platform: p}
		if e := managerInstall(ctx, r); e == nil {
			t.Fatal("ignored install failure")
		}
		if e := managerStart(ctx, r); e == nil {
			t.Fatal("ignored start failure")
		}
	}
	for _, pair := range []struct{ platform, output, want string }{{"darwin", "gui/1 = {\n security context = {\n asid = 123\n}\n}", "123"}, {"linux", strings.Repeat("a", 32) + "\n", strings.Repeat("a", 32)}, {"darwin", "unknown", ""}, {"linux", strings.Repeat("0", 32), ""}, {"linux", "wrong", ""}} {
		ctx := adapted(func(context.Context, string, ...string) ([]byte, error) { return []byte(pair.output), nil })
		got, e := unixSession(ctx, pair.platform)
		if got != pair.want || (pair.want == "" && e == nil) {
			t.Fatal(got, e)
		}
	}
	var b boundedOutput
	b.Write([]byte(strings.Repeat("x", 70000)))
	b.Write([]byte("more"))
	if b.Len() != 65536 {
		t.Fatal(b.Len())
	}
}
func TestUnavailableRegistrationAndRetry(t *testing.T) {
	r, src := receiptFixture(t)
	if e := removeOwned(filepath.Join(r.Dir, "install.json")); e != nil {
		t.Fatal(e)
	}
	c := Config{Dir: r.Dir, Home: r.Home, Label: r.Label, Executable: src, SHA256: r.SHA256, Version: r.Version, DataDir: r.DataDir, RunDir: r.RunDir}
	ctx := adapted(func(context.Context, string, ...string) ([]byte, error) { return nil, ErrUnavailable })
	report, e := Install(ctx, c)
	if !errors.Is(e, ErrUnavailable) || report.State != "autostart_unavailable" {
		t.Fatal(report, e)
	}
	if _, e = os.Stat(filepath.Join(r.Dir, "manager.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = Status(ctx, r.Dir); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	ctx = fixtureManager(r)
	if report, e = Register(ctx, r.Dir); e != nil || report.State != "registered" {
		t.Fatal(report, e)
	}
	if e = Autostart(ctx, r.Dir); e != nil {
		t.Fatal(e)
	}
	if e = Start(ctx, r.Dir); e != nil {
		t.Fatal(e)
	}
	if e = Uninstall(ctx, r.Dir, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(r.Dir, "install.json")); !os.IsNotExist(e) {
		t.Fatal("receipt retained", e)
	}
}

func TestUninstallUnavailableManager(t *testing.T) {
	r, _ := receiptFixture(t)
	if e := writeJSON(filepath.Join(r.Dir, "manager.json"), Report{"autostart_unavailable", r}); e != nil {
		t.Fatal(e)
	}
	ctx := adapted(func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("unavailable install touched service manager")
		return nil, ErrUnavailable
	})
	if e := Uninstall(ctx, r.Dir, nil); !errors.Is(e, ErrUpgrade) {
		t.Fatal(e)
	}
	if e := Uninstall(ctx, r.Dir, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e := readReceipt(r.Dir); !os.IsNotExist(e) {
		t.Fatal(e)
	}
}
func TestUpgradeAndUnsettledDrain(t *testing.T) {
	r, src := receiptFixture(t)
	ctx := fixtureManager(r)
	if _, e := Register(ctx, r.Dir); e != nil {
		t.Fatal(e)
	}
	// Unit command adapters provide a deterministic GUI login identity too.
	called := false
	if _, e := Upgrade(ctx, r.Dir, src, r.SHA256, "2.0", func(context.Context) error { called = true; return errors.New("unsettled") }); !errors.Is(e, ErrUpgrade) || !called {
		t.Fatal(e, called)
	}
	old, e := readReceipt(r.Dir)
	if e != nil || old.Version != r.Version {
		t.Fatal("receipt changed before settlement", e)
	}
	if _, e = Upgrade(ctx, r.Dir, src, r.SHA256, "2.0", func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
	next, e := readReceipt(r.Dir)
	if e != nil || next.Version != "2.0" {
		t.Fatal(next, e)
	}
	var i intent
	if e = readPrivate(filepath.Join(r.Dir, "intent.json"), &i); e != nil || i.Mode != "upgrade" || i.Version != "2.0" {
		t.Fatal(i, e)
	}
}
