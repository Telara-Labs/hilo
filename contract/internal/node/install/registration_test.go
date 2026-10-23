package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
)

func launchRegistration(r Record) []byte { // used only by unit fixtures through tests
	return []byte(fmt.Sprintf("%s = {\n\tpath = %s\n\ttype = LaunchAgent\n\tprogram = %s\n\targuments = {\n\t\t%s\n\t\tmanaged-daemon\n\t\t--install-dir\n\t\t%s\n\t}\n\tdomain = %s [42]\n}\n", service(r), definitionPath(r), r.Executable, r.Executable, r.Dir, domain(r)))
}

func TestRegisteredIdentity(t *testing.T) {
	for _, platform := range []string{"darwin", "linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			r, _ := receiptFixture(t)
			r.Platform = platform
			for _, change := range []string{"none", "program", "arguments", "owner", "digest"} {
				t.Run(change, func(t *testing.T) {
					actual := r
					switch change {
					case "program":
						actual.Executable += "-foreign"
					case "arguments":
						actual.Dir += "-foreign"
					case "owner":
						actual.UserID = "foreign"
					}
					m := &managerFixture{record: actual, present: true}
					ctx := adapted(func(ctx context.Context, p string, args ...string) ([]byte, error) {
						b, e := m.command(ctx, p, args...)
						if change == "owner" && platform == "darwin" && len(args) == 2 && args[1] == service(r) {
							b = launchRegistration(actual)
							b = bytes.Replace(b, []byte(service(actual)+" = {"), []byte(service(r)+" = {"), 1)
						}
						if change == "owner" && platform == "linux" {
							b = bytes.Replace(b, []byte("User=\n"), []byte("User=foreign\n"), 1)
						}
						return b, e
					})
					checked := r
					if change == "digest" {
						checked.SHA256 = strings.Repeat("0", 64)
					}
					e := registered(ctx, checked)
					if change == "none" {
						if e != nil {
							t.Fatal(e)
						}
					} else if e == nil {
						t.Fatal("adopted foreign identity")
					}
				})
			}
		})
	}
}
func TestCollisionNeverMutated(t *testing.T) {
	r, src := receiptFixture(t)
	if _, e := Register(fixtureManager(r), r.Dir); e != nil {
		t.Fatal(e)
	}
	other := r
	other.Executable += "-unrelated"
	m := &managerFixture{record: other, present: true}
	ctx := adapted(m.command)
	q := func(context.Context) error { t.Fatal("quiesced foreign service"); return nil }
	if _, e := Status(ctx, r.Dir); !errors.Is(e, ErrUnverified) {
		t.Fatal(e)
	}
	for _, fn := range []func() error{
		func() error { return Autostart(ctx, r.Dir) }, func() error { return Start(ctx, r.Dir) },
		func() error { return Stop(ctx, r.Dir, q) }, func() error { return Uninstall(ctx, r.Dir, q) },
		func() error { _, e := Upgrade(ctx, r.Dir, src, r.SHA256, "2.0", q); return e },
		func() error { _, e := Register(ctx, r.Dir); return e },
	} {
		if e := fn(); !errors.Is(e, ErrUnverified) {
			t.Fatal(e)
		}
	}
	for _, args := range m.calls {
		if args[0] != "print" && args[0] != "/Query" && !(args[0] == "--user" && (args[1] == "show" || args[1] == "--json=short")) {
			t.Fatal("mutated colliding service", args)
		}
	}
	if _, e := readReceipt(r.Dir); e != nil {
		t.Fatal(e)
	}
}
func TestFreshInstallCollision(t *testing.T) {
	r, src := receiptFixture(t)
	if e := removeOwned(filepath.Join(r.Dir, "install.json")); e != nil {
		t.Fatal(e)
	}
	foreign := r
	foreign.Executable += "-foreign"
	m := &managerFixture{record: foreign, present: true}
	c := Config{Dir: r.Dir, Home: r.Home, Label: r.Label, Executable: src, SHA256: r.SHA256, Version: r.Version, DataDir: r.DataDir, RunDir: r.RunDir}
	if _, e := Install(adapted(m.command), c); !errors.Is(e, ErrUnverified) {
		t.Fatal(e)
	}
	if _, e := os.Stat(definitionPath(r)); !os.IsNotExist(e) {
		t.Fatal("wrote definition for collision", e)
	}
}
func TestUninstallAfterStopAndFailedBootstrap(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("LaunchAgent lifecycle regression")
	}
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			r, _ := receiptFixture(t)
			m := &managerFixture{record: r}
			ctx := adapted(m.command)
			if _, e := Register(ctx, r.Dir); e != nil {
				t.Fatal(e)
			}
			q := func(context.Context) error { return nil }
			if partial {
				m.present = false
			} else if e := Stop(ctx, r.Dir, q); e != nil {
				t.Fatal(e)
			}
			if e := Uninstall(ctx, r.Dir, q); e != nil {
				t.Fatal(e)
			}
			for _, p := range []string{definitionPath(r), filepath.Join(r.Dir, "install.json")} {
				if _, e := os.Stat(p); !os.IsNotExist(e) {
					t.Fatal("retained autostart input", p, e)
				}
			}
			if _, e := os.Stat(r.Executable); e != nil {
				t.Fatal("removed image", e)
			}
		})
	}
}
func TestAmbiguousAbsenceRefusesCleanup(t *testing.T) {
	r, _ := receiptFixture(t)
	if _, e := Register(fixtureManager(r), r.Dir); e != nil {
		t.Fatal(e)
	}
	ctx := adapted(func(context.Context, string, ...string) ([]byte, error) {
		return []byte("access denied"), ErrUnavailable
	})
	if e := Uninstall(ctx, r.Dir, func(context.Context) error { return nil }); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if _, e := os.Stat(definitionPath(r)); e != nil {
		t.Fatal(e)
	}
	if _, e := readReceipt(r.Dir); e != nil {
		t.Fatal(e)
	}
}

func TestRegistrationParsersRejectAmbiguousConfiguration(t *testing.T) {
	r, _ := receiptFixture(t)
	r.Platform = "darwin"
	good := launchRegistration(r)
	for _, bad := range [][]byte{
		bytes.Replace(good, []byte("\tprogram = "), []byte("\t\tprogram = "), 1),
		bytes.Replace(good, []byte("\tdomain = "), []byte("\tdomain = system [1]\n\tignored = "), 1),
		bytes.Replace(good, []byte("\tprogram = "+r.Executable), []byte("\tprogram = /foreign\n\tprogram = "+r.Executable), 1),
		bytes.Replace(good, []byte("\t\t"+r.Dir), []byte("\t\t"+r.Dir+"\n\t\textra"), 1),
	} {
		if e := verifyLaunchRegistration(bad, r); e == nil {
			t.Fatal("accepted ambiguous launch configuration")
		}
	}
	r.Platform = "windows"
	good, e := Definition("windows", r)
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{
		bytes.Replace(good, []byte("</Actions>"), []byte("<ComHandler><ClassId>foreign</ClassId></ComHandler></Actions>"), 1),
		bytes.Replace(good, []byte("LeastPrivilege"), []byte("HighestAvailable"), 1),
		bytes.Replace(good, []byte("</Exec>"), []byte("</Exec><Exec><Command>foreign</Command></Exec>"), 1),
		append(good, []byte("<Task/>")...),
		bytes.Replace(good, []byte("<Command>"), []byte("<Command>foreign</Command><Command>"), 1),
		bytes.Replace(good, []byte("<UserId>"), []byte("<UserId>foreign</UserId><UserId>"), 1),
	} {
		if e := verifyTaskRegistration(bad, r); e == nil {
			t.Fatal("accepted ambiguous task configuration")
		}
	}
}
func TestStopBootoutRaceRequiresConfirmedAbsence(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("LaunchAgent command")
	}
	for _, absent := range []bool{false, true} {
		r, _ := receiptFixture(t)
		m := &managerFixture{record: r, present: true}
		ctx := adapted(func(ctx context.Context, p string, args ...string) ([]byte, error) {
			if args[0] == "bootout" {
				m.present = !absent
				return nil, ErrUnavailable
			}
			return m.command(ctx, p, args...)
		})
		e := managerStop(ctx, r)
		if (e == nil) != absent {
			t.Fatal(absent, e)
		}
	}
}

func TestSystemdExecKeepsArgumentBoundaries(t *testing.T) {
	r := Record{Executable: "/safe/node", Dir: "/safe/install with spaces"}
	for _, args := range [][]string{{r.Executable, "managed-daemon", "--install-dir", r.Dir}, {r.Executable, "managed-daemon --install-dir", r.Dir}, {r.Executable, "managed-daemon", "--install-dir", "/safe/install", "with", "spaces"}} {
		b, e := json.Marshal(map[string]any{"type": "a(sasbttttuii)", "data": [][]any{{r.Executable, args, false, 0, 0, 0, 0, 0, 0, 0}}})
		if e != nil {
			t.Fatal(e)
		}
		e = verifySystemdExec(b, r)
		if (e == nil) != (len(args) == 4) {
			t.Fatal(args, e)
		}
	}
}

func TestTaskUTF16AndMalformedInputs(t *testing.T) {
	r := Record{Label: "dev.test", Executable: "C:\\safe\\node.exe", Dir: "C:\\safe\\install", UserID: "S-1-5-21-123"}
	b, e := Definition("windows", r)
	if e != nil {
		t.Fatal(e)
	}
	for _, little := range []bool{false, true} {
		text := strings.Replace(string(b), "UTF-8", "UTF-16", 1)
		units := utf16.Encode([]rune(text))
		encoded := []byte{254, 255}
		if little {
			encoded = []byte{255, 254}
		}
		for _, v := range units {
			hi, lo := byte(v>>8), byte(v)
			if little {
				encoded = append(encoded, lo, hi)
			} else {
				encoded = append(encoded, hi, lo)
			}
		}
		if e := verifyTaskRegistration(encoded, r); e != nil {
			t.Fatal(e)
		}
		if e := verifyTaskRegistration(append(encoded, 0), r); e == nil {
			t.Fatal("accepted incomplete UTF16")
		}
	}
	for _, bad := range [][]byte{[]byte("not XML"), bytes.Replace(b, []byte("UTF-8"), []byte("unknown-charset"), 1)} {
		if e := verifyTaskRegistration(bad, r); e == nil {
			t.Fatal("accepted malformed task")
		}
	}
}

func TestSystemdRejectsAuxiliaryActions(t *testing.T) {
	r, _ := receiptFixture(t)
	r.Platform = "linux"
	m := &managerFixture{record: r, present: true}
	good, e := m.command(context.Background(), "linux", "--user", "show", service(r), "--property=LoadState")
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"ExecCondition", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost", "Environment", "EnvironmentFiles", "RootDirectory", "RootImage", "DropInPaths"} {
		bad := bytes.Replace(good, []byte(key+"=\n"), []byte(key+"=foreign\n"), 1)
		if e := verifySystemdRegistration(bad, r); e == nil {
			t.Fatal("adopted auxiliary config", key)
		}
	}
}
