package main

import (
	contractdata "github.com/Telara-Labs/hilo/contract"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRegistryAndFixturesArePinned(t *testing.T) {
	root := "../.."
	raw := contractdata.ConformanceRegistry()
	if _, err := validateRegistry(root, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := validateRegistry(root, append(raw, ' ')); err == nil {
		t.Fatal("mutated registry accepted")
	}
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "testdata"), 0700)
	if _, err := validateRegistry(dir, raw); err == nil {
		t.Fatal("missing fixtures accepted")
	}
	// A complete staging fixture tree with one changed byte must fail pinning.
	r, err := validateRegistry(root, raw)
	if err != nil {
		t.Fatal(err)
	}
	for n := range r.FixtureDigests {
		b, e := os.ReadFile(filepath.Join(root, "testdata", n))
		if e != nil {
			t.Fatal(e)
		}
		os.WriteFile(filepath.Join(dir, "testdata", n), b, 0600)
	}
	os.WriteFile(filepath.Join(dir, "testdata", "v03-records.json"), []byte("changed"), 0600)
	if _, err := validateRegistry(dir, raw); err == nil {
		t.Fatal("changed fixture accepted")
	}
}
func TestConformanceForcesWorkspaceOff(t *testing.T) {
	out := workOff([]string{"PATH=/bin", "GOWORK=/other/work", "GOWORK=auto"})
	count := 0
	for _, v := range out {
		if strings.HasPrefix(v, "GOWORK=") {
			count++
			if v != "GOWORK=off" {
				t.Fatal("workspace leaked")
			}
		}
	}
	if count != 1 {
		t.Fatal("ambiguous workspace env")
	}
}

func dispatchRegistry(t *testing.T) registry {
	t.Helper()
	r, err := validateRegistry("../..", contractdata.ConformanceRegistry())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func assertRuntimeRows(t *testing.T, r registry, got report, status string) {
	t.Helper()
	if len(got.Vectors) != 30 {
		t.Fatal("lost a vector", len(got.Vectors))
	}
	count, pureCount := 0, 0
	for i, v := range r.Vectors {
		if got.Vectors[i].ID != v.ID {
			t.Fatal("changed vector order")
		}
		want := []runtimeResult{}
		for _, tc := range v.Tests {
			if _, runtime := runtimePackages[tc.Package]; runtime {
				want = append(want, runtimeResult{Package: tc.Package, Run: tc.Run, Status: status})
				count++
			} else {
				pureCount++
			}
		}
		actual := got.Vectors[i].RuntimeTests
		if len(actual) != len(want) {
			t.Fatal("runtime rows disappeared", v.ID, actual)
		}
		for j := range want {
			if actual[j] != want[j] {
				t.Fatal("changed runtime registry entry", v.ID, actual[j], want[j])
			}
		}
		if !reflect.DeepEqual(got.Vectors[i].AdapterRequired, v.AdapterRequired) {
			t.Fatal("lost adapter requirements", v.ID)
		}
	}
	if count != 20 || pureCount != 80 {
		t.Fatal("registry classification changed", count, pureCount)
	}
	total := 0
	for _, v := range got.Vectors {
		total += v.PureTests
	}
	if total != 80 {
		t.Fatal("runtime tests counted as pure or pure tests lost", total)
	}
	// Adapter requirements remain evidence gaps even when all source tests pass.
	if got.Status != "INCOMPLETE" {
		t.Fatal("adapter requirements became a pass claim", got.Status)
	}
}

func TestPureDispatchRetainsAllTwentyRuntimeEntriesWithoutLaunching(t *testing.T) {
	r := dispatchRegistry(t)
	calls := 0
	out, err := runRegistry("pure-source", filepath.Join(t.TempDir(), "unavailable-node"), "", true, r, func(dir, pkg, selector string) testOutcome {
		calls++
		if dir != "pure-source" || !purePackages[pkg] {
			t.Fatal("pure mode launched runtime", dir, pkg)
		}
		return testOutcome{Status: "PASS"}
	})
	if err != nil || calls != 80 {
		t.Fatal(err, calls)
	}
	assertRuntimeRows(t, r, out, "NOT_RUN")
}

func TestFullDispatchUsesExplicitNodeModuleRootAndExactPackageMap(t *testing.T) {
	node := t.TempDir()
	if err := os.WriteFile(filepath.Join(node, "go.mod"), []byte("module "+nodeModule+"\ngo 1.26.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := dispatchRegistry(t)
	calls := 0
	runtimeCalls := 0
	type invocation struct{ dir, pkg, selector string }
	wantCalls := []invocation{}
	exactRuntime := map[string]string{"./internal/node/store": "./store", "./internal/node/bundle": "./bundle", "./internal/node/syncnode": "./syncnode", "./cmd/telara-memory": "./cmd/hilo"}
	for _, v := range r.Vectors {
		for _, tc := range v.Tests {
			dir, pkg := "pure-source", tc.Package
			if mapped, ok := exactRuntime[pkg]; ok {
				dir, pkg = node, mapped
			}
			wantCalls = append(wantCalls, invocation{dir, pkg, tc.Run})
		}
	}
	out, err := runRegistry("pure-source", node, "", false, r, func(dir, pkg, selector string) testOutcome {
		if calls >= len(wantCalls) || wantCalls[calls] != (invocation{dir, pkg, selector}) {
			t.Fatal("dispatch changed exact cwd/package/selector", calls, dir, pkg, selector)
		}
		calls++
		if dir == node {
			runtimeCalls++
			if pkg != "./store" && pkg != "./bundle" && pkg != "./syncnode" && pkg != "./cmd/hilo" {
				t.Fatal("invalid runtime remap", pkg)
			}
		} else if dir != "pure-source" || !purePackages[pkg] {
			t.Fatal("wrong dispatch root", dir, pkg)
		}
		return testOutcome{Status: "PASS"}
	})
	if err != nil || calls != 100 || runtimeCalls != 20 {
		t.Fatal(err, calls, runtimeCalls)
	}
	assertRuntimeRows(t, r, out, "PASS")
	want := []string{"test", "-p", "1", "-json", "-mod=readonly", "-count=1", "-timeout=300s", "./store", "-run", "^TestBound$"}
	if !reflect.DeepEqual(goTestArgs("./store", "^TestBound$"), want) {
		t.Fatal("test arguments lost reproducibility/read-only guards")
	}
}

func TestMissingNodeDispatchIsIncompleteAndInvalidModuleRefuses(t *testing.T) {
	r := dispatchRegistry(t)
	calls := 0
	out, err := runRegistry("pure-source", "", "", false, r, func(dir, pkg, selector string) testOutcome {
		calls++
		if dir != "pure-source" {
			t.Fatal("implicit node root")
		}
		return testOutcome{Status: "PASS"}
	})
	if err != nil || calls != 80 {
		t.Fatal(err, calls)
	}
	assertRuntimeRows(t, r, out, "NOT_RUN")
	for _, body := range []string{"", "module other/module\n", "module " + nodeModule + "/suffix\n", "module " + nodeModule + "\nmodule " + nodeModule + "\n"} {
		node := t.TempDir()
		if err := os.WriteFile(filepath.Join(node, "go.mod"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := runRegistry("pure", node, "", false, r, func(string, string, string) testOutcome {
			t.Fatal("invalid module launched tests")
			return testOutcome{Status: "FAIL"}
		}); err == nil {
			t.Fatal("invalid node identity accepted", body)
		}
	}
	if _, err := runRegistry("pure", filepath.Join(t.TempDir(), "missing"), "", false, r, func(string, string, string) testOutcome {
		t.Fatal("unavailable module launched tests")
		return testOutcome{Status: "FAIL"}
	}); err == nil {
		t.Fatal("unavailable explicit node root accepted")
	}
}

func TestConformanceUnknownPathsRefuseAndEmptyTestRunsFail(t *testing.T) {
	r := dispatchRegistry(t)
	r.Vectors[0].Tests[0].Package = "./internal/node/store/../../unlisted"
	if _, err := runRegistry("pure", "", "", true, r, func(string, string, string) testOutcome {
		t.Fatal("unlisted registry launched tests")
		return testOutcome{Status: "FAIL"}
	}); err == nil {
		t.Fatal("prefix dispatch accepted unknown package")
	}
	r = dispatchRegistry(t)
	out, err := runRegistry("pure", "", "V1", true, r, func(string, string, string) testOutcome {
		return testOutcome{Status: "NOT_RUN", Error: "no selected named execution"}
	})
	if err != nil || out.Status != "INCOMPLETE" {
		t.Fatal("empty test run became proof", out, err)
	}
	if _, err := runRegistry("pure", "", "missing-vector", true, r, func(string, string, string) testOutcome {
		t.Fatal("unknown vector launched tests")
		return testOutcome{Status: "FAIL"}
	}); err == nil {
		t.Fatal("unknown vector accepted")
	}
}
