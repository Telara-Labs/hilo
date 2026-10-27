package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func executionJSON(t *testing.T, events ...goTestEvent) []byte {
	t.Helper()
	raw := []byte{}
	for _, e := range events {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, b...)
		raw = append(raw, '\n')
	}
	return raw
}
func TestNamedExecutionRequiresEverySourceTestAndNoSkip(t *testing.T) {
	const pkg = pureModule + "/policy"
	start := goTestEvent{Action: "start", Package: pkg}
	done := goTestEvent{Action: "pass", Package: pkg}
	run := func(n string) goTestEvent { return goTestEvent{Action: "run", Package: pkg, Test: n} }
	pass := func(n string) goTestEvent { return goTestEvent{Action: "pass", Package: pkg, Test: n} }
	skip := func(n string) goTestEvent { return goTestEvent{Action: "skip", Package: pkg, Test: n} }
	for _, tc := range []struct {
		name, status string
		events       []goTestEvent
		processErr   error
	}{
		{"positive-all-named", "PASS", []goTestEvent{start, run("TestA"), run("TestA/child"), pass("TestA/child"), pass("TestA"), run("TestB"), pass("TestB"), done}, nil},
		{"positive-compound-subtest-name", "PASS", []goTestEvent{start, run("TestA"), run("TestA/V18/TestVerify"), pass("TestA/V18/TestVerify"), pass("TestA"), run("TestB"), pass("TestB"), done}, nil},
		{"package-ok-only", "NOT_RUN", []goTestEvent{start, done}, nil},
		{"missing-one-matching-root", "NOT_RUN", []goTestEvent{start, run("TestA"), pass("TestA"), done}, nil},
		{"root-skip", "NOT_RUN", []goTestEvent{start, run("TestA"), skip("TestA"), run("TestB"), pass("TestB"), done}, nil},
		{"nested-skip", "NOT_RUN", []goTestEvent{start, run("TestA"), run("TestA/child"), skip("TestA/child"), pass("TestA"), run("TestB"), pass("TestB"), done}, nil},
		{"pass-without-run", "FAIL", []goTestEvent{start, pass("TestA"), done}, nil},
		{"missing-terminal", "FAIL", []goTestEvent{start, run("TestA"), done}, nil},
		{"duplicate-run", "FAIL", []goTestEvent{start, run("TestA"), run("TestA"), done}, nil},
		{"duplicate-pass", "FAIL", []goTestEvent{start, run("TestA"), pass("TestA"), pass("TestA"), done}, nil},
		{"duplicate-package", "FAIL", []goTestEvent{start, start, done}, nil},
		{"no-tests", "NOT_RUN", []goTestEvent{start, {Action: "output", Package: pkg, Output: "testing: warning: no tests to run\n"}, done}, nil},
		{"cached", "FAIL", []goTestEvent{start, {Action: "output", Package: pkg, Output: "ok (cached)\n"}, done}, nil},
		{"cache-field", "FAIL", []goTestEvent{start, {Action: "pass", Package: pkg, Cached: true}}, nil},
		{"fail-event", "FAIL", []goTestEvent{start, run("TestA"), {Action: "fail", Package: pkg, Test: "TestA"}, done}, nil},
		{"failed-command", "FAIL", nil, errors.New("exit1")},
		{"unexpected-name", "FAIL", []goTestEvent{start, run("TestOther"), pass("TestOther"), done}, nil},
		{"wrong-package", "FAIL", []goTestEvent{start, {Action: "run", Package: pkg + "/other", Test: "TestA"}, done}, nil},
		{"missing-package-end", "FAIL", []goTestEvent{start, run("TestA"), pass("TestA")}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := namedExecution(executionJSON(t, tc.events...), tc.processErr, pkg, []string{"TestA", "TestB"})
			if got.Status != tc.status {
				t.Fatal(got, tc.status)
			}
		})
	}
	if got := namedExecution([]byte("ok package\n"), nil, pkg, []string{"TestA"}); got.Status != "FAIL" {
		t.Fatal("plain package ok accepted", got)
	}
}

func TestSourceInventoryBindsInternalAndExternalPackages(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("inside_test.go", "package policy\nimport \"testing\"\nfunc TestInside(t *testing.T) {}\n")
	write("outside_test.go", "package policy_test\nimport \"testing\"\nfunc TestOutside(t *testing.T) {}\n")
	p := packageSources{Dir: dir, ImportPath: pureModule + "/policy", Name: "policy", TestGoFiles: []string{"inside_test.go"}, XTestGoFiles: []string{"outside_test.go"}}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sourceTestNames(raw, p.ImportPath, "^Test")
	if err != nil || !reflect.DeepEqual(got, []string{"TestInside", "TestOutside"}) {
		t.Fatal(got, err)
	}
	for _, name := range []string{"duplicate-name", "wrong-declared-package", "escaping-file", "duplicate-file", "zero-selector", "skip-call", "wrong-import-path"} {
		t.Run(name, func(t *testing.T) {
			q := p
			selector := "^Test"
			q.TestGoFiles = append([]string{}, p.TestGoFiles...)
			q.XTestGoFiles = append([]string{}, p.XTestGoFiles...)
			switch name {
			case "duplicate-name":
				write("other_test.go", "package policy_test\nimport \"testing\"\nfunc TestInside(t *testing.T) {}\n")
				q.XTestGoFiles = []string{"other_test.go"}
			case "wrong-declared-package":
				write("other_test.go", "package other\nimport \"testing\"\nfunc TestOther(t *testing.T) {}\n")
				q.XTestGoFiles = []string{"other_test.go"}
			case "escaping-file":
				q.XTestGoFiles = []string{"../outside_test.go"}
			case "duplicate-file":
				q.XTestGoFiles = []string{"inside_test.go"}
			case "zero-selector":
				selector = "^TestAbsent$"
			case "skip-call":
				write("other_test.go", "package policy\nimport \"testing\"\nfunc TestSkips(t *testing.T) { t.Skip(\"unverified\") }\n")
				q.TestGoFiles = []string{"other_test.go"}
			case "wrong-import-path":
				q.ImportPath += "/other"
			}
			b, err := json.Marshal(q)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sourceTestNames(b, p.ImportPath, selector); err == nil {
				t.Fatal("invalid source binding accepted", name)
			}
		})
	}
}

func TestCrossLanguageOptionalPathsStillRequireActualNamedPass(t *testing.T) {
	dir := t.TempDir()
	source := "package conformance_test\nimport \"testing\"\nfunc TestPythonOptional(t *testing.T){t.Skip(\"UNVERIFIED\")}\n"
	if err := os.WriteFile(filepath.Join(dir, "optional_test.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	p := packageSources{Dir: dir, ImportPath: pureModule + "/conformance", Name: "conformance", XTestGoFiles: []string{"optional_test.go"}}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	names, err := sourceTestNames(raw, p.ImportPath, "^TestPythonOptional$")
	if err != nil || len(names) != 1 {
		t.Fatal(names, err)
	}
	output := executionJSON(t, goTestEvent{Action: "start", Package: p.ImportPath}, goTestEvent{Action: "run", Package: p.ImportPath, Test: names[0]}, goTestEvent{Action: "skip", Package: p.ImportPath, Test: names[0]}, goTestEvent{Action: "pass", Package: p.ImportPath})
	if got := namedExecution(output, nil, p.ImportPath, names); got.Status != "NOT_RUN" {
		t.Fatal("optional path skip became proof", got)
	}
}
