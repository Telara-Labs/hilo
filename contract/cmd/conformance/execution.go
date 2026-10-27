package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const pureModule = "github.com/Telara-Labs/hilo/contract"

type packageSources struct {
	Dir, ImportPath, Name     string
	TestGoFiles, XTestGoFiles []string
	Error                     json.RawMessage `json:"Error,omitempty"`
}

func expectedPackage(root, pkg string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	module := ""
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(strings.SplitN(line, "//", 2)[0])
		if len(f) == 0 || f[0] != "module" {
			continue
		}
		if len(f) != 2 || module != "" || (f[1] != pureModule && f[1] != nodeModule) {
			return "", errors.New("conformance source module identity mismatch")
		}
		module = f[1]
	}
	if module == "" {
		return "", errors.New("conformance source module identity absent")
	}
	if pkg == "." {
		return module, nil
	}
	if !strings.HasPrefix(pkg, "./") || strings.Contains(pkg, "..") {
		return "", errors.New("invalid conformance package")
	}
	return module + "/" + strings.TrimPrefix(pkg, "./"), nil
}

// Go list supplies the actual build-selected internal and external test files.
// AST declarations bind every matching named test to that source set; JSON must
// later prove every name ran and passed, rather than just one regexp match.
func prohibitsSourceSkip(pkg string) bool {
	if pkg == pureModule {
		return true
	}
	for _, name := range []string{"jcs", "record", "sig", "policy", "invalidate", "heads", "view", "transport", "replay"} {
		if pkg == pureModule+"/"+name {
			return true
		}
	}
	// The independent cross-language package retains its explicit optional Python
	// paths. Selected execution still needs complete named JSON run/pass evidence.
	return false
}

func sourceTestNames(raw []byte, expected, selector string) ([]string, error) {
	var p packageSources
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if dec.Decode(new(any)) != io.EOF || p.ImportPath != expected || p.Name == "" || !filepath.IsAbs(p.Dir) || len(p.Error) > 0 {
		return nil, errors.New("test source inventory identity mismatch")
	}
	re, err := regexp.Compile(selector)
	if err != nil {
		return nil, err
	}
	seenFiles := map[string]bool{}
	names := map[string]bool{}
	for _, name := range append(append([]string{}, p.TestGoFiles...), p.XTestGoFiles...) {
		if filepath.Base(name) != name || seenFiles[name] {
			return nil, errors.New("duplicate or escaping test source")
		}
		seenFiles[name] = true
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(p.Dir, name), nil, 0)
		if err != nil {
			return nil, err
		}
		if f.Name.Name != p.Name && f.Name.Name != p.Name+"_test" {
			return nil, errors.New("test source package misbinding")
		}
		if prohibitsSourceSkip(expected) {
			skipped := false
			ast.Inspect(f, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if s, ok := c.Fun.(*ast.SelectorExpr); ok && (s.Sel.Name == "Skip" || s.Sel.Name == "Skipf" || s.Sel.Name == "SkipNow") {
						skipped = true
					}
				}
				return true
			})
			if skipped {
				return nil, errors.New("pure conformance source may not skip")
			}
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") || fn.Name.Name == "TestMain" {
				continue
			}
			if names[fn.Name.Name] {
				return nil, errors.New("duplicate internal/external test name")
			}
			names[fn.Name.Name] = true
		}
	}
	out := []string{}
	for name := range names {
		if re.MatchString(name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, errors.New("selector matches no source tests")
	}
	return out, nil
}

func runGoTest(directory, pkg, selector string) testOutcome {
	expected, err := expectedPackage(directory, pkg)
	if err != nil {
		return testOutcome{"FAIL", err.Error()}
	}
	list := exec.Command("go", "list", "-mod=readonly", "-json", pkg)
	list.Dir = directory
	list.Env = workOff(os.Environ())
	raw, err := list.CombinedOutput()
	if err != nil {
		return testOutcome{"FAIL", fmt.Sprintf("test source inventory failed: %v\n%s", err, raw)}
	}
	names, err := sourceTestNames(raw, expected, selector)
	if err != nil {
		return testOutcome{"FAIL", err.Error()}
	}
	cmd := exec.Command("go", goTestArgs(pkg, selector)...)
	cmd.Dir = directory
	cmd.Env = workOff(os.Environ())
	output, err := cmd.CombinedOutput()
	return namedExecution(output, err, expected, names)
}

type goTestEvent struct {
	Action, Package, ImportPath, Test, Output string
	Cached                                    bool
}

func namedExecution(raw []byte, processErr error, expected string, names []string) testOutcome {
	if processErr != nil {
		return testOutcome{"FAIL", fmt.Sprintf("go test failed: %v\n%s", processErr, raw)}
	}
	roots := map[string]bool{}
	for _, n := range names {
		if n == "" || strings.Contains(n, "/") || roots[n] {
			return testOutcome{"FAIL", "invalid expected source test set"}
		}
		roots[n] = true
	}
	if len(roots) == 0 {
		return testOutcome{"FAIL", "empty expected source test set"}
	}
	states := map[string]string{}
	starts, ends := 0, 0
	skipped := false
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var e goTestEvent
		err := dec.Decode(&e)
		if err == io.EOF {
			break
		}
		if err != nil {
			return testOutcome{"FAIL", "malformed go test JSON"}
		}
		if e.Cached || strings.Contains(e.Output, "(cached)") {
			return testOutcome{"FAIL", "cached conformance execution refused"}
		}
		if e.Action == "build-fail" || e.Action == "fail" {
			return testOutcome{"FAIL", "failed conformance event"}
		}
		if e.Action == "build-output" {
			if e.Test != "" || e.ImportPath == "" {
				return testOutcome{"FAIL", "malformed build event"}
			}
			continue
		}
		if e.Package != expected {
			return testOutcome{"FAIL", "conformance event package mismatch"}
		}
		if ends != 0 {
			return testOutcome{"FAIL", "events after package completion"}
		}
		if e.Test == "" {
			switch e.Action {
			case "start":
				starts++
				if starts != 1 {
					return testOutcome{"FAIL", "duplicate package start"}
				}
			case "output":
			case "skip":
				skipped = true
				ends++
			case "pass":
				ends++
			default:
				return testOutcome{"FAIL", "invalid package event"}
			}
			continue
		}
		if starts != 1 {
			return testOutcome{"FAIL", "test event before package start"}
		}
		root := strings.SplitN(e.Test, "/", 2)[0]
		if !roots[root] {
			return testOutcome{"FAIL", "test event not bound to selected source"}
		}
		state := states[e.Test]
		switch e.Action {
		case "run":
			if state != "" {
				return testOutcome{"FAIL", "duplicate test run"}
			}
			if e.Test != root {
				// A single t.Run name may contain slashes without emitting
				// separate intermediate parent events. Its selected root must
				// be running; every actual nested event still needs run/pass.
				if states[root] != "run" {
					return testOutcome{"FAIL", "nested test without selected running root"}
				}
			}
			states[e.Test] = "run"
		case "pass", "skip":
			if state != "run" {
				return testOutcome{"FAIL", "terminal event without unique run"}
			}
			states[e.Test] = e.Action
			if e.Action == "skip" {
				skipped = true
			}
		case "pause", "cont":
			if state != "run" {
				return testOutcome{"FAIL", "parallel event without run"}
			}
		case "output":
			if state == "" {
				return testOutcome{"FAIL", "output without named run"}
			}
		default:
			return testOutcome{"FAIL", "invalid named test event"}
		}
	}
	if starts != 1 || ends != 1 {
		return testOutcome{"FAIL", "package execution receipt incomplete"}
	}
	for name, state := range states {
		if state == "run" {
			return testOutcome{"FAIL", "named test missing terminal event: " + name}
		}
	}
	if skipped {
		return testOutcome{"NOT_RUN", "selected root or nested test skipped"}
	}
	for name := range roots {
		if states[name] != "pass" {
			return testOutcome{"NOT_RUN", "selected source test did not run and pass: " + name}
		}
	}
	return testOutcome{Status: "PASS"}
}
