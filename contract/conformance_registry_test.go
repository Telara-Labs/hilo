package contract_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	contractdata "github.com/Telara-Labs/hilo/contract"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const historyRoot = "testdata/oracle-history/"
const nodeVectorSetSHA256 = "638d59ed3c90a303a09572a45a5688ae9f183829f4b9616a6801d65dc2ebd893"
const nodeSourceManifestSHA256 = "5d185d07e55cfe83400177adcef0394621df5fd7aa8d34dfdbd04d844ad9b354"
const currentSourceManifestSHA256 = "cf9795fcf5b28987fdc97767fc69f6503c3a3cb461e68c2c0003f383c3f62c51"

type vectorSelector struct {
	Package string `json:"package"`
	Run     string `json:"run"`
}
type conformanceVector struct {
	ID    string           `json:"id"`
	Tests []vectorSelector `json:"tests"`
}
type vectorRegistry struct {
	Contract string              `json:"contract"`
	Vectors  []conformanceVector `json:"vectors"`
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func digestBytes(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func loadRegistry(t *testing.T) vectorRegistry {
	t.Helper()
	raw := contractdata.ConformanceRegistry()
	var r vectorRegistry
	if digestBytes(raw) != contractdata.ConformanceRegistryDigest || json.Unmarshal(raw, &r) != nil || r.Contract != "mnc/3.0" || len(r.Vectors) != 30 {
		t.Fatal("canonical registry/version/count")
	}
	for i, v := range r.Vectors {
		if v.ID != fmt.Sprintf("V%d", i+1) {
			t.Fatal("missing/reordered/duplicate vector", v.ID)
		}
	}
	return r
}
func checkExactHistoryFiles(t *testing.T, dir string, files map[string]string, extras map[string]bool) {
	t.Helper()
	want := map[string]bool{}
	for n := range files {
		want[n] = true
	}
	for n := range extras {
		want[n] = true
	}
	seen := map[string]bool{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !want[rel] {
			return fmt.Errorf("unaccounted historical fixture %s", rel)
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name := range want {
		if !seen[name] {
			t.Fatal("missing historical fixture", name)
		}
	}
}
func TestConformanceVectorDrift(t *testing.T) {
	dir := historyRoot + "vectors/"
	raw := mustRead(t, dir+"SOURCE.json")
	if digestBytes(raw) != nodeSourceManifestSHA256 {
		t.Fatal("historical SOURCE changed")
	}
	var source struct {
		Contract string
		Digest   string `json:"vector_set_sha256"`
		Files    map[string]string
		Tests    map[string]string `json:"test_sources"`
		RootTest string            `json:"root_test_sha256"`
		Runner   string            `json:"runner_sha256"`
	}
	if json.Unmarshal(raw, &source) != nil || source.Contract != "mnc/2.0" || source.Digest != nodeVectorSetSHA256 || len(source.Files) != 11 || len(source.Tests) != 9 {
		t.Fatal("unexpected historical source set")
	}
	names := []string{}
	for n := range source.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	var set strings.Builder
	for _, name := range names {
		got := digestBytes(mustRead(t, dir+name))
		if got != source.Files[name] {
			t.Fatal("historical fixture drift", name)
		}
		fmt.Fprintf(&set, "%s\x00%s\n", name, got)
	}
	if digestBytes([]byte(set.String())) != nodeVectorSetSHA256 {
		t.Fatal("historical vector set digest")
	}
	extras := map[string]bool{"SOURCE.json": true, "applicability.json": true, "node-conformance_test.go.txt": true, "node-conformance-main.go.txt": true}
	for name, want := range source.Tests {
		path := "test-sources/" + name + ".txt"
		if digestBytes(mustRead(t, dir+path)) != want {
			t.Fatal("historical original test-source drift", name)
		}
		extras[path] = true
	}
	if digestBytes(mustRead(t, dir+"node-conformance_test.go.txt")) != source.RootTest || digestBytes(mustRead(t, dir+"node-conformance-main.go.txt")) != source.Runner {
		t.Fatal("historical root/runner snapshot drift")
	}
	checkExactHistoryFiles(t, strings.TrimSuffix(dir, "/"), source.Files, extras)
}

// Current source bindings are a separately reviewed migration receipt, never a
// rewrite of historical SOURCE, test adaptation hashes or old golden bytes.
func TestCurrentConformanceSourceMigration(t *testing.T) {
	raw := mustRead(t, historyRoot+"current-source.json")
	if digestBytes(raw) != currentSourceManifestSHA256 {
		t.Fatal("current source migration receipt drift")
	}
	var m struct {
		Schema, Status    string
		Sources           map[string]string
		CanonicalFixtures map[string]string `json:"canonical_fixtures"`
		HistoricalSources map[string]string `json:"historical_sources"`
	}
	if json.Unmarshal(raw, &m) != nil || m.Schema != "telara-memory.conformance-source-migration.v1" || m.Status != "SOURCE_ONLY_NOT_RUN" || len(m.Sources) != 12 || len(m.CanonicalFixtures) != 22 || len(m.HistoricalSources) != 3 {
		t.Fatal("current migration receipt shape")
	}
	for path, want := range m.Sources {
		if digestBytes(mustRead(t, path)) != want {
			t.Fatal("current source binding drift", path)
		}
	}
	for path, want := range m.CanonicalFixtures {
		if digestBytes(mustRead(t, "testdata/"+path)) != want {
			t.Fatal("current canonical fixture drift", path)
		}
	}
	for path, want := range m.HistoricalSources {
		if digestBytes(mustRead(t, historyRoot+path)) != want {
			t.Fatal("historical SOURCE relabeled", path)
		}
	}
	entries, err := os.ReadDir(strings.TrimSuffix(historyRoot, "/"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatal("unaccounted historical lane root")
	}
	for _, e := range entries {
		if e.Name() != "vectors" && e.Name() != "node-mnc3" && e.Name() != "v3" && e.Name() != "current-source.json" {
			t.Fatal("unknown historical lane entry", e.Name())
		}
	}
}

func TestConformanceRootVectors(t *testing.T) {
	tests := []testing.InternalTest{{Name: "TestV1JSON", F: TestV1JSON}, {Name: "TestV2JSON", F: TestV2JSON}, {Name: "TestV3JSON", F: TestV3JSON}, {Name: "TestV4JSON", F: TestV4JSON}, {Name: "TestV5JSON", F: TestV5JSON}, {Name: "TestV15MatrixJSON", F: TestV15MatrixJSON}, {Name: "TestV4EventJSON", F: TestV4EventJSON}, {Name: "TestV3WorkedAndHistoricalFixtures", F: TestV3WorkedAndHistoricalFixtures}, {Name: "TestV4KeyedTextJSON", F: TestV4KeyedTextJSON}, {Name: "TestV3InvalidLateBodyNoMembership", F: TestV3InvalidLateBodyNoMembership}}
	count := 0
	for _, v := range loadRegistry(t).Vectors {
		for _, sel := range v.Tests {
			if sel.Package != "." {
				continue
			}
			count++
			pattern, err := regexp.Compile(sel.Run)
			if err != nil {
				t.Fatal(err)
			}
			matched := 0
			for _, test := range tests {
				if pattern.MatchString(test.Name) {
					matched++
					t.Run(v.ID+"/"+test.Name, func(t *testing.T) {
						t.Cleanup(func() {
							if t.Skipped() {
								t.Error("conformance root test skipped")
							}
						})
						test.F(t)
					})
				}
			}
			if matched == 0 {
				t.Fatal("root selector matched no tests", sel.Run)
			}
		}
	}
	if count != 10 {
		t.Fatal("unexpected root selector count", count)
	}
}

type sourceTarget struct{ Package, Name string }
type sourceBinding struct{ Package, Name, Target string }

func validateSelectorBindings(functions map[sourceTarget]bool, bindings []sourceBinding, selector string) error {
	pattern, err := regexp.Compile(selector)
	if err != nil {
		return err
	}
	seen := map[sourceTarget]bool{}
	names := map[string]bool{}
	for _, b := range bindings {
		key := sourceTarget{b.Package, b.Name}
		if b.Name != b.Target || !functions[key] || seen[key] {
			return errors.New("duplicate/misbound/unknown table target")
		}
		seen[key] = true
	}
	matched := 0
	for fn := range functions {
		if pattern.MatchString(fn.Name) {
			if names[fn.Name] {
				return errors.New("ambiguous internal/external source name")
			}
			names[fn.Name] = true
			matched++
			if !seen[fn] {
				return errors.New("missing matching source binding")
			}
		}
	}
	if matched == 0 {
		return errors.New("selector matches no source functions")
	}
	return nil
}
func inspectConformancePackage(dir string) (map[sourceTarget]bool, []sourceBinding, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		return nil, nil, err
	}
	functions := map[sourceTarget]bool{}
	bindings := []sourceBinding{}
	for _, path := range paths {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return nil, nil, err
		}
		wrapper := filepath.Base(path) == "conformance_vectors_test.go" || filepath.Base(path) == "conformance_external_test.go"
		badSkip := false
		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Skip" || sel.Sel.Name == "Skipf" || sel.Sel.Name == "SkipNow") {
					badSkip = true
				}
			}
			return true
		})
		if badSkip {
			return nil, nil, fmt.Errorf("conformance source may not skip %s", path)
		}
		if !wrapper {
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") && fn.Name.Name != "TestMain" {
					key := sourceTarget{f.Name.Name, fn.Name.Name}
					if functions[key] {
						return nil, nil, errors.New("duplicate source declaration")
					}
					functions[key] = true
				}
			}
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			var name, target string
			for _, e := range lit.Elts {
				kv, ok := e.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				if key.Name == "Name" {
					if v, ok := kv.Value.(*ast.BasicLit); ok {
						name, _ = strconv.Unquote(v.Value)
					}
				}
				if key.Name == "F" {
					if v, ok := kv.Value.(*ast.Ident); ok {
						target = v.Name
					}
				}
			}
			if name != "" {
				bindings = append(bindings, sourceBinding{f.Name.Name, name, target})
			}
			return true
		})
	}
	return functions, bindings, nil
}
func TestConformanceSelectorBindings(t *testing.T) {
	r := loadRegistry(t)
	for _, pkg := range []string{"jcs", "record", "sig", "policy", "invalidate", "heads", "view", "transport", "replay"} {
		functions, bindings, err := inspectConformancePackage(pkg)
		if err != nil {
			t.Fatal(err)
		}
		selectors := 0
		for _, v := range r.Vectors {
			for _, sel := range v.Tests {
				if sel.Package != "./"+pkg {
					continue
				}
				selectors++
				if err := validateSelectorBindings(functions, bindings, sel.Run); err != nil {
					t.Fatal(v.ID, pkg, sel.Run, err)
				}
			}
		}
		if selectors == 0 {
			t.Fatal("no package selectors", pkg)
		}
	}
}
func TestConformanceBindingsRejectDuplicateMissingAndMisbound(t *testing.T) {
	functions := map[sourceTarget]bool{{"policy", "TestInside"}: true, {"policy_test", "TestOutside"}: true}
	good := []sourceBinding{{"policy", "TestInside", "TestInside"}, {"policy_test", "TestOutside", "TestOutside"}}
	if err := validateSelectorBindings(functions, good, "^Test"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"duplicate", "missing", "misbound", "wrong-package", "unknown-target", "zero-match"} {
		t.Run(name, func(t *testing.T) {
			b := append([]sourceBinding{}, good...)
			selector := "^Test"
			switch name {
			case "duplicate":
				b = append(b, b[0])
			case "missing":
				b = b[1:]
			case "misbound":
				b[0].Target = "TestOutside"
			case "wrong-package":
				b[0].Package = "other"
			case "unknown-target":
				b[0].Name = "TestUnknown"
				b[0].Target = b[0].Name
			case "zero-match":
				selector = "^TestAbsent$"
			}
			if validateSelectorBindings(functions, b, selector) == nil {
				t.Fatal("dishonest selector binding accepted", name)
			}
		})
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "skip_test.go"), []byte("package fixture\nimport \"testing\"\nfunc TestSkips(t *testing.T){t.SkipNow()}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectConformancePackage(dir); err == nil {
		t.Fatal("AST skip call accepted")
	}
}
