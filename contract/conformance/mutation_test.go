package conformance_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pythonTree copies the runner and every fixture it reads into a fresh
// contract-shaped directory so one fixture can be changed without touching
// the committed files.
func pythonTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	copyFile := func(src, dst string) {
		raw, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyFile("python_vectors.py", filepath.Join(root, "conformance", "python_vectors.py"))
	copyFile(fixtureName, filepath.Join(root, "conformance", fixtureName))
	for _, pattern := range []string{"../testdata/*.json", "../testdata/historical-mnc2/*.json"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range matches {
			rel, _ := filepath.Rel("../testdata", m)
			copyFile(m, filepath.Join(root, "testdata", rel))
		}
	}
	return root
}

func runPython(t *testing.T, python, root string) (string, error) {
	t.Helper()
	args := []string{"-I", filepath.Join(root, "conformance", "python_vectors.py")}
	if *pyDeps != "" {
		args = append(args, "--deps", *pyDeps)
	}
	cmd := exec.Command(python, args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// flip changes one character in the middle of a hex or base64url value.
func flip(v string) string {
	b := []byte(v)
	i := len(b) / 2
	if b[i] == 'a' {
		b[i] = 'b'
	} else {
		b[i] = 'a'
	}
	return string(b)
}

func field(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			v = v.(map[string]any)[k]
		case int:
			v = v.([]any)[k]
		}
	}
	return v
}

func named(list any, name string) any {
	for _, x := range list.([]any) {
		if x.(map[string]any)["name"] == name {
			return x
		}
	}
	return nil
}

// TestPythonRejectsMutatedFixtures proves each section of the Python runner
// is load-bearing: one changed value in that section's fixture must stop the
// runner at that section, after every earlier section passed.
func TestPythonRejectsMutatedFixtures(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("UNVERIFIED: python3 is not installed")
	}
	base := pythonTree(t)
	out, err := runPython(t, python, base)
	if err != nil {
		if strings.Contains(out, "ModuleNotFoundError") && *pyDeps == "" {
			t.Skipf("UNVERIFIED: Python requirements not installed; pass -pydeps (%s)", strings.TrimSpace(out))
		}
		t.Fatalf("unmutated copy failed: %v\n%s", err, out)
	}
	sigOf := func(list, name string) func(any) string {
		return func(v any) string {
			return field(named(field(v, list), name), "sigs", 0, "value").(string)
		}
	}
	cases := []struct {
		vector, file, before, section string
		pick                          func(any) string
	}{
		{"V1", "testdata/v01-jcs.json", "", "V1 PASS", func(v any) string { return field(v, 0, "canonical").(string) }},
		{"V2", "testdata/v02-identity.json", "V1 PASS", "V2 PASS", func(v any) string { return field(v, "repo").(string) }},
		{"V3", "testdata/v03-records.json", "V2 PASS", "V3 PASS", func(v any) string { return field(v, 0, "ID").(string) }},
		{"V4", "testdata/v04-salt.json", "V3 PASS", "V4 PASS", func(v any) string { return field(v, "salt").(string) }},
		{"V5", "testdata/v05-signature.json", "V4 PASS", "V5 PASS", func(v any) string { return field(v, "signature", "value").(string) }},
		{"worked_examples", "testdata/v03-worked-example.json", "V5 PASS", "Worked examples and signed exposure manifest PASS", func(v any) string { return field(v, "id").(string) }},
		{"historical_major_2", "testdata/historical-mnc2/v03-records.json", "Worked examples and signed exposure manifest PASS", "Historical major-2 integrity PASS", func(v any) string { return field(v, 0, "ID").(string) }},
		{"V6", "conformance/" + fixtureName, "Historical major-2 integrity PASS", "V6 PASS", sigOf("ops", "addB")},
		{"V7", "conformance/" + fixtureName, "V6 PASS", "V7 PASS", sigOf("v7", "rotated_successor_verified")},
		{"V6_possession_bootstrap", "testdata/v06-possession-bootstrap.json", "V7 PASS", "V6 possession bootstrap PASS", sigOf("ops", "tskT")},
	}
	for _, c := range cases {
		t.Run(c.vector, func(t *testing.T) {
			root := pythonTree(t)
			path := filepath.Join(root, filepath.FromSlash(c.file))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var v any
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			old := c.pick(v)
			if n := bytes.Count(raw, []byte(old)); n != 1 {
				t.Fatalf("mutation target occurs %d times", n)
			}
			mutated := flip(old)
			if err := os.WriteFile(path, bytes.Replace(raw, []byte(old), []byte(mutated), 1), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := runPython(t, python, root)
			if err == nil {
				t.Fatalf("mutated %s accepted\n%s", c.file, out)
			}
			if strings.Contains(out, c.section) || (c.before != "" && !strings.Contains(out, c.before)) {
				t.Fatalf("mutation did not stop at %q\n%s", c.section, out)
			}
			lines := strings.Split(strings.TrimSpace(out), "\n")
			t.Logf("%s: %s %q -> %q: %s", c.vector, c.file, old, mutated, lines[len(lines)-1])
		})
	}
}
