// Command conformance runs the shared vector registry. Storage/transport proof
// remains INCOMPLETE until the corresponding adapter executes its listed gates.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type test struct {
	Package string `json:"package"`
	Run     string `json:"run"`
}
type vector struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Tests           []test   `json:"tests"`
	Fixtures        []string `json:"fixtures"`
	AdapterRequired []string `json:"adapter_required"`
}
type registry struct {
	Contract string   `json:"contract"`
	Vectors  []vector `json:"vectors"`
}
type result struct {
	ID, Status      string
	PureTests       int
	AdapterRequired []string `json:"adapter_required,omitempty"`
	Error           string   `json:"error,omitempty"`
}

func main() {
	root := flag.String("root", ".", "contract module directory")
	only := flag.String("vector", "", "one vector, e.g. V9")
	pure := flag.Bool("pure", false, "return success if pure tests pass, while reporting adapter gates")
	flag.Parse()
	raw, err := os.ReadFile(filepath.Join(*root, "testdata/vectors.json"))
	if err != nil {
		panic(err)
	}
	var r registry
	if err = json.Unmarshal(raw, &r); err != nil {
		panic(err)
	}
	allowed := map[string]bool{".": true, "./jcs": true, "./record": true, "./sig": true, "./heads": true, "./invalidate": true, "./policy": true, "./view": true, "./transport": true, "./replay": true}
	out := []result{}
	failed, pending, matched := false, false, false
	for _, v := range r.Vectors {
		if *only != "" && *only != v.ID {
			continue
		}
		matched = true
		x := result{ID: v.ID, Status: "PASS", AdapterRequired: v.AdapterRequired}
		for _, tc := range v.Tests {
			if !allowed[tc.Package] || !strings.HasPrefix(tc.Run, "^Test") {
				x.Status = "FAIL"
				x.Error = "invalid test registry"
				failed = true
				break
			}
			cmd := exec.Command("go", "test", tc.Package, "-run", tc.Run, "-count=1")
			cmd.Dir = *root
			output, err := cmd.CombinedOutput()
			if err != nil || strings.Contains(string(output), "[no tests to run]") {
				x.Status = "FAIL"
				x.Error = string(output)
				failed = true
				break
			}
			x.PureTests++
		}
		if len(v.AdapterRequired) > 0 && x.Status != "FAIL" {
			x.Status = "INCOMPLETE"
			pending = true
		}
		out = append(out, x)
	}
	if !matched {
		fmt.Fprintln(os.Stderr, "unknown vector")
		os.Exit(1)
	}
	report := struct {
		Contract, Status string
		Vectors          []result
	}{r.Contract, "PASS", out}
	if pending {
		report.Status = "INCOMPLETE"
	}
	if failed {
		report.Status = "FAIL"
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(report)
	if failed {
		os.Exit(1)
	}
	if pending && !*pure {
		os.Exit(2)
	}
}
