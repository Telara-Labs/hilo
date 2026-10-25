// Command conformance runs the shared vector registry. Storage/transport proof
// remains INCOMPLETE until the corresponding adapter executes its listed gates.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	contractdata "github.com/Telara-Labs/telara-memory/contract"
	"github.com/Telara-Labs/telara-memory/contract/record"
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
	Contract       string            `json:"contract"`
	FixtureDigests map[string]string `json:"fixture_digests"`
	Vectors        []vector          `json:"vectors"`
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
	r, err := validateRegistry(*root, raw)
	if err != nil {
		panic(err)
	}
	allowed := map[string]bool{".": true, "./jcs": true, "./record": true, "./sig": true, "./heads": true, "./invalidate": true, "./policy": true, "./view": true, "./transport": true, "./replay": true,
		// Cross-language fixture pinned by the Go verifier; the Python runner checks the same bytes.
		"./conformance": true,
		// Node adapter tests run the actual SQLite store and the installed command.
		"./internal/node/bundle": true, "./internal/node/store": true, "./internal/node/syncnode": true, "./cmd/telara-memory": true}
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
			cmd := exec.Command("go", "test", "-p", "1", "-count=1", "-timeout=300s", tc.Package, "-run", tc.Run)
			cmd.Dir = *root
			cmd.Env = workOff(os.Environ())
			output, err := cmd.CombinedOutput()
			if err != nil || (strings.Contains(string(output), "[no tests to run]") || strings.Contains(string(output), "[no test files]")) {
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

func validateRegistry(root string, raw []byte) (registry, error) {
	var r registry
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != contractdata.ConformanceRegistryDigest {
		return r, errors.New("conformance registry digest mismatch")
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	if r.Contract != record.ContractVersion || len(r.Vectors) != 30 {
		return r, errors.New("unsupported vector registry")
	}
	for _, v := range r.Vectors {
		for _, name := range v.Fixtures {
			if name == "" || filepath.Base(name) != name {
				return r, errors.New("invalid fixture path")
			}
			bytes, err := os.ReadFile(filepath.Join(root, "testdata", name))
			if err != nil {
				return r, err
			}
			sum := sha256.Sum256(bytes)
			if hex.EncodeToString(sum[:]) != r.FixtureDigests[name] {
				return r, errors.New("conformance fixture digest mismatch")
			}
		}
	}
	return r, nil
}
func workOff(existing []string) []string {
	out := []string{}
	for _, value := range existing {
		if !strings.HasPrefix(value, "GOWORK=") {
			out = append(out, value)
		}
	}
	return append(out, "GOWORK=off")
}
