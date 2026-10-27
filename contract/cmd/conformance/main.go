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
type runtimeResult struct {
	Package string `json:"package"`
	Run     string `json:"run"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
}
type result struct {
	ID, Status      string
	PureTests       int
	RuntimeTests    []runtimeResult `json:"runtime_tests,omitempty"`
	AdapterRequired []string        `json:"adapter_required,omitempty"`
	Error           string          `json:"error,omitempty"`
}

const nodeModule = "github.com/Telara-Labs/telara-memory/contract/internal/node"

// Exact registry package identities only; no arbitrary path-prefix dispatch.
var purePackages = map[string]bool{
	".": true, "./jcs": true, "./record": true, "./sig": true, "./heads": true,
	"./invalidate": true, "./policy": true, "./view": true, "./transport": true,
	"./replay": true, "./conformance": true,
}
var runtimePackages = map[string]string{
	"./internal/node/store": "./store", "./internal/node/bundle": "./bundle",
	"./internal/node/syncnode": "./syncnode", "./cmd/telara-memory": "./cmd/telara-memory",
}

type report struct {
	Contract, Status string
	Vectors          []result
}
type testOutcome struct{ Status, Error string }
type testRunner func(directory, pkg, selector string) testOutcome

func main() {
	root := flag.String("root", ".", "pure contract module directory")
	nodeRoot := flag.String("node-root", "", "explicit runtime module directory for full adapter test dispatch")
	only := flag.String("vector", "", "one vector, e.g. V9")
	pure := flag.Bool("pure", false, "run pure tests only, reporting runtime and adapter gates as incomplete")
	flag.Parse()
	raw, err := os.ReadFile(filepath.Join(*root, "testdata/vectors.json"))
	if err != nil {
		panic(err)
	}
	r, err := validateRegistry(*root, raw)
	if err != nil {
		panic(err)
	}
	out, err := runRegistry(*root, *nodeRoot, *only, *pure, r, runGoTest)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if out.Status == "FAIL" {
		os.Exit(1)
	}
	if out.Status == "INCOMPLETE" && !*pure {
		os.Exit(2)
	}
}

func goTestArgs(pkg, selector string) []string {
	return []string{"test", "-p", "1", "-json", "-mod=readonly", "-count=1", "-timeout=300s", pkg, "-run", selector}
}

func validatedNodeRoot(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(filepath.Join(absolute, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("node-root module unavailable: %w", err)
	}
	modules := 0
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(strings.SplitN(line, "//", 2)[0])
		if len(fields) == 0 || fields[0] != "module" {
			continue
		}
		if len(fields) != 2 || fields[1] != nodeModule {
			return "", errors.New("node-root module identity mismatch")
		}
		modules++
	}
	if modules != 1 {
		return "", errors.New("node-root module identity missing or ambiguous")
	}
	return absolute, nil
}

func runRegistry(root, nodeRoot, only string, pure bool, r registry, run testRunner) (report, error) {
	out := report{Contract: r.Contract, Status: "PASS", Vectors: []result{}}
	// Refuse malformed package identities before launching any subprocess.
	for _, v := range r.Vectors {
		for _, tc := range v.Tests {
			_, runtime := runtimePackages[tc.Package]
			if (!purePackages[tc.Package] && !runtime) || !strings.HasPrefix(tc.Run, "^Test") {
				return out, errors.New("invalid test registry")
			}
		}
	}
	if !pure && nodeRoot != "" {
		var err error
		nodeRoot, err = validatedNodeRoot(nodeRoot)
		if err != nil {
			return out, err
		}
	}
	matched := false
	for _, v := range r.Vectors {
		if only != "" && only != v.ID {
			continue
		}
		matched = true
		x := result{ID: v.ID, Status: "PASS", AdapterRequired: v.AdapterRequired}
		for _, tc := range v.Tests {
			if _, runtime := runtimePackages[tc.Package]; runtime {
				x.RuntimeTests = append(x.RuntimeTests, runtimeResult{Package: tc.Package, Run: tc.Run, Status: "NOT_RUN"})
			}
		}
		runtimeIndex := 0
		for _, tc := range v.Tests {
			pkg, runtime := runtimePackages[tc.Package]
			directory := root
			if runtime {
				i := runtimeIndex
				runtimeIndex++
				if pure || nodeRoot == "" || x.Status == "FAIL" {
					continue
				}
				directory = nodeRoot
				outcome := run(directory, pkg, tc.Run)
				if outcome.Status != "PASS" && outcome.Status != "NOT_RUN" {
					outcome.Status = "FAIL"
				}
				x.RuntimeTests[i].Status, x.RuntimeTests[i].Error = outcome.Status, outcome.Error
				if outcome.Status == "FAIL" {
					x.Status, x.Error = "FAIL", outcome.Error
				} else if outcome.Status == "NOT_RUN" {
					x.Status, x.Error = "INCOMPLETE", outcome.Error
				}
				continue
			}
			if x.Status == "FAIL" {
				continue
			}
			outcome := run(directory, tc.Package, tc.Run)
			if outcome.Status == "PASS" {
				x.PureTests++
			} else if outcome.Status == "NOT_RUN" {
				x.Status, x.Error = "INCOMPLETE", outcome.Error
			} else {
				x.Status, x.Error = "FAIL", outcome.Error
			}
		}
		if x.Status != "FAIL" {
			if len(v.AdapterRequired) > 0 {
				x.Status = "INCOMPLETE"
			}
			for _, tc := range x.RuntimeTests {
				if tc.Status == "NOT_RUN" {
					x.Status = "INCOMPLETE"
				}
			}
		}
		if x.Status == "FAIL" {
			out.Status = "FAIL"
		} else if x.Status == "INCOMPLETE" && out.Status != "FAIL" {
			out.Status = "INCOMPLETE"
		}
		out.Vectors = append(out.Vectors, x)
	}
	if !matched {
		return out, errors.New("unknown vector")
	}
	return out, nil
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
