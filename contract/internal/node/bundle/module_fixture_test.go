package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contractdata "github.com/Telara-Labs/telara-memory/contract"
)

const pureModulePath = "github.com/Telara-Labs/telara-memory/contract"

type pureModule struct {
	Path, Version, Dir string
	Main               bool
	Replace            *json.RawMessage
	Error              *struct{ Err string }
}

type pureModuleQuery func(string) ([]byte, error)

func queryPureModule(root string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-m", "-json", pureModulePath)
	cmd.Dir = root
	return cmd.CombinedOutput()
}

func requiredPureVersion(raw []byte) (string, error) {
	version, requirements := "", 0
	inRequire := false
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(strings.SplitN(line, "//", 2)[0])
		if len(f) == 0 {
			continue
		}
		if f[0] == "replace" {
			return "", errors.New("fixture module replacements refused")
		}
		if f[0] == "require" {
			if len(f) == 2 && f[1] == "(" {
				inRequire = true
				continue
			}
			f = f[1:]
		} else if !inRequire {
			continue
		}
		if len(f) == 1 && f[0] == ")" {
			inRequire = false
			continue
		}
		if len(f) > 0 && f[0] == pureModulePath {
			if len(f) != 2 {
				return "", errors.New("invalid pure fixture requirement")
			}
			version = f[1]
			requirements++
		}
	}
	if requirements != 1 || version == "" {
		return "", errors.New("exact published pure fixture requirement unavailable")
	}
	return version, nil
}

// Resolve only the node module's exact required dependency. Never search an
// ancestor checkout, substitute local files or regenerate the canonical oracle.
func readPinnedPureFixture(nodeRoot string, query pureModuleQuery) ([]byte, error) {
	mod, err := os.ReadFile(filepath.Join(nodeRoot, "go.mod"))
	if err != nil {
		return nil, err
	}
	version, err := requiredPureVersion(mod)
	if err != nil {
		return nil, err
	}
	data, err := query(nodeRoot)
	if err != nil {
		return nil, fmt.Errorf("pure fixture module lookup failed: %w", err)
	}
	var m pureModule
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.Path != pureModulePath || m.Version != version || m.Main || m.Replace != nil || m.Error != nil || !filepath.IsAbs(m.Dir) {
		return nil, errors.New("pure fixture module identity or version mismatch")
	}
	registry := contractdata.ConformanceRegistry()
	registrySum := sha256.Sum256(registry)
	if hex.EncodeToString(registrySum[:]) != contractdata.ConformanceRegistryDigest {
		return nil, errors.New("fixture registry digest mismatch")
	}
	var pins struct {
		FixtureDigests map[string]string `json:"fixture_digests"`
	}
	if err := json.Unmarshal(registry, &pins); err != nil {
		return nil, err
	}
	want := pins.FixtureDigests["v20-exposures.json"]
	if len(want) != 64 {
		return nil, errors.New("fixture digest absent from registry")
	}
	raw, err := os.ReadFile(filepath.Join(m.Dir, "testdata", "v20-exposures.json"))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != want {
		return nil, errors.New("pure module fixture digest mismatch")
	}
	return raw, nil
}

func TestPureFixtureRequirementComesOnlyFromNodeModule(t *testing.T) {
	for _, raw := range []string{
		"require " + pureModulePath + " v1.2.3\n",
		"require (\n\t" + pureModulePath + " v1.2.3 // indirect\n)\n",
	} {
		if got, err := requiredPureVersion([]byte(raw)); err != nil || got != "v1.2.3" {
			t.Fatal(got, err)
		}
	}
	for _, raw := range []string{"", "require (\nother/module v1.2.3\n)\n", "require " + pureModulePath + " v1.2.3\nrequire " + pureModulePath + " v1.2.3\n", "require " + pureModulePath + " v1.2.3\nreplace other/module => ../local\n"} {
		if _, err := requiredPureVersion([]byte(raw)); err == nil {
			t.Fatal("accepted unavailable/ambiguous/replaced dependency", raw)
		}
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module runtime\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPinnedPureFixture(root, func(string) ([]byte, error) { t.Fatal("unpublished dependency launched lookup"); return nil, nil }); err == nil {
		t.Fatal("missing pure pin accepted")
	}
}

func TestPinnedPureFixtureRejectsUnboundModuleOrFixture(t *testing.T) {
	root, dep := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("require "+pureModulePath+" v1.2.3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wrong-path", "wrong-version", "main", "replace", "relative-dir", "lookup-error", "missing-fixture", "changed-fixture"} {
		t.Run(name, func(t *testing.T) {
			m := pureModule{Path: pureModulePath, Version: "v1.2.3", Dir: dep}
			switch name {
			case "wrong-path":
				m.Path = pureModulePath + "/internal/node"
			case "wrong-version":
				m.Version = "v1.2.4"
			case "main":
				m.Main = true
			case "replace":
				raw := json.RawMessage(`{"Dir":"/local"}`)
				m.Replace = &raw
			case "relative-dir":
				m.Dir = "../contract"
			case "changed-fixture":
				if err := os.MkdirAll(filepath.Join(dep, "testdata"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dep, "testdata", "v20-exposures.json"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			query := func(got string) ([]byte, error) {
				if got != root {
					t.Fatal("lookup escaped explicit node root")
				}
				if name == "lookup-error" {
					return nil, errors.New("unavailable")
				}
				return json.Marshal(m)
			}
			if _, err := readPinnedPureFixture(root, query); err == nil {
				t.Fatal("unbound fixture accepted", name)
			}
		})
	}
}
