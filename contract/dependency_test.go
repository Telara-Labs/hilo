package contract_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Package discovery and test dependencies must remain inside the pure boundary,
// including the conformance command and standard-library release verifier.
func TestPurePackageDependencyBoundary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("list packages failed %v\n%s", err, out)
	}
	const prefix = "github.com/Telara-Labs/telara-memory/contract"
	packages := strings.Fields(string(out))
	seen := map[string]bool{}
	for _, p := range packages {
		if p != prefix && !strings.HasPrefix(p, prefix+"/") {
			t.Fatalf("foreign pure package %s", p)
		}
		if strings.HasPrefix(p, prefix+"/internal/node") {
			t.Fatalf("runtime module discovered in pure inventory %s", p)
		}
		seen[p] = true
	}
	for _, required := range []string{prefix, prefix + "/cmd/conformance", prefix + "/releaseauth"} {
		if !seen[required] {
			t.Fatalf("pure inventory omitted %s", required)
		}
	}
	// -test includes each pure package's own test dependency closure. No cmd
	// exclusion can conceal a future runtime import in the conformance runner.
	args := append([]string{"list", "-mod=readonly", "-deps", "-test"}, packages...)
	out, err = exec.CommandContext(ctx, "go", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("list test dependencies failed %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasPrefix(dep, prefix+"/internal/node") || strings.HasPrefix(dep, "modernc.org/") || dep == "database/sql" || dep == "database/sql/driver" || dep == "net/http" {
			t.Errorf("pure package or test depends on runtime adapter %s", dep)
		}
	}
}
