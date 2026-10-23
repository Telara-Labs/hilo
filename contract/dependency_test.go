package contract_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Pure consumers must not compile runtime adapters, even while private
// development temporarily shares module dependency metadata.
func TestPurePackageDependencyBoundary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "go", "list", "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("list packages failed %v\n%s", err, out)
	}
	const prefix = "github.com/Telara-Labs/telara-memory/contract"
	args := []string{"list", "-deps"}
	for _, p := range strings.Fields(string(out)) {
		if p == prefix || strings.HasPrefix(p, prefix+"/") && !strings.HasPrefix(p, prefix+"/internal/node/") && p != prefix+"/internal/node" && !strings.HasPrefix(p, prefix+"/cmd/") {
			args = append(args, p)
		}
	}
	if len(args) == 2 {
		t.Fatal("pure package inventory is empty")
	}
	out, err = exec.CommandContext(ctx, "go", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("list dependencies failed %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasPrefix(dep, prefix+"/internal/node") || strings.HasPrefix(dep, "modernc.org/") || dep == "database/sql" || dep == "database/sql/driver" || dep == "net/http" {
			t.Errorf("pure package depends on runtime adapter %s", dep)
		}
	}
}
