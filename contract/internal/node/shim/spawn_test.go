package shim

import (
	"context"
	"errors"
	"fmt"
	"github.com/Telara-Labs/hilo/contract/internal/node/install"
	"github.com/Telara-Labs/hilo/contract/internal/node/ipc"
	"os"
	"testing"
)

func TestManagedSpawnReceiptAndIntent(t *testing.T) {
	p := ipc.Paths{Data: "data", Run: "run"}
	good := install.Report{State: "registered", Record: install.Record{DataDir: p.Data, RunDir: p.Run}}
	for _, tc := range []struct {
		name                string
		report              install.Report
		statusErr, startErr error
		want                string
		calls               int
	}{
		{"verified", good, nil, nil, "", 1},
		{"stopped", good, nil, install.ErrStopped, "autostart_stopped", 1},
		{"unavailable", good, install.ErrUnavailable, nil, "autostart_unavailable", 0},
		{"start-unavailable", good, nil, install.ErrUnavailable, "autostart_unavailable", 1},
		{"unsafe", good, install.ErrUnsafe, nil, "autostart_unverified_install", 0},
		{"unverified", good, install.ErrUnverified, nil, "autostart_unverified_install", 0},
		{"missing", install.Report{}, os.ErrNotExist, nil, "autostart_unverified_install", 0},
		{"mismatch-data", install.Report{Record: install.Record{DataDir: "other", RunDir: p.Run}}, nil, nil, "autostart_unverified_install", 0},
		{"mismatch-run", install.Report{Record: install.Record{DataDir: p.Data, RunDir: "other"}}, nil, nil, "autostart_unverified_install", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := spawnManaged(context.Background(), p, "install", func(ctx context.Context, dir string) (install.Report, error) { return tc.report, tc.statusErr }, func(ctx context.Context, dir string) error { calls++; return tc.startErr })
			got := ""
			if err != nil {
				got = autostartCode(err)
			}
			if got != tc.want || calls != tc.calls {
				t.Fatalf("%s calls %d", got, calls)
			}
		})
	}
	for _, err := range []error{fmt.Errorf("wrapped %w", install.ErrStopped), fmt.Errorf("wrapped %w", install.ErrUnavailable)} {
		if autostartCode(err) == "daemon_unavailable" {
			t.Fatal("lost distinct error")
		}
	}
	if autostartCode(errors.New("secret")) != "daemon_unavailable" {
		t.Fatal("raw diagnostic")
	}
}
