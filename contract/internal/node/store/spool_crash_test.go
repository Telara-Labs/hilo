package store

import (
	"bufio"
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"modernc.org/sqlite"
)

type spoolCrashInput struct {
	Options Options
	Request CaptureRequest
	Plan    CommitPlan
}

// A test-only SQLite trigger stops the actual public CaptureSignal transaction
// after announcement or spool_done insertion. The parent sends SIGKILL; no
// production hook, alternate transaction path, shell, or environment flag exists.
func TestSpoolCrashChild(t *testing.T) {
	var mode, path string
	for i, arg := range os.Args {
		if arg == "--spool-crash" && i+2 < len(os.Args) {
			mode, path = os.Args[i+1], os.Args[i+2]
		}
	}
	if mode == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var in spoolCrashInput
	if json.Unmarshal(raw, &in) != nil {
		t.Fatal("invalid crash input")
	}
	checkpoint := func() { fmt.Println("SPOOL_CHECKPOINT"); var b [1]byte; _, _ = os.Stdin.Read(b[:]); os.Exit(19) }
	if err = sqlite.RegisterScalarFunction("spool_test_checkpoint", 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) { checkpoint(); return nil, nil }); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), in.Options)
	if err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "announcement", "done":
		table := "spool_announcement"
		if mode == "done" {
			table = "spool_done"
		}
		if _, err = s.conn.ExecContext(context.Background(), "CREATE TRIGGER spool_kill AFTER INSERT ON "+table+" BEGIN SELECT spool_test_checkpoint(); END"); err != nil {
			t.Fatal(err)
		}
	case "committed":
	default:
		t.Fatal("unknown mode")
	}
	if _, err = s.CaptureSignal(context.Background(), spoolTestHint(), spoolTestID, in.Request, func(*CaptureTxn) (CommitPlan, error) { return in.Plan, nil }); err != nil {
		t.Fatal(err)
	}
	if mode != "committed" {
		t.Fatal("checkpoint not reached")
	}
	checkpoint()
}
func TestSpoolKillAtomicityAndRestartDrainExactlyOnce(t *testing.T) {
	for _, mode := range []string{"announcement", "done", "committed"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := newProducer(t, "synthetic source crash canary")
			baseline := len(f.w.snapshot().Entries)
			raw, err := json.Marshal(spoolCrashInput{f.w.o, f.q, f.plan})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.w.o.Dir, "spool-crash-input.json")
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err = f.w.s.Close(); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestSpoolCrashChild$", "--", "--spool-crash", mode, path)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			ready := make(chan bool, 1)
			go func() {
				scan := bufio.NewScanner(stdout)
				for scan.Scan() {
					if strings.TrimSpace(scan.Text()) == "SPOOL_CHECKPOINT" {
						ready <- true
						return
					}
				}
				ready <- false
			}()
			select {
			case found := <-ready:
				if !found {
					t.Fatalf("child failed before checkpoint %s", stderr.String())
				}
			case <-time.After(30 * time.Second):
				t.Fatal("crash checkpoint timeout")
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err = cmd.Wait(); err == nil {
				t.Fatal("child was not killed")
			}
			s, err := Open(ctx, f.w.o)
			if err != nil {
				t.Fatal(err)
			}
			f.w.s = s
			if _, err = s.conn.ExecContext(ctx, "DROP TRIGGER IF EXISTS spool_kill"); err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "committed" {
				want = 1
			}
			for _, table := range []string{"spool_announcement", "spool_done", "spool_process", "capture_transition", "capture_progress"} {
				if n := spoolCount(t, s, table); n != want {
					t.Fatal("crash split", mode, table, n, want)
				}
			}
			if n := len(f.w.snapshot().Entries); n != baseline+want*2 {
				t.Fatal("partial output after kill", n)
			}
			calls := 0
			// The collector's receipt-first drain rule on two consecutive restarts.
			for i := 0; i < 2; i++ {
				done, err := f.w.s.SignalDone(ctx, "claude", spoolTestID)
				if err != nil {
					t.Fatal(err)
				}
				if !done {
					if _, err = f.w.s.CaptureSignal(ctx, spoolTestHint(), spoolTestID, f.q, func(*CaptureTxn) (CommitPlan, error) { calls++; return f.plan, nil }); err != nil {
						t.Fatal(err)
					}
				}
				spoolReopen(t, f.w)
			}
			if calls != 1-want || spoolCount(t, f.w.s, "spool_done") != 1 || spoolCount(t, f.w.s, "capture_transition") != 1 || len(f.w.snapshot().Entries) != baseline+2 {
				t.Fatal("restart admitted more than once", calls)
			}
		})
	}
}
