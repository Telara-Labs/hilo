//go:build linux || darwin

package capture

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

func TestCollectorUnitPendingIdentityBeforeCapture(t *testing.T) {
	for _, state := range []string{"absent", "growing", "partial-line", "empty"} {
		t.Run(state, func(t *testing.T) {
			f := runtimeWorld(t, sourceMessages(t, 1, -1, ""))
			fake := &unitSignalStore{st: f.s, done: map[string]bool{}}
			f.p.signals = fake
			c, err := NewCollector(f.p, filepath.Join(f.c.Home, "synthetic-node"))
			if err != nil {
				t.Fatal(err)
			}
			switch state {
			case "absent":
				if err = os.Remove(f.path); err != nil {
					t.Fatal(err)
				}
			case "growing":
				if err = os.WriteFile(f.path, []byte(`{"type":`), 0600); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err = os.WriteFile(f.path, nil, 0600); err != nil {
					t.Fatal(err)
				}
				quietSource()
			case "partial-line":
				if err = os.WriteFile(f.path, []byte(`{"type":`), 0600); err != nil {
					t.Fatal(err)
				}
				quietSource()
			}
			h := transport.HookSignal{V: 3, At: 1, Client: "claude", Event: "SessionStart", NativeSession: syntheticSession, TranscriptPath: f.path, HookPID: os.Getpid()}
			raw, _ := json.Marshal(h)
			path := spoolFile(t, c, "new", testSignalULID+".json", raw)
			if err = c.Drain(context.Background(), "credential"); err != nil {
				t.Fatal("pending identity blocked drain", err)
			}
			if len(fake.observed) != 1 || len(fake.order) != 0 || c.Stats().Done != 0 {
				t.Fatal("pending capture ACKed or identity not processed")
			}
			if _, err = os.Stat(path); err != nil {
				t.Fatal("pending hint lost", err)
			}
			if records, _ := runtimeSnapshot(t, f.s); len(records) != 1 {
				t.Fatal("pending capture admitted output")
			}
			fake.fail = true
			if err = c.Drain(context.Background(), "credential"); Code(err) != "spool_admission_failed" {
				t.Fatal("pending identity store failure bypassed", err)
			}
			fake.fail = false
			if err = os.WriteFile(f.path, sourceMessages(t, 1, -1, ""), 0600); err != nil {
				t.Fatal(err)
			}
			quietSource()
			// The original nonterminal hint is retried on a later drain, even
			// without a terminal signal. The real SQLite producer admits output.
			if err = c.Drain(context.Background(), "credential"); err != nil {
				t.Fatal(err)
			}
			if len(fake.order) != 1 || c.Stats().Done != 1 {
				t.Fatal("settled pending signal not captured")
			}
			if _, err = os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("captured hint retained", err)
			}
		})
	}
}

func TestCollectorPendingDoesNotHideHostilePath(t *testing.T) {
	for _, state := range []string{"symlink", "public-file", "public-root", "session-mismatch"} {
		t.Run(state, func(t *testing.T) {
			f := runtimeWorld(t, []byte(`{"type":`))
			fake := &unitSignalStore{st: f.s, done: map[string]bool{}}
			f.p.signals = fake
			c, err := NewCollector(f.p, filepath.Join(f.c.Home, "synthetic-node"))
			if err != nil {
				t.Fatal(err)
			}
			h := transport.HookSignal{V: 3, At: 1, Client: "claude", Event: "SessionStart", NativeSession: syntheticSession, TranscriptPath: f.path, HookPID: os.Getpid()}
			switch state {
			case "symlink":
				if err = os.Rename(f.path, f.path+".original"); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(f.path+".original", f.path); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err = os.Chmod(f.path, 0644); err != nil {
					t.Fatal(err)
				}
			case "public-root":
				if err = os.Chmod(filepath.Dir(f.path), 0755); err != nil {
					t.Fatal(err)
				}
			case "session-mismatch":
				h.NativeSession = "11111111-1111-4111-8111-111111111111"
			}
			raw, _ := json.Marshal(h)
			spoolFile(t, c, "new", testSignalULID+".json", raw)
			if err = c.Drain(context.Background(), "credential"); err == nil {
				t.Fatal("hostile signal allowed")
			}
			if len(fake.observed) != 0 || c.Stats().Done != 0 {
				t.Fatal("hostile hint processed as pending identity")
			}
		})
	}
}

func TestFrameLiveGrowthVersusPathReplacement(t *testing.T) {
	for _, replace := range []bool{false, true} {
		f := runtimeWorld(t, sourceMessages(t, 1, -1, ""))
		h, err := openUnit(filepath.Dir(f.path), filepath.Base(f.path))
		if err != nil {
			t.Fatal(err)
		}
		err = frameUnit(context.Background(), h, func(_ int, _ []byte) error {
			if replace {
				if e := os.Rename(f.path, f.path+".old"); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(f.path, []byte("{}\n"), 0600); e != nil {
					t.Fatal(e)
				}
			} else {
				file, e := os.OpenFile(f.path, os.O_APPEND|os.O_WRONLY, 0)
				if e != nil {
					t.Fatal(e)
				}
				_, e = file.WriteString(`{"unfinished":`)
				file.Close()
				if e != nil {
					t.Fatal(e)
				}
			}
			return nil
		})
		want := "source_unsettled"
		if replace {
			want = "source_changed"
		}
		if Code(err) != want {
			t.Fatalf("replace %v expected %s got %v", replace, want, err)
		}
		h.close()
	}
}

func TestCollectorPendingRequiresObservationSupport(t *testing.T) {
	c := testCollector(t)
	// Retain all real receipt/capture methods but deliberately hide ObserveSignal.
	c.pipeline.signals = struct{ SignalStore }{c.pipeline.signals}
	h := transport.HookSignal{V: 3, At: 1, Client: "claude", Event: "SessionStart", NativeSession: syntheticSession, TranscriptPath: filepath.Join(c.pipeline.config.Roots["fixture"].AbsPath, syntheticSession+".jsonl"), HookPID: os.Getpid()}
	raw, _ := json.Marshal(h)
	path := spoolFile(t, c, "new", testSignalULID+".json", raw)
	if err := c.Drain(context.Background(), "credential"); Code(err) != "spool_observation_unavailable" {
		t.Fatal("missing identity processor bypassed", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("unobserved hint lost", err)
	}
}

type mutatingUnitSignalStore struct {
	*unitSignalStore
	mutate func()
}

func (s *mutatingUnitSignalStore) CaptureSignal(ctx context.Context, h transport.HookSignal, id string, q store.CaptureRequest, produce func(*store.CaptureTxn) (store.CommitPlan, error)) (store.CaptureReceipt, error) {
	s.mutate()
	return s.unitSignalStore.CaptureSignal(ctx, h, id, q, produce)
}

func TestCollectorMutationAtCaptureWriter(t *testing.T) {
	for _, scenario := range []string{"growth", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			f := runtimeWorld(t, sourceMessages(t, 1, -1, ""))
			base := &unitSignalStore{st: f.s, done: map[string]bool{}}
			f.p.signals = &mutatingUnitSignalStore{base, func() {
				if scenario == "growth" {
					file, err := os.OpenFile(f.path, os.O_APPEND|os.O_WRONLY, 0)
					if err != nil {
						t.Fatal(err)
					}
					_, err = file.WriteString(`{"type":`)
					file.Close()
					if err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Rename(f.path, f.path+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(f.path, sourceMessages(t, 1, -1, ""), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}}
			c, err := NewCollector(f.p, filepath.Join(f.c.Home, "synthetic-node"))
			if err != nil {
				t.Fatal(err)
			}
			h := transport.HookSignal{V: 3, At: 1, Client: "claude", Event: "Stop", NativeSession: syntheticSession, TranscriptPath: f.path, HookPID: os.Getpid()}
			raw, _ := json.Marshal(h)
			spoolFile(t, c, "new", testSignalULID+".json", raw)
			quietSource()
			err = c.Drain(context.Background(), "credential")
			if scenario == "growth" {
				if err != nil || len(base.observed) != 1 {
					t.Fatal("live writer refused or not observed", err)
				}
			} else if Code(err) != "producer_refused" || len(base.observed) != 0 {
				t.Fatal("replaced source softened into pending", err)
			}
			if records, _ := runtimeSnapshot(t, f.s); len(records) != 1 || c.Stats().Done != 0 {
				t.Fatal("unstable source admitted records/ACK")
			}
		})
	}
}
