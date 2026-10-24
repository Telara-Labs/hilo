//go:build linux || darwin

package capture

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

const testSignalULID = "01JAZZZZZZ0000000000000000"

func spoolFile(t *testing.T, c *Collector, sub, name string, b []byte) string {
	t.Helper()
	dir := filepath.Join(c.dir, "spool", "claude", sub)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func testCollector(t *testing.T) *Collector {
	t.Helper()
	f := runtimeWorld(t, sourceMessages(t, 1, -1, ""))
	c, err := NewCollector(f.p, filepath.Join(f.c.Home, "synthetic-node"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestSignalULIDValidation(t *testing.T) {
	for _, s := range []string{testSignalULID, "00000000000000000000000000", "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"} {
		if !signalID(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"", testSignalULID + "x", "8ZZZZZZZZZZZZZZZZZZZZZZZZZ", "01JAZZZZZZ000000000000000i", "../"} {
		if signalID(s) {
			t.Fatal(s)
		}
	}
}
func TestCollectorDropsMalformedAndAbandonsOnlyOldTmp(t *testing.T) {
	c := testCollector(t)
	for i, b := range [][]byte{[]byte("{"), []byte(`{"v":3,"final_text":"must never archive"}`), []byte(strings.Repeat("x", (16<<10)+1))} {
		spoolFile(t, c, "new", testSignalULID[:25]+string(rune('1'+i))+".json", b)
	}
	spoolFile(t, c, "new", "not-a-ulid.json", []byte("{}"))
	old := spoolFile(t, c, "tmp", "old.json", []byte("unfinished"))
	now := spoolFile(t, c, "tmp", "new.json", []byte("unfinished"))
	earlier := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, earlier, earlier); err != nil {
		t.Fatal(err)
	}
	if err := c.Drain(context.Background(), "credential"); err != nil {
		t.Fatal(err)
	}
	stats := c.Stats()
	if stats.Dropped != 4 || stats.Abandoned != 1 || stats.Done != 0 {
		t.Fatal(stats)
	}
	if _, err := os.Lstat(now); err != nil {
		t.Fatal("active tmp consumed", err)
	}
	names, err := os.ReadDir(filepath.Dir(old))
	if err != nil || len(names) != 1 {
		t.Fatal("abandoned cleanup", err)
	}
	newNames, err := os.ReadDir(filepath.Join(c.dir, "spool", "claude", "new"))
	if err != nil || len(newNames) != 0 {
		t.Fatal("malformed archive retained", err)
	}
	if err := c.Drain(context.Background(), "credential"); err != nil || c.Stats() != stats {
		t.Fatal("cleanup not idempotent", err)
	}
}
func TestCollectorRetainsValidSignalWhenAtomicStoreSeamMissing(t *testing.T) {
	c := testCollector(t)
	if c.pipeline.signals != nil {
		t.Skip("store seam implemented; positive integration supersedes this negative gate")
	}
	// No transcript path means no source bytes need be opened to retain a valid
	// identity hint. The production SQLite API must still atomically admit it.
	signal := transport.HookSignal{V: 3, At: 1, Client: "claude", Event: "SessionStart", NativeSession: syntheticSession, HookPID: os.Getpid()}
	raw, _ := json.Marshal(signal)
	path := spoolFile(t, c, "new", testSignalULID+".json", raw)
	err := c.Drain(context.Background(), "credential")
	if Code(err) != "spool_receipts_unavailable" {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("unadmitted signal lost", err)
	}
	if c.Stats().Done != 0 {
		t.Fatal("false ACK")
	}
}
func TestCollectorRejectsUnsafeSpoolAndCancellation(t *testing.T) {
	for _, which := range []string{"symlink-dir", "symlink-file", "public-dir", "public-file", "hardlink"} {
		t.Run(which, func(t *testing.T) {
			c := testCollector(t)
			p := spoolFile(t, c, "new", testSignalULID+".json", []byte("{}"))
			switch which {
			case "symlink-dir":
				dir := filepath.Dir(p)
				if err := os.Rename(dir, dir+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+"-old", dir); err != nil {
					t.Fatal(err)
				}
			case "symlink-file":
				if err := os.Rename(p, p+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p+"-old", p); err != nil {
					t.Fatal(err)
				}
			case "public-dir":
				if err := os.Chmod(filepath.Dir(p), 0755); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.Chmod(p, 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(p, p+"-link"); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Drain(context.Background(), "credential"); err == nil || strings.Contains(err.Error(), c.dir) {
				t.Fatal("unsafe spool accepted or path leaked", err)
			}
		})
	}
	c := testCollector(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Drain(ctx, "credential"); err == nil {
		t.Fatal("cancelled drain")
	}
	if err := c.Drain(context.Background(), ""); err == nil {
		t.Fatal("empty credential")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Drain(context.Background(), "credential"); Code(err) != "closed" {
		t.Fatal(err)
	}
}
func TestSignalDirectoryBindingRejectsReplacement(t *testing.T) {
	c := testCollector(t)
	p := spoolFile(t, c, "new", testSignalULID+".json", []byte("{}"))
	d, err := openSignalDirectory(c.dir, filepath.Join("spool", "claude", "new"))
	if err != nil || d == nil {
		t.Fatal(err)
	}
	defer d.close()
	dir := filepath.Dir(p)
	if err := os.Rename(dir, dir+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.names(); err == nil {
		t.Fatal("replaced spool binding accepted")
	}
	if err := d.remove(filepath.Base(p)); err == nil {
		t.Fatal("deleted from detached directory")
	}
}

// Unit-only receipt fake exercises collector ordering and failure interleavings.
// Capture itself still runs the real SQLite producer. This fake is deliberately
// NOT used by any integration test and proves no same-transaction durability.
type unitSignalStore struct {
	st    *store.Store
	done  map[string]bool
	order []string
	fail  bool
}

func (s *unitSignalStore) SignalDone(_ context.Context, client, ulid string) (bool, error) {
	return s.done[client+"/"+ulid], nil
}
func (s *unitSignalStore) AdmitSignal(_ context.Context, h transport.HookSignal, ulid string) error {
	if s.fail {
		return hold("unit_admission_failure")
	}
	s.done[h.Client+"/"+ulid] = true
	s.order = append(s.order, ulid)
	return nil
}
func (s *unitSignalStore) CaptureSignal(ctx context.Context, h transport.HookSignal, ulid string, q store.CaptureRequest, produce func(*store.CaptureTxn) (store.CommitPlan, error)) (store.CaptureReceipt, error) {
	if s.fail {
		return store.CaptureReceipt{}, hold("unit_admission_failure")
	}
	receipt, err := s.st.Capture(ctx, q, produce)
	if err == nil {
		s.done[h.Client+"/"+ulid] = true
		s.order = append(s.order, ulid)
	}
	return receipt, err
}
func TestCollectorUnitOrderingFailureAndAlreadyDoneRecovery(t *testing.T) {
	c := testCollector(t)
	fake := &unitSignalStore{st: c.pipeline.store, done: map[string]bool{}}
	c.pipeline.signals = fake
	h := transport.HookSignal{V: 3, At: 1, Client: "claude", Event: "SessionStart", NativeSession: syntheticSession, HookPID: os.Getpid()}
	raw, _ := json.Marshal(h)
	first := testSignalULID[:25] + "1"
	last := testSignalULID[:25] + "9"
	// Publish reverse order. An old signal's timestamp does not exclude it.
	spoolFile(t, c, "new", last+".json", raw)
	spoolFile(t, c, "new", first+".json", raw)
	fake.fail = true
	if err := c.Drain(context.Background(), "credential"); err == nil || c.Stats().Done != 0 {
		t.Fatal("failed admission ACKed")
	}
	fake.fail = false
	if err := c.Drain(context.Background(), "credential"); err != nil {
		t.Fatal(err)
	}
	if len(fake.order) != 2 || fake.order[0] != first || fake.order[1] != last {
		t.Fatal("ULID ordering", fake.order)
	}
	// Model commit-before-unlink. Source does not exist and raw hint is malformed;
	// durable receipt lookup must win without reparse/recapture after restart.
	fake.done["claude/"+testSignalULID] = true
	p := spoolFile(t, c, "new", testSignalULID+".json", []byte("malformed no source"))
	if err := c.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatal("committed signal not recovered")
	}
	if len(fake.order) != 2 || c.Stats().Done != 3 {
		t.Fatal("recovered signal repeated admission")
	}
}
func TestCollectorUnitTranscriptCaptureAndCrashBeforeUnlink(t *testing.T) {
	f := runtimeWorld(t, sourceMessages(t, 1, -1, ""))
	fake := &unitSignalStore{st: f.s, done: map[string]bool{}}
	f.p.signals = fake
	c, err := NewCollector(f.p, filepath.Join(f.c.Home, "synthetic-node"))
	if err != nil {
		t.Fatal(err)
	}
	h := transport.HookSignal{V: 3, At: 1, Client: "claude", Event: "Stop", NativeSession: syntheticSession, TranscriptPath: f.path, HookPID: os.Getpid()}
	raw, _ := json.Marshal(h)
	spoolFile(t, c, "new", testSignalULID+".json", raw)
	quietSource()
	if err := c.Drain(context.Background(), "credential"); err != nil {
		t.Fatal(err)
	}
	records, _ := runtimeSnapshot(t, f.s)
	if len(records) != 3 || len(fake.order) != 1 {
		t.Fatal("real producer not invoked")
	}
	// Recreate only the content-free hint, then remove its external transcript.
	// Recovery has to unlink from the receipt without opening that transcript.
	spoolFile(t, c, "new", testSignalULID+".json", raw)
	if err := os.Remove(f.path); err != nil {
		t.Fatal(err)
	}
	if err := c.Drain(context.Background(), "credential"); err != nil {
		t.Fatal(err)
	}
	if len(fake.order) != 1 {
		t.Fatal("receipt replay recaptured")
	}
}
func TestCollectorUnitSignalSessionMismatch(t *testing.T) {
	f := runtimeWorld(t, sourceMessages(t, 1, -1, ""))
	f.p.signals = &unitSignalStore{st: f.s, done: map[string]bool{}}
	c, err := NewCollector(f.p, filepath.Join(f.c.Home, "synthetic-node"))
	if err != nil {
		t.Fatal(err)
	}
	h := transport.HookSignal{V: 3, At: 1, Client: "claude", Event: "Stop", NativeSession: "11111111-1111-4111-8111-111111111111", TranscriptPath: f.path, HookPID: os.Getpid()}
	raw, _ := json.Marshal(h)
	spoolFile(t, c, "new", testSignalULID+".json", raw)
	if err := c.Drain(context.Background(), "credential"); Code(err) != "signal_session_mismatch" {
		t.Fatal(err)
	}
	records, _ := runtimeSnapshot(t, f.s)
	if len(records) != 1 {
		t.Fatal("mismatched signal captured")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Recover(ctx); err == nil {
		t.Fatal("cancelled recovery")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Recover(context.Background()); Code(err) != "closed" {
		t.Fatal(err)
	}
}
