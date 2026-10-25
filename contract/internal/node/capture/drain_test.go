//go:build linux || darwin

package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// Every fixed code the capture package can return, and every store code
// storeFailure passes through, has an explicit drain class. The list is
// derived from the source, so a new code fails this test until classified.
func TestDrainClassesCoverEveryCode(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]bool{}
	literal := regexp.MustCompile(`hold\("([a-z_]+)"\)`)
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range literal.FindAllSubmatch(b, -1) {
			codes[string(m[1])] = true
		}
		if name == "pipeline.go" {
			// storeFailure forwards these store codes by name.
			start := bytes.Index(b, []byte("func storeFailure("))
			end := bytes.Index(b[start:], []byte("\n}\n"))
			for _, m := range regexp.MustCompile(`"([a-z_]+)"`).FindAllSubmatch(b[start:start+end], -1) {
				codes[string(m[1])] = true
			}
		}
	}
	if len(codes) < 50 {
		t.Fatal("code derivation found too few codes", len(codes))
	}
	for code := range codes {
		if _, ok := drainClasses[code]; !ok {
			t.Errorf("code %q has no explicit drain class", code)
		}
	}
	// The default for an unknown code is fatal, never a silent skip.
	if class, _ := classify(hold("never_classified_code")); class != drainFatal {
		t.Fatal("unknown code not fatal")
	}
	// A producer refusal is classified by its fixed local cause.
	if class, code := classify(&Error{code: "producer_refused", cause: "plan_limit"}); class != drainGap || code != "plan_limit" {
		t.Fatal("producer cause ignored", class, code)
	}
}

func hookSignal(native, path string) []byte {
	raw, _ := json.Marshal(transport.HookSignal{V: 3, At: 1, Client: "claude", Event: "Stop", NativeSession: native, TranscriptPath: path, HookPID: os.Getpid()})
	return raw
}

func spoolNew(t *testing.T, c *Collector) int {
	t.Helper()
	names, err := os.ReadDir(filepath.Join(c.dir, "spool", "claude", "new"))
	if err != nil {
		t.Fatal(err)
	}
	return len(names)
}

func storeDB(t *testing.T, f *runtimeFixture) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(f.c.Home, "synthetic-node", "memory.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func announced(t *testing.T, f *runtimeFixture, ulid string) bool {
	t.Helper()
	var n int
	if err := storeDB(t, f).QueryRow("SELECT count(*) FROM spool_announcement WHERE client='claude' AND ulid=?", ulid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// Uncovered transcript content is acknowledged as a durable gap: the drain
// succeeds, nothing is captured and progress does not move. A later signal
// re-reads the unit through every gate, so corrected content is captured, and
// content that erasure then covers is never captured again.
func TestDrainGapAcknowledgesUncoveredContent(t *testing.T) {
	const later, erasedAppend = "laterunitcanaryhollis", "erasedappendcanarytamsin"
	bad := append(sourceMessages(t, 1, -1, ""), []byte("{\"type\":\"assistant\",\"message\":7}\n")...)
	f := runtimeWorld(t, bad)
	c, err := NewCollector(f.p, filepath.Join(f.c.Home, "synthetic-node"))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := runtimeSnapshot(t, f.s)
	quietSource()
	first := testSignalULID[:25] + "1"
	spoolFile(t, c, "new", first+".json", hookSignal(syntheticSession, f.path))
	if err = c.Drain(context.Background(), "credential"); err != nil {
		t.Fatal("uncovered content held the drain", err)
	}
	if spoolNew(t, c) != 0 || c.Stats().Gap != 1 || c.Stats().Done != 0 {
		t.Fatal("gap not acknowledged", spoolNew(t, c), c.Stats())
	}
	if done, err := f.s.SignalDone(context.Background(), "claude", first); err != nil || !done {
		t.Fatal("gap receipt not durable", done, err)
	}
	diag, err := store.Inspect(context.Background(), filepath.Join(f.c.Home, "synthetic-node"))
	if err != nil || len(diag.SpoolGaps) != 1 {
		t.Fatal("gap not diagnosed", diag.SpoolGaps, err)
	}
	for key := range diag.SpoolGaps {
		if code := strings.TrimPrefix(key, "claude:"); drainClasses[code] != drainGap {
			t.Fatal("gap recorded under a non-gap code", key)
		}
	}
	if after, _ := runtimeSnapshot(t, f.s); len(after) != len(before) {
		t.Fatal("gap admitted records")
	}
	inspection, err := f.s.InspectCapture(context.Background(), store.SourceOccurrence{Owner: f.c.OwnerGenesis, Source: mustSource(t, f), SessionKey: mustSession(t, f)})
	if err != nil || inspection.Progress.Version != 0 {
		t.Fatal("gap advanced progress", inspection.Progress, err)
	}
	// Crash before unlink: the receipt is replayed without reopening the unit.
	spoolFile(t, c, "new", first+".json", hookSignal(syntheticSession, f.path))
	if err = c.Recover(context.Background()); err != nil || spoolNew(t, c) != 0 {
		t.Fatal("gap receipt not recovered", err)
	}
	// Corrected content and a later signal: the unit is captured normally.
	if err = os.WriteFile(f.path, sourceMessages(t, 2, 1, later), 0600); err != nil {
		t.Fatal(err)
	}
	quietSource()
	spoolFile(t, c, "new", testSignalULID[:25]+"2.json", hookSignal(syntheticSession, f.path))
	if err = c.Drain(context.Background(), "credential"); err != nil || !runtimeBodiesContain(t, f.s, later) || c.Stats().Done != 2 {
		t.Fatal("eligible re-read after a gap not captured", err, c.Stats())
	}
	// Erase it, then append uncovered content: suppression wins before any read,
	// so nothing is recaptured and no gap is recorded for the erased unit.
	eraseRuntimeCapture(t, f)
	grown, err := os.OpenFile(f.path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = grown.Write(append(sourceMessages(t, 3, 2, erasedAppend)[len(sourceMessages(t, 2, 1, later)):], []byte("{\"type\":\"assistant\",\"message\":7}\n")...))
	grown.Close()
	quietSource()
	spoolFile(t, c, "new", testSignalULID[:25]+"3.json", hookSignal(syntheticSession, f.path))
	if err = c.Drain(context.Background(), "credential"); err != nil || spoolNew(t, c) != 0 || c.Stats().Gap != 1 {
		t.Fatal("erased unit not skipped", err, c.Stats())
	}
	if runtimeBodiesContain(t, f.s, later) || runtimeBodiesContain(t, f.s, erasedAppend) {
		t.Fatal("erased unit recaptured")
	}
}

func mustSource(t *testing.T, f *runtimeFixture) string {
	t.Helper()
	rel, _ := filepath.Rel(f.c.Home, filepath.Dir(f.path))
	s, err := record.SourceKey("claude-code", f.c.MachineID, filepath.ToSlash(filepath.Join(rel, filepath.Base(f.path))))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustSession(t *testing.T, f *runtimeFixture) string {
	t.Helper()
	s, err := record.SessionKey("claude-code", "local", record.NativeGlobal, syntheticSession, f.c.MachineID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// An owner block defers capture: the drain succeeds, the hint's identity is
// applied, and the hint stays pending until the block clears, then captures.
func TestDrainPendingDefersOwnerBlockedCapture(t *testing.T) {
	const canary = "ownerblockcanarybexley"
	f := runtimeWorld(t, sourceMessages(t, 1, 0, canary))
	c, err := NewCollector(f.p, filepath.Join(f.c.Home, "synthetic-node"))
	if err != nil {
		t.Fatal(err)
	}
	db := storeDB(t, f)
	setBarrier := func(insert bool) {
		t.Helper()
		q := "DELETE FROM privacy_barrier WHERE control=?"
		args := []any{strings.Repeat("d", 64)}
		if insert {
			q = "INSERT INTO privacy_barrier(owner,control,reason,generation) SELECT ?,?, 'bulk_confirmation_required',generation+1 FROM meta WHERE singleton=1"
			args = []any{f.c.OwnerGenesis, strings.Repeat("d", 64)}
		}
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec("UPDATE meta SET generation=generation+1 WHERE singleton=1"); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	recordCount := func() int {
		t.Helper()
		var n int
		if err := db.QueryRow("SELECT count(*) FROM record").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := recordCount()
	setBarrier(true)
	quietSource()
	spoolFile(t, c, "new", testSignalULID+".json", hookSignal(syntheticSession, f.path))
	for i := 0; i < 2; i++ {
		if err = c.Drain(context.Background(), "credential"); err != nil {
			t.Fatal("owner block denied the drain", err)
		}
	}
	if spoolNew(t, c) != 1 || c.Stats().Done != 0 || c.Stats().Gap != 0 || !announced(t, f, testSignalULID) || recordCount() != before {
		t.Fatal("deferred hint acknowledged, captured or not observed", c.Stats())
	}
	if done, _ := f.s.SignalDone(context.Background(), "claude", testSignalULID); done {
		t.Fatal("deferred hint has a receipt")
	}
	setBarrier(false)
	if err = c.Drain(context.Background(), "credential"); err != nil || spoolNew(t, c) != 0 || !runtimeBodiesContain(t, f.s, canary) {
		t.Fatal("deferred hint not captured after the block cleared", err, c.Stats())
	}
}

// A policy refusal is a gap, not a deferral, and never denies the drain.
func TestDrainNoCaptureIsGap(t *testing.T) {
	f := runtimeWorld(t, sourceMessages(t, 1, -1, ""))
	f.p.config.CaptureEnabled = false
	c, err := NewCollector(f.p, filepath.Join(f.c.Home, "synthetic-node"))
	if err != nil {
		t.Fatal(err)
	}
	spoolFile(t, c, "new", testSignalULID+".json", hookSignal(syntheticSession, f.path))
	if err = c.Drain(context.Background(), "credential"); err != nil || spoolNew(t, c) != 0 || c.Stats().Gap != 1 {
		t.Fatal("no-capture refusal held the drain", err, c.Stats())
	}
	diag, err := store.Inspect(context.Background(), filepath.Join(f.c.Home, "synthetic-node"))
	if err != nil || diag.SpoolGaps["claude:no_capture"] != 1 {
		t.Fatal(diag.SpoolGaps, err)
	}
}

// Untrustworthy hints are dropped through the real store: never retained as an
// announcement, never captured and never a drain refusal.
func TestDrainDropsUntrustedHints(t *testing.T) {
	f := runtimeWorld(t, sourceMessages(t, 1, -1, ""))
	c, err := NewCollector(f.p, filepath.Join(f.c.Home, "synthetic-node"))
	if err != nil {
		t.Fatal(err)
	}
	quietSource()
	mismatch := testSignalULID[:25] + "1"
	spoolFile(t, c, "new", mismatch+".json", hookSignal("11111111-1111-4111-8111-111111111111", f.path))
	spoolFile(t, c, "new", testSignalULID[:25]+"2.json", []byte("{"))
	if err = c.Drain(context.Background(), "credential"); err != nil || spoolNew(t, c) != 0 || c.Stats().Dropped != 2 || c.Stats().Done != 0 {
		t.Fatal("untrusted hint held the drain or was admitted", err, c.Stats())
	}
	if announced(t, f, mismatch) {
		t.Fatal("dropped hint retained")
	}
	if records, _ := runtimeSnapshot(t, f.s); len(records) != 1 {
		t.Fatal("dropped hint captured")
	}
	// The same immutable ULID reused for different content is a conflict: drop.
	first := testSignalULID[:25] + "3"
	other := filepath.Join(filepath.Dir(f.path), "01990000-0000-4000-8000-000000000009.jsonl")
	if err = os.WriteFile(other, []byte("{\"type\":"), 0600); err != nil {
		t.Fatal(err)
	}
	spoolFile(t, c, "new", first+".json", hookSignal("01990000-0000-4000-8000-000000000009", other))
	if err = c.Drain(context.Background(), "credential"); err != nil || spoolNew(t, c) != 1 {
		t.Fatal("pending hint", err)
	}
	spoolFile(t, c, "new", first+".json", hookSignal(syntheticSession, f.path))
	if err = c.Drain(context.Background(), "credential"); err != nil || spoolNew(t, c) != 0 || c.Stats().Dropped != 3 {
		t.Fatal("conflicting ULID reuse not dropped", err, c.Stats())
	}
	if records, _ := runtimeSnapshot(t, f.s); len(records) != 1 {
		t.Fatal("conflicting hint captured")
	}
}

// A broken store is fatal: the drain fails and the hint is kept.
func TestDrainFatalStoreFailure(t *testing.T) {
	f := runtimeWorld(t, sourceMessages(t, 1, -1, ""))
	c, err := NewCollector(f.p, filepath.Join(f.c.Home, "synthetic-node"))
	if err != nil {
		t.Fatal(err)
	}
	spoolFile(t, c, "new", testSignalULID+".json", hookSignal(syntheticSession, f.path))
	if err = f.s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = c.Drain(context.Background(), "credential"); Code(err) != "spool_receipt_failed" {
		t.Fatal("closed store not fatal", err)
	}
	if spoolNew(t, c) != 1 || c.Stats() != (SpoolStats{}) {
		t.Fatal("fatal outcome changed the spool", c.Stats())
	}
}

// twoClientWorld is one real SQLite store and pipeline with a Claude root and
// a Codex root, each holding one transcript for syntheticSession.
func twoClientWorld(t *testing.T, claude, codex []byte) (*Collector, *store.Store, string, string) {
	t.Helper()
	ctx := context.Background()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{51}, 32))
	pub := key.Public().(ed25519.PublicKey)
	cfg := Config{Home: home, OwnerGenesis: sig.KeyID(pub), MachineID: syntheticSession, Roots: map[string]Root{}, CaptureEnabled: true}
	paths := map[string]string{}
	for id, data := range map[string][]byte{"claude-code": claude, "codex": codex} {
		root := filepath.Join(home, "synthetic-"+id)
		if err = os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
		cfg.Roots[strings.ReplaceAll(id, "-", "")] = Root{Client: id, AbsPath: root}
		paths[id] = filepath.Join(root, syntheticSession+".jsonl")
		if err = os.WriteFile(paths[id], data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := store.Open(ctx, store.Options{Dir: filepath.Join(home, "synthetic-node"), PinnedGenesisID: cfg.OwnerGenesis, LocalMachineID: cfg.MachineID})
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := sig.BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Genesis: cfg.OwnerGenesis, Subject: sig.KeyRefOf(pub, record.RoleDevice, cfg.MachineID)}, pub, cfg.MachineID, 1761150000000, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Append(ctx, store.SignedRecord{HeaderJCS: genesis.Rec.HeaderJCS, BodyJCS: genesis.Rec.BodyJCS, Sigs: genesis.Sigs, AdvisoryID: genesis.Rec.ID}); err != nil {
		t.Fatal(err)
	}
	material, err := PreloadKeys(bytes.Repeat([]byte{52}, 32), key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPipeline(ctx, s, cfg, material)
	material.Clear()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCollector(p, filepath.Join(home, "synthetic-node"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = s.Close(); clear(key) })
	return c, s, paths["claude-code"], paths["codex"]
}

func clientSpool(t *testing.T, c *Collector, client, name string, h transport.HookSignal) string {
	t.Helper()
	dir := filepath.Join(c.dir, "spool", client, "new")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(h)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// One client's stuck hints never hold another client's capture. Claude's
// earlier-ordered hints are pending and gap; Codex is captured in the same
// drain, which succeeds. A fatal spool failure for Claude still lets Codex
// drain, and is reported.
func TestDrainIsolatesClients(t *testing.T) {
	claudeBad := append(sourceMessages(t, 1, -1, ""), []byte("{\"type\":\"assistant\",\"message\":7}\n")...)
	c, s, claudePath, codexPath := twoClientWorld(t, claudeBad, readFixture(t, "codex"))
	pendingPath := filepath.Join(filepath.Dir(claudePath), "01990000-0000-4000-8000-000000000005.jsonl")
	if err := os.WriteFile(pendingPath, []byte("{\"type\":"), 0600); err != nil {
		t.Fatal(err)
	}
	quietSource()
	stop := transport.HookSignal{V: 3, At: 1, Event: "Stop", HookPID: os.Getpid()}
	h := stop
	h.Client, h.NativeSession, h.TranscriptPath = "claude", syntheticSession, claudePath
	clientSpool(t, c, "claude", testSignalULID[:25]+"1.json", h)
	h.NativeSession, h.TranscriptPath = "01990000-0000-4000-8000-000000000005", pendingPath
	stuck := clientSpool(t, c, "claude", testSignalULID[:25]+"2.json", h)
	h.Client, h.NativeSession, h.TranscriptPath = "codex", syntheticSession, codexPath
	codexHint := clientSpool(t, c, "codex", testSignalULID[:25]+"9.json", h)
	if err := c.Drain(context.Background(), "credential"); err != nil {
		t.Fatal("one client's stuck hints denied the drain", err)
	}
	if _, err := os.Lstat(codexHint); !os.IsNotExist(err) {
		t.Fatal("codex hint not drained", err)
	}
	if done, err := s.SignalDone(context.Background(), "codex", testSignalULID[:25]+"9"); err != nil || !done {
		t.Fatal("codex hint not captured", done, err)
	}
	if _, err := os.Lstat(stuck); err != nil || c.Stats().Gap != 1 || c.Stats().Done != 1 {
		t.Fatal("claude outcomes", err, c.Stats())
	}
	// Claude's spool directory becomes unsafe: fatal for Claude only.
	if err := os.Chmod(filepath.Dir(stuck), 0755); err != nil {
		t.Fatal(err)
	}
	codexNext := clientSpool(t, c, "codex", testSignalULID[:25]+"A.json", h)
	if err := c.Drain(context.Background(), "credential"); Code(err) != "unsafe_spool" {
		t.Fatal("unsafe spool not fatal", err)
	}
	if _, err := os.Lstat(codexNext); !os.IsNotExist(err) {
		t.Fatal("claude's fatal spool blocked codex", err)
	}
}
