package syncnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// pinReader opens a read transaction on one database file of dir and reads a
// row, so its snapshot pins the WAL until release. A pinned WAL cannot be
// truncated, and the bytes a deletion superseded stay on disk.
func pinReader(t *testing.T, path, query string) (release func()) {
	t.Helper()
	db, err := sql.Open("sqlite", store.SQLiteURI(path, ""))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err = tx.QueryRow(query).Scan(&n); err != nil || n == 0 {
		t.Fatalf("reader fixture %s: %d %v", filepath.Base(path), n, err)
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			_ = tx.Rollback()
			_ = db.Close()
		})
	}
	t.Cleanup(release)
	return release
}

// foreignChunk is another device's transcript chunk holding text, as hosted
// would relay it as data. v1 quarantines it with its full envelope.
func foreignChunk(t *testing.T, sk, text string, at int64) (record.Envelope, string) {
	t.Helper()
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	pub := other.Public().(ed25519.PublicKey)
	machine := "88888888-8888-4888-8888-888888888888"
	id, err := record.EventID(sk, "assistant_final", record.Anchor{NativeItemID: "relayed"})
	if err != nil {
		t.Fatal(err)
	}
	e := record.Event{ID: id, Seq: 1, Kind: "assistant_final", Prov: "transcript", Text: &record.Text{Body: text}}
	h := record.Header{Type: record.KindChunk, Prov: record.ProvTranscript, Subj: record.Subject{SessionKey: sk}, LID: record.ChunkLID(sk, machine, id), At: at, Author: record.Author{MachineID: machine, KeyID: sig.KeyID(pub)}, Red: record.Redact{Profile: record.ProfileLocal}}
	r, err := record.Build(h, &record.ChunkBody{Events: []record.Event{e}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := sig.SignRecord(other, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return envelopeOf(r, []record.Signature{s}), r.ID
}

// An enforced ACK is the hosted fan-out's evidence that the device no longer
// holds what the control erased. While a deliberately busy reader pins the
// sync database WAL, and then while another pins the node store WAL, the
// erasure is logically applied but its bytes are still on disk: no ACK may
// cover it. Only the round that establishes physical cleanup of every managed
// copy acknowledges it, and the ACK handler itself finds the planted bytes
// gone from every file, the quarantined hosted copy in sync.sqlite included.
func TestEnforcedAckWaitsForPhysicalCleanupOfEveryCopy(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	h := w.hosted
	p := w.enroll()
	wk := w.worker()
	sk := x2SessionKey(t)

	const local = "ack_scrub_local_store_canary_2e7b"
	const relayed = "ack_scrub_quarantined_copy_canary_91d4"
	k, _, event := w.chunk(sk, local, "ack-local")
	q, qid := foreignChunk(t, sk, relayed, w.at)
	// The quarantine row holds the exact envelope JSON, whose body is the
	// base64url frame; those bytes are what must leave sync.sqlite.
	planted := q.Body.Bytes
	h.addData(q)
	if err := wk.Round(ctx); err != nil {
		t.Fatal("quarantine round", err)
	}
	if n := count(t, wk, "SELECT count(*) FROM data_quarantine"); n != 1 {
		t.Fatalf("hosted copy not quarantined: %d", n)
	}
	if canaryIn(w.dir, planted) == nil || canaryIn(w.dir, local) == nil {
		t.Fatal("fixture did not plant both copies")
	}

	var mu sync.Mutex
	var failures []string
	var hc int64
	h.onAck = func(_ string, ack transport.Ack) {
		mu.Lock()
		defer mu.Unlock()
		if hc == 0 || ack.CtlEnforcedThrough < hc {
			return
		}
		for _, needle := range []string{local, planted} {
			if err := canaryIn(w.dir, needle); err != nil {
				failures = append(failures, fmt.Sprintf("ack %d covers the erasure while %v", ack.CtlEnforcedThrough, err))
			}
		}
	}
	round := func(stage string, want error) {
		t.Helper()
		if err := wk.Round(ctx); !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Fatalf("%s: round %v, want %v", stage, err, want)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(failures) > 0 {
			t.Fatal(stage, failures)
		}
	}
	below := func(stage string) {
		t.Helper()
		c := cursorsOf(t, wk, p)
		if c.Ctl >= hc || c.BarrierHSeq != hc || c.BarrierReason != "scrub_pending" {
			t.Fatalf("%s: cursors %+v", stage, c)
		}
		for _, ack := range h.ackList() {
			if ack.CtlEnforcedThrough >= hc {
				t.Fatalf("%s: ack %+v covers an erasure whose cleanup is pending", stage, ack)
			}
		}
	}

	// Both readers start before the erasure, so their snapshots hold the
	// planted bytes.
	releaseSidecar := pinReader(t, filepath.Join(w.dir, store.SyncDatabaseName), "SELECT count(*) FROM data_quarantine")
	releaseStore := pinReader(t, filepath.Join(w.dir, "memory.sqlite"), "SELECT count(*) FROM record")
	w.at++
	ids := []string{k.ID, qid}
	sort.Strings(ids)
	c := erasureBy(t, w.key, w.machine, "ack-scrub", w.at, record.Selectors{IDs: ids, Events: []record.EventSelector{{Owner: w.genesis, SessionKey: sk, EventID: event}}})
	mu.Lock()
	hc = h.addControl(c)
	mu.Unlock()

	// The sync database WAL is pinned: the quarantined copy is deleted
	// logically, the local chunk is purged, and neither is acknowledged.
	round("sidecar pinned", ErrControlBlocked)
	below("sidecar pinned")
	if state, body := entryState(t, w.st, k.ID); state != "invalidated" || body {
		t.Fatalf("erasure not applied logically: %s body=%v", state, body)
	}
	if n := count(t, wk, "SELECT count(*) FROM data_quarantine"); n != 0 {
		t.Fatalf("quarantined copy kept: %d", n)
	}
	if canaryIn(w.dir, planted) == nil {
		t.Fatal("the pinned sidecar reader did not retain the quarantined bytes")
	}

	// The sidecar is released, the node store WAL is still pinned.
	releaseSidecar()
	round("store pinned", ErrControlBlocked)
	below("store pinned")
	if err := canaryIn(w.dir, planted); err != nil {
		t.Fatal("sidecar not cleaned once its reader left:", err)
	}
	if canaryIn(w.dir, local) == nil {
		t.Fatal("the pinned store reader did not retain the local bytes")
	}

	releaseStore()
	round("released", nil)
	if c := cursorsOf(t, wk, p); c.Ctl != hc || c.BarrierHSeq != 0 {
		t.Fatalf("cleanup did not complete the control: %+v", c)
	}
	acks := h.ackList()
	if len(acks) == 0 || acks[len(acks)-1].CtlEnforcedThrough != hc {
		t.Fatalf("final ack %+v", acks)
	}
	assertNoCanary(t, w.dir, local)
	assertNoCanary(t, w.dir, planted)
}
