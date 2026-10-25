package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// managedFiles returns the bytes of every regular file under the store
// directory: the database, its WAL and shared-memory sidecars and anything
// else the node keeps there.
func managedFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[path] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// assertAbsent fails when any managed file holds any of the forbidden values.
func assertAbsent(t *testing.T, dir string, forbidden ...string) {
	t.Helper()
	for path, content := range managedFiles(t, dir) {
		for _, f := range forbidden {
			if f != "" && bytes.Contains(content, []byte(f)) {
				t.Fatalf("erased value %.12q survives in %s", f, filepath.Base(path))
			}
		}
	}
}

func countRows(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.conn.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// acknowledgeLatest confirms the newest render of op with its exact item set.
func (k *kernelWorld) acknowledgeLatest(op string) {
	k.t.Helper()
	ctx := context.Background()
	var nonce string
	if err := k.s.conn.QueryRowContext(ctx, "SELECT nonce FROM render_attempt WHERE op=? ORDER BY db_generation DESC LIMIT 1", op).Scan(&nonce); err != nil {
		k.t.Fatal(err)
	}
	rows, err := k.s.conn.QueryContext(ctx, "SELECT lid,id FROM render_item WHERE attempt=(SELECT id FROM render_attempt WHERE nonce=?) ORDER BY ordinal", nonce)
	if err != nil {
		k.t.Fatal(err)
	}
	var items []ItemMarker
	for rows.Next() {
		var m ItemMarker
		if err := rows.Scan(&m.LID, &m.ID); err != nil {
			k.t.Fatal(err)
		}
		items = append(items, m)
	}
	rows.Close()
	if got, err := k.e.Acknowledge(ctx, k.h, ACK{nonce, items}); err != nil || got.Status != "confirmed" {
		k.t.Fatal("delivery confirmation", got, err)
	}
}

// unsealed returns an event at seq with its own anchor, left for record.Build
// to seal with fresh entropy.
func (w *world) unsealed(text, anchor string, seq int64) record.Event {
	e := w.event(text)
	e.Seq = seq
	if anchor != "" {
		var err error
		if e.ID, err = record.EventID(w.sessionKey(), "assistant_final", record.Anchor{NativeItemID: anchor}); err != nil {
			w.t.Fatal(err)
		}
	}
	e.Revision = ""
	e.Salt = ""
	return e
}

// The durable recall facts are the transcript recall ledger (item_recall) and
// the append-only exposure ledger. A delivered-set reset (compaction), a full
// projection rebuild and a restart must not drop either, so erase and retract
// still hold every semantic descendant, whichever order the reset and the
// control arrive in. Each ledger is load-bearing on its own: the transcript
// root is never looked up, and the exposed root is never recalled.
func TestRecallLedgerAndHoldsSurviveDeliveredSetResetAndReindex(t *testing.T) {
	for _, ledger := range []string{"transcript", "exposure"} {
		for _, kind := range []record.Kind{record.KindErasure, record.KindRetraction} {
			for _, order := range []string{"control-after-reset", "control-before-reset"} {
				t.Run(ledger+"/"+string(kind)+"/"+order, func(t *testing.T) {
					k := newKernel(t)
					ctx := context.Background()
					exposed := k.task(1, "exposure ledger root 7f0a")
					k.append(exposed)
					recalled := k.task(3, "transcript recall root 0be2")
					k.append(recalled)
					parsed, err := record.Parse(recalled.HeaderJCS, recalled.BodyJCS, recalled.AdvisoryID)
					if err != nil {
						t.Fatal(err)
					}
					// Admitted before the exposure fence and ordered before the
					// recall, so it is never a semantic descendant.
					early := k.chunk(k.unsealed("recall ledger known earlier output", "ledger-early", 5))
					k.append(early)
					lookup := k.execute("recall-lookup", "local.lookup_record", map[string]any{"record_id": exposed.AdvisoryID})
					k.release(lookup)
					k.acknowledgeLatest(lookup.op)

					marker := k.unsealed("recall ledger marker", "ledger-marker", 10)
					marker.Recalled = []string{parsed.Header.LID + "@" + recalled.AdvisoryID}
					recallChunk := k.chunk(marker)
					k.append(recallChunk)
					laterText := "recall_ledger_later_canary_31d9"
					later := k.chunk(k.unsealed(laterText, "ledger-later", 11))
					k.append(later)
					futureText := "recall_ledger_future_canary_c27e"
					future := k.task(2, futureText)
					k.append(future)

					recallQuery := "SELECT count(*) FROM item_recall WHERE id=? AND recalled=? AND event_seq=10"
					recalls := countRows(t, k.s, recallQuery, recallChunk.AdvisoryID, recalled.AdvisoryID)
					exposures := countRows(t, k.s, "SELECT count(*) FROM exposure WHERE root=?", exposed.AdvisoryID)
					if recalls != 1 || exposures == 0 || countRows(t, k.s, "SELECT count(*) FROM delivery_confirmation") == 0 {
						t.Fatal("fixture did not record recall facts", recalls, exposures)
					}
					if countRows(t, k.s, "SELECT count(*) FROM exposure WHERE root=?", recalled.AdvisoryID) != 0 {
						t.Fatal("transcript root was exposed by the fixture")
					}
					for _, r := range []SignedRecord{early, later, future} {
						if e := find(k.snapshot(), r.AdvisoryID); e.State != "live" {
							t.Fatal("descendant held before any control", e.State)
						}
					}

					target, held, live := recalled, []SignedRecord{later}, []SignedRecord{early, future}
					if ledger == "exposure" {
						target, held, live = exposed, []SignedRecord{later, future}, []SignedRecord{early}
					}
					control := k.control(91, kind, target.AdvisoryID)
					reset := func() {
						signal, err := k.a.issueSyntheticCompaction(ctx, k.sc)
						if err != nil {
							t.Fatal(err)
						}
						if err = k.a.applySyntheticCompaction(ctx, signal); err != nil {
							t.Fatal(err)
						}
						if err = k.s.Reindex(ctx); err != nil {
							t.Fatal(err)
						}
					}
					if order == "control-before-reset" {
						k.append(control)
						reset()
					} else {
						reset()
						k.append(control)
					}

					check := func(stage string) {
						t.Helper()
						if n := countRows(t, k.s, recallQuery, recallChunk.AdvisoryID, recalled.AdvisoryID); n != recalls {
							t.Fatal(stage, "recall ledger lost", n)
						}
						if n := countRows(t, k.s, "SELECT count(*) FROM exposure WHERE root=?", exposed.AdvisoryID); n != exposures {
							t.Fatal(stage, "exposure ledger reset", n, exposures)
						}
						snap := k.snapshot()
						for _, r := range live {
							if e := find(snap, r.AdvisoryID); e.State != "live" || len(e.BodyJCS) == 0 {
								t.Fatal(stage, "unrelated output held", e.State)
							}
						}
						for _, r := range held {
							e := find(snap, r.AdvisoryID)
							if e.State != "lineage-hold" || len(e.BodyJCS) != 0 {
								t.Fatal(stage, "semantic descendant served", e.State)
							}
							if n := countRows(t, k.s, "SELECT count(*) FROM passage WHERE id=?", r.AdvisoryID); n != 0 {
								t.Fatal(stage, "held descendant searchable")
							}
						}
						if n := countRows(t, k.s, "SELECT count(*) FROM search WHERE search MATCH ?", `"`+laterText+`"`); n != 0 {
							t.Fatal(stage, "held text in FTS")
						}
					}
					check("after reset")
					k.e.Close()
					k.s.Close()
					s, err := Open(ctx, k.o)
					if err != nil {
						t.Fatal(err)
					}
					k.s = s
					check("after restart")
					if err = s.Reindex(ctx); err != nil {
						t.Fatal(err)
					}
					check("after restart and reindex")
				})
			}
		}
	}
}
