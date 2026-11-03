package store

import (
	"context"
	"encoding/json"
	"github.com/Telara-Labs/hilo/contract/record"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLaterFullBodyUsesOriginalSequenceAndCannotRefillTomb(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	full := w.task(1, "latefullbody")
	header := full
	header.BodyJCS = nil
	a := w.append(header)
	if len(find(w.snapshot(), a.ID).BodyJCS) != 0 {
		t.Fatal("body fabricated")
	}
	b := w.append(full)
	if !b.Duplicate || b.Sequence != a.Sequence || len(find(w.snapshot(), a.ID).BodyJCS) == 0 {
		t.Fatal("matching body not enriched")
	}
	w.append(w.control(1, record.KindErasure, a.ID))
	w.append(full)
	if len(find(w.snapshot(), a.ID).BodyJCS) != 0 {
		t.Fatal("erased body refilled")
	}
	if e := w.s.Reindex(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestSynchronousProjectionFailureRollsBackWholeAdmission(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	seedFreshCheckpoint(w, "trusted positive projection")
	r := w.task(1, "projectionfailurecanary")
	var expectedSequence int64
	w.s.conn.QueryRowContext(ctx, "SELECT next_seq FROM meta").Scan(&expectedSequence)
	before := w.snapshot()
	if _, e := w.s.conn.ExecContext(ctx, "CREATE TRIGGER reject_passage BEFORE INSERT ON passage BEGIN SELECT RAISE(ABORT,'private_canary_error'); END"); e != nil {
		t.Fatal(e)
	}
	_, e := w.s.Append(ctx, r)
	if Code(e) != "storage_error" || e.Error() != "storage_error" {
		t.Fatal("failure leaked or ignored", e)
	}
	after := w.snapshot()
	if before.Generation != after.Generation || len(before.Entries) != len(after.Entries) {
		t.Fatal("partial commit")
	}
	if _, e = w.s.conn.ExecContext(ctx, "DROP TRIGGER reject_passage"); e != nil {
		t.Fatal(e)
	}
	a := w.append(r)
	if a.Sequence != expectedSequence {
		t.Fatal("failed write consumed admission order")
	}
}
func TestCrashChild(t *testing.T) {
	at := -1
	for n, a := range os.Args {
		if a == "--store-crash" {
			at = n
			break
		}
	}
	if at < 0 {
		return
	}
	if len(os.Args) != at+4 {
		os.Exit(9)
	}
	mode, dir, pin := os.Args[at+1], os.Args[at+2], os.Args[at+3]
	ctx := context.Background()
	o := Options{Dir: dir, PinnedGenesisID: pin, LocalMachineID: testMachine}
	s, e := Open(ctx, o)
	if e != nil {
		os.Exit(10)
	}
	var r SignedRecord
	sealed, err := os.ReadFile(filepath.Join(dir, "crash-candidate.json"))
	if err != nil || json.Unmarshal(sealed, &r) != nil {
		os.Exit(17)
	}
	if mode == "after" {
		if _, e = s.Append(ctx, r); e != nil {
			os.Exit(11)
		}
		os.Exit(0)
	}
	if _, e = s.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		os.Exit(12)
	}
	// This crash fixture enters the writer directly so it can exit without
	// writeMode's rollback defer. Retain the same bounded reduction context.
	s.reductions = newReductionContext()
	d, e := s.load(ctx)
	if e != nil {
		os.Exit(13)
	}
	parsed, signatures, e := parse(r)
	if e != nil {
		os.Exit(14)
	}
	x := &stored{rec: parsed, sigs: signatures, owner: pin, seq: d.nextSeq, generation: d.generation + 1}
	material(x)
	d.records = append(d.records, x)
	d.byID[r.AdvisoryID] = x
	if d.rebuild(o) != nil || s.insertRecord(ctx, x) != nil {
		os.Exit(15)
	}
	if _, e = s.conn.ExecContext(ctx, "UPDATE meta SET generation=generation+1,next_seq=next_seq+1"); e != nil {
		os.Exit(16)
	}
	// Abrupt exit skips every Go/SQLite close and rollback defer.
	os.Exit(0)
}
func TestAbruptProcessRecoveryBeforeAndAfterCommit(t *testing.T) {
	for _, mode := range []string{"before", "after"} {
		t.Run(mode, func(t *testing.T) {
			w := newWorld(t)
			r := w.task(1000, "abrupt-recovery-marker")
			sealed, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(w.o.Dir, "crash-candidate.json"), sealed, 0600); err != nil {
				t.Fatal(err)
			}
			w.s.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "--", "--store-crash", mode, w.o.Dir, w.o.PinnedGenesisID)
			if out, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("child failed %v %s", e, out)
			}
			s, e := Open(context.Background(), w.o)
			if e != nil {
				t.Fatal(e)
			}
			w.s = s
			v := find(w.snapshot(), r.AdvisoryID)
			if mode == "before" && v.ID != "" {
				t.Fatal("uncommitted record survived")
			}
			if mode == "after" && (v.ID == "" || len(v.BodyJCS) == 0 || v.TaskStatus != "active") {
				t.Fatal("durable commit lost")
			}
		})
	}
}
