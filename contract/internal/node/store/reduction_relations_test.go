package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

// A store-private historical exposure fixture exercises retained SQL keys and
// actual signed admission. It does not claim an installed client delivered all
// these roots. No source completeness or client authority is minted by it.
func relationCapacityWorld(t *testing.T) (*kernelWorld, []string) {
	t.Helper()
	k := newKernel(t)
	ctx := context.Background()
	r := k.execute("relation-root", "local.create_task", map[string]any{"goal": "retained relation root"})
	var first, attempt, call string
	k.s.conn.QueryRowContext(ctx, "SELECT id FROM outcome_member WHERE op=?", r.op).Scan(&first)
	k.s.conn.QueryRowContext(ctx, "SELECT id FROM render_attempt WHERE op=?", r.op).Scan(&attempt)
	k.s.conn.QueryRowContext(ctx, "SELECT call_ref FROM operation WHERE op=?", r.op).Scan(&call)
	roots := []string{first}
	var inputs []SignedRecord
	for i := 0; i < 255; i++ {
		in := k.task(95000+i, "retained root")
		inputs = append(inputs, in)
		roots = append(roots, in.AdvisoryID)
	}
	k.seedPending(inputs)
	var fence int64
	k.s.conn.QueryRowContext(ctx, "SELECT next_seq-1 FROM meta").Scan(&fence)
	if err := k.s.write(ctx, func() error {
		for i, id := range roots[1:] {
			exposure := fmt.Sprintf("cccccccc-cccc-4ccc-8ccc-%012x", i)
			if _, err := k.s.conn.ExecContext(ctx, "INSERT INTO exposure VALUES(?,?,?,?,?,?,?,?,?,'local-admission-fence/1')", exposure, k.o.PinnedGenesisID, testMachine, k.h.credential, k.sc.id, id, call, attempt, fence); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	inputs = nil
	for i := 0; i < 255; i++ {
		inputs = append(inputs, k.task(96000+i, "future observed output"))
	}
	k.seedPending(inputs)
	var rows int
	if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM exposure_affect").Scan(&rows); err != nil || rows != 65535 {
		t.Fatal("wrong retained SQL pair fixture", rows, err)
	}
	if _, err := k.s.Snapshot(ctx, ReadRequest{}); err != nil {
		t.Fatal("within-bound prior state unavailable", err)
	}
	return k, roots
}
func TestReductionExposureSQLUnionRefusesBeforeCandidatePersistence(t *testing.T) {
	k, _ := relationCapacityWorld(t)
	ctx := context.Background()
	candidate := k.task(97000, "unretained exposure capacity candidate")
	var seq, generation int64
	k.s.conn.QueryRowContext(ctx, "SELECT next_seq,generation FROM meta").Scan(&seq, &generation)
	if _, err := k.s.Append(ctx, candidate); Code(err) != "lineage_evaluation_required" {
		t.Fatal("candidate SQL-key overflow not held", err)
	}
	var rows, persisted int
	var after int64
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM exposure_affect").Scan(&rows)
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record WHERE id=?", candidate.AdvisoryID).Scan(&persisted)
	k.s.conn.QueryRowContext(ctx, "SELECT next_seq FROM meta").Scan(&after)
	if rows != 65535 || persisted != 0 || after != seq {
		t.Fatal("candidate or partial SQL union persisted", rows, persisted, after)
	}
	var holds int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_hold").Scan(&holds)
	if holds != 1 {
		t.Fatal("retained exposure uncertainty was not durably fenced")
	}
}
func TestReductionSemanticHoldSQLUnionKeepsDistinctRootCauseTokens(t *testing.T) {
	k, roots := relationCapacityWorld(t)
	ctx := context.Background()
	k.append(k.control(98100, record.KindErasure, roots...))
	var count int
	if err := k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM semantic_hold_cause").Scan(&count); err != nil || count != 65535 {
		t.Fatal("wrong exact hold token fixture", count, err)
	}
	if _, err := k.s.Snapshot(ctx, ReadRequest{}); err != nil {
		t.Fatal("within-bound semantic holds did not reconstruct", err)
	}
	var effects int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect").Scan(&effects)
	if effects != 511 {
		t.Fatal("effect dedup differs from distinct hold-token accounting", effects)
	}
	candidate := k.control(98101, record.KindErasure, roots[1])
	var seq int64
	k.s.conn.QueryRowContext(ctx, "SELECT next_seq FROM meta").Scan(&seq)
	if _, err := k.s.ApplyControl(ctx, candidate); Code(err) != "lineage_evaluation_required" {
		t.Fatal("distinct cause capacity bypassed", err)
	}
	var after, persisted int
	var afterSeq int64
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM semantic_hold_cause").Scan(&after)
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record WHERE id=?", candidate.AdvisoryID).Scan(&persisted)
	k.s.conn.QueryRowContext(ctx, "SELECT next_seq FROM meta").Scan(&afterSeq)
	if after != count || persisted != 0 || afterSeq != seq {
		t.Fatal("control or partial hold causes persisted", after, persisted, afterSeq)
	}
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM erasure_effect").Scan(&after)
	if after != effects {
		t.Fatal("rejected control consumed effects", after, effects)
	}
}

func TestReductionRetainedForeignSessionFactsCannotDisappear(t *testing.T) {
	for _, table := range []string{"presence", "witness"} {
		t.Run(table, func(t *testing.T) {
			f := newProducer(t, "same historical payload")
			f.commit()
			ctx := context.Background()
			if table == "witness" {
				in := f.chunk([]record.Event{f.event(f.q.EventIDs[0], 0, "same historical payload")}, nil)
				f.w.append(in)
				f.w.append(f.page([]string{f.plan.NewRecords[0].AdvisoryID, in.AdvisoryID}, 0, f.plan.NewRecords[1].AdvisoryID))
			}
			var rows int
			if err := f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&rows); err != nil || rows == 0 {
				t.Fatal("missing nonvacuous retained fixture", rows, err)
			}
			foreign, err := record.SessionKey("claude-code", "local", record.NativeGlobal, "33333333-3333-4333-8333-333333333333", "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.w.s.conn.ExecContext(ctx, "UPDATE "+table+" SET session=?", foreign); err != nil {
				t.Fatal(err)
			}
			if _, err = f.w.s.Snapshot(ctx, ReadRequest{}); Code(err) != "corrupt_database" {
				t.Fatal("retained foreign session metadata was silently omitted", err)
			}
			f.w.s.Close()
			reopened, openErr := Open(ctx, f.w.o)
			if reopened != nil {
				reopened.Close()
			}
			if Code(openErr) != "corrupt_database" {
				t.Fatal("reopen silently omitted corruption", openErr)
			}
		})
	}
}
