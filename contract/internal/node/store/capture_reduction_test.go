package store

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/record"
)

func TestCaptureHistoryWorkRefusalDoesNotPoisonOrFreeze(t *testing.T) {
	f := newProducer(t, "same-seal history work")
	f.commit()
	parsed, err := record.Parse(f.plan.NewRecords[0].HeaderJCS, f.plan.NewRecords[0].BodyJCS, "")
	if err != nil {
		t.Fatal(err)
	}
	events := parsed.Body.(*record.ChunkBody).Events
	var copies []SignedRecord
	for i := 0; i < 1600; i++ {
		copies = append(copies, f.chunk(events, nil))
	}
	f.w.seedPending(copies)
	ctx := context.Background()
	before := f.w.snapshot()
	q := f.q
	q.ExpectedVersion = 1
	called := false
	_, err = f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { called = true; return CommitPlan{}, nil })
	var fixed *Error
	if !errors.As(err, &fixed) || fixed.Code != "lineage_evaluation_required" || fixed.OwnerBlocked || called || f.w.s.poisoned {
		t.Fatal("history-only refusal claimed unknown durability or producer ran", err, called, f.w.s.poisoned)
	}
	after, err := f.w.s.Snapshot(ctx, ReadRequest{})
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("history-only refusal changed or hid current state", err)
	}
	var holds, transitions int
	if f.w.s.conn.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM privacy_barrier)+(SELECT count(*) FROM projection_hold),(SELECT count(*) FROM capture_transition)").Scan(&holds, &transitions) != nil || holds != 0 || transitions != 1 {
		t.Fatal("history-only refusal persisted guard or progress", holds, transitions)
	}
	if _, err = f.w.s.Identity(ctx); err != nil {
		t.Fatal("known refusal poisoned later instance inspection", err)
	}
}

func TestCaptureLoadProjectionGuardHasKnownCommittedReceipt(t *testing.T) {
	for _, inspect := range []bool{false, true} {
		name := "capture"
		if inspect {
			name = "inspect"
		}
		t.Run(name, func(t *testing.T) {
			k := newKernel(t)
			root := k.execute("capture-load-guard-root", "local.create_task", map[string]any{"goal": "guard root"})
			k.release(root)
			seedDisclosureExposureHistory(t, k, root, 8193)
			f := producerFor(k.world, "unreleased capture")
			ctx := context.Background()
			var before int64
			if err := k.s.conn.QueryRowContext(ctx, "SELECT generation FROM meta").Scan(&before); err != nil {
				t.Fatal(err)
			}
			var err error
			if inspect {
				_, err = k.s.InspectCapture(ctx, f.q.Occurrence)
			} else {
				_, err = k.s.Capture(ctx, f.q, func(*CaptureTxn) (CommitPlan, error) {
					t.Fatal("incomplete durable lineage reached producer")
					return CommitPlan{}, nil
				})
			}
			var fixed *Error
			if !errors.As(err, &fixed) || fixed.Code != "lineage_evaluation_required" || !fixed.OwnerBlocked || k.s.poisoned {
				t.Fatal("known committed guard became unknown", err, k.s.poisoned)
			}
			var count int
			var generation int64
			if k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_hold").Scan(&count) != nil || k.s.conn.QueryRowContext(ctx, "SELECT generation FROM meta").Scan(&generation) != nil || count != 1 || generation != before+1 {
				t.Fatal("guard did not commit exactly once", count, generation, before)
			}
			if _, err = k.s.Identity(ctx); err != nil {
				t.Fatal("committed guard poisoned handle", err)
			}
		})
	}
}
