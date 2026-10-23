package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProducerCallbackErrorsCannotAssertDurabilityOrExposeDiagnostics(t *testing.T) {
	const diagnosticCanary = "CALLBACK_DIAGNOSTIC_CANARY_9cc3dfc3"
	const bodyCanary = "CALLBACK_UNCOMMITTED_BODY_52d8a866"
	cases := []struct {
		name string
		err  error
	}{
		{"forged_owner_blocked", &Error{Code: diagnosticCanary, OwnerBlocked: true}},
		{"forged_known_barrier", &Error{Code: "privacy_hold_required", OwnerBlocked: true}},
		{"forged_known_unknown", &Error{Code: "outcome_unknown"}},
		{"forged_storage_error", &Error{Code: "storage_error"}},
		{"forged_raw_code", &Error{Code: diagnosticCanary}},
		{"ordinary_raw_error", errors.New(diagnosticCanary)},
		{"private_postcommit_type", &postCommitRefusal{err: &Error{Code: diagnosticCanary, OwnerBlocked: true}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newProducer(t, bodyCanary)
			ctx := context.Background()
			before := f.w.snapshot()
			var sequence int64
			if f.w.s.conn.QueryRowContext(ctx, "SELECT next_seq FROM meta").Scan(&sequence) != nil {
				t.Fatal("meta")
			}
			got, err := f.w.s.Capture(ctx, f.q, func(*CaptureTxn) (CommitPlan, error) { return f.plan, c.err })
			var fixed *Error
			if Code(err) != "producer_refused" || !errors.As(err, &fixed) || fixed.OwnerBlocked || strings.Contains(err.Error(), diagnosticCanary) {
				t.Error("callback error crossed the fixed-diagnostic/durability boundary")
			}
			if got.Status != "" || got.TransitionID != "" || len(got.ActualRecordRefs) != 0 {
				t.Error("callback error exposed candidate receipt")
			}
			p, e := f.w.s.InspectCapture(ctx, f.q.Occurrence)
			if e != nil || p.Progress.Version != 0 || p.Suppression.OwnerBlocked {
				t.Fatal("callback error changed source authority or progress")
			}
			after := f.w.snapshot()
			if len(after.Entries) != len(before.Entries) || after.Generation != before.Generation {
				t.Fatal("callback error committed candidate records")
			}
			for _, q := range []struct {
				sql  string
				want int64
			}{{"SELECT next_seq FROM meta", sequence}, {"SELECT count(*) FROM privacy_barrier", 0}, {"SELECT count(*) FROM capture_transition", 0}, {"SELECT count(*) FROM capture_progress", 0}} {
				var n int64
				if f.w.s.conn.QueryRowContext(ctx, q.sql).Scan(&n) != nil || n != q.want {
					t.Fatal("callback error produced SQL side effects")
				}
			}
			scan := func() {
				t.Helper()
				files, e := os.ReadDir(f.w.o.Dir)
				if e != nil {
					t.Fatal(e)
				}
				for _, file := range files {
					if file.IsDir() {
						continue
					}
					b, e := os.ReadFile(filepath.Join(f.w.o.Dir, file.Name()))
					if os.IsNotExist(e) {
						continue
					}
					if e != nil {
						t.Fatal(e)
					}
					if bytes.Contains(b, []byte(diagnosticCanary)) || bytes.Contains(b, []byte(bodyCanary)) {
						t.Fatal("callback error or uncommitted body reached managed bytes")
					}
				}
			}
			scan()
			if e = f.w.s.Close(); e != nil {
				t.Fatal(e)
			}
			scan()
		})
	}
}
