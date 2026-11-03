package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

func pendingReuseLatePlan(t *testing.T, extra int) (*producerFixture, CaptureRequest, CommitPlan) {
	t.Helper()
	f, q, p, _ := lateProducerPlan(t, extra, false)
	r, e := record.Parse(f.plan.NewRecords[0].HeaderJCS, f.plan.NewRecords[0].BodyJCS, "")
	if e != nil {
		t.Fatal(e)
	}
	pending := f.chunk(r.Body.(*record.ChunkBody).Events, []string{record.H("missing-reuse-parent")})
	f.w.append(pending)
	page := f.page([]string{f.plan.NewRecords[0].AdvisoryID, p.NewRecords[0].AdvisoryID, pending.AdvisoryID}, 0, f.plan.NewRecords[1].AdvisoryID)
	p.NewRecords[1] = page
	p.ReuseRecordIDs = append(p.ReuseRecordIDs, pending.AdvisoryID)
	p.Next.SessionPageIDs = []PageRef{{0, page.AdvisoryID}}
	return f, q, p
}
func TestProducerPendingReuseCannotBypassVerifiedLateErasure(t *testing.T) {
	for _, extra := range []int{0, 1001} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			f, q, p := pendingReuseLatePlan(t, extra)
			ctx := context.Background()
			var seq, gen, records, effects, bodies int64
			for _, v := range []struct {
				q string
				p *int64
			}{{"SELECT next_seq FROM meta", &seq}, {"SELECT generation FROM meta", &gen}, {"SELECT count(*) FROM record", &records}, {"SELECT count(*) FROM erasure_effect", &effects}, {"SELECT count(*) FROM record_body", &bodies}} {
				if f.w.s.conn.QueryRowContext(ctx, v.q).Scan(v.p) != nil {
					t.Fatal(v.q)
				}
			}
			got, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil })
			want := "privacy_hold_required"
			if extra > 0 {
				want = "bulk_confirmation_required"
			}
			var held *Error
			if !errors.As(e, &held) || held.Code != want || !held.OwnerBlocked {
				var n int
				f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&n)
				snap, read := f.w.s.Snapshot(ctx, ReadRequest{IDs: []string{f.plan.NewRecords[0].AdvisoryID}})
				body := 0
				state := "unknown"
				if read == nil && len(snap.Entries) == 1 {
					body = len(snap.Entries[0].BodyJCS)
					state = snap.Entries[0].State
				}
				t.Fatalf("unavailable reuse discarded verified proof: code=%s barriers=%d originalState=%s bodyBytes=%d", Code(e), n, state, body)
			}
			if got.Status != "" || len(got.ActualRecordRefs) != 0 {
				t.Fatal("refusal returned candidate facts")
			}
			for _, v := range []struct {
				q    string
				want int64
			}{{"SELECT next_seq FROM meta", seq}, {"SELECT generation FROM meta", gen + 1}, {"SELECT count(*) FROM record", records}, {"SELECT count(*) FROM erasure_effect", effects}, {"SELECT count(*) FROM record_body", bodies}, {"SELECT count(*) FROM capture_transition", 1}, {"SELECT count(*) FROM capture_progress WHERE version=1", 1}} {
				var n int64
				if f.w.s.conn.QueryRowContext(ctx, v.q).Scan(&n) != nil || n != v.want {
					t.Fatal("nonminimal refusal", v.q, n, v.want)
				}
			}
		})
	}
}

func TestProducerUnavailableReuseVariantsDeferUntilTrustedClosure(t *testing.T) {
	for _, kind := range []string{"missing", "bodyless", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			f, q, p, _ := lateProducerPlan(t, 0, false)
			ctx := context.Background()
			r, e := record.Parse(f.plan.NewRecords[0].HeaderJCS, f.plan.NewRecords[0].BodyJCS, "")
			if e != nil {
				t.Fatal(e)
			}
			id := record.H("missing-reuse-reference")
			if kind == "bodyless" {
				bodyless := f.chunk(r.Body.(*record.ChunkBody).Events, nil)
				bodyless.BodyJCS = nil
				f.w.append(bodyless)
				id = bodyless.AdvisoryID
			}
			if kind == "revoked" {
				a := f.w.key
				b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{33}, 32))
				c := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{34}, 32))
				enroll := f.w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Genesis: f.w.o.PinnedGenesisID, Subject: sig.KeyRefOf(b.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Parents: []string{f.w.genesis.AdvisoryID}}, a, a, b)
				f.w.append(enroll)
				parent := f.w.op(record.KeyOpBody{Op: record.OpDeviceAdd, Genesis: f.w.o.PinnedGenesisID, Subject: sig.KeyRefOf(c.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Parents: []string{enroll.AdvisoryID}}, a, a, c)
				revoke := f.w.op(record.KeyOpBody{Op: record.OpDeviceRevoke, Genesis: f.w.o.PinnedGenesisID, Subject: sig.KeyRefOf(b.Public().(ed25519.PublicKey), record.RoleDevice, testMachine), Parents: []string{parent.AdvisoryID}, Reason: "compromised"}, a, a)
				f.w.append(revoke)
				f.w.key = b
				f.q.AuthorKeyID = sig.KeyID(b.Public().(ed25519.PublicKey))
				u := f.chunk(r.Body.(*record.ChunkBody).Events, nil)
				f.w.append(u)
				f.w.key = a
				f.q.AuthorKeyID = q.AuthorKeyID
				f.w.append(parent)
				id = u.AdvisoryID
				if v := find(f.w.snapshot(), id); v.SignatureStatus != "signer-revoked" {
					t.Fatal("revoked reuse fixture still eligible", v.SignatureStatus, v.State)
				}
			}
			page := f.page([]string{f.plan.NewRecords[0].AdvisoryID, p.NewRecords[0].AdvisoryID, id}, 0, f.plan.NewRecords[1].AdvisoryID)
			p.NewRecords[1] = page
			p.ReuseRecordIDs = append(p.ReuseRecordIDs, id)
			p.Next.SessionPageIDs = []PageRef{{0, page.AdvisoryID}}
			got, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil })
			var held *Error
			if !errors.As(e, &held) || held.Code != "privacy_hold_required" || !held.OwnerBlocked || got.Status != "" {
				t.Fatal("reuse state bypassed privacy closure", kind, got, e)
			}
			var n int
			if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record WHERE id IN (?,?)", p.NewRecords[0].AdvisoryID, p.NewRecords[1].AdvisoryID).Scan(&n) != nil || n != 0 {
				t.Fatal("deferred reuse persisted candidates")
			}
		})
	}
}
func TestProducerUnavailableReuseStillRejectsBadCryptoBeforeBarrier(t *testing.T) {
	f, q, p := pendingReuseLatePlan(t, 0)
	ctx := context.Background()
	p.NewRecords = append([]SignedRecord(nil), p.NewRecords...)
	p.NewRecords[1].Sigs = append([]record.Signature(nil), p.NewRecords[1].Sigs...)
	p.NewRecords[1].Sigs[0].Value = strings.Repeat("A", 86)
	if _, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return p, nil }); Code(e) != "unauthorized_record" {
		t.Fatal("unavailable reuse masked failed crypto", e)
	}
	var n int
	if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&n) != nil || n != 0 {
		t.Fatal("bad crypto created barrier")
	}
}
func TestProducerUnavailableReuseWithoutLateProofRemainsOrdinaryRollback(t *testing.T) {
	f := newProducer(t, "ordinary unavailable reuse")
	f.commit()
	ctx := context.Background()
	q := f.q
	q.ExpectedVersion = 1
	plan := CommitPlan{ReuseRecordIDs: []string{f.plan.NewRecords[0].AdvisoryID, f.plan.NewRecords[1].AdvisoryID, record.H("ordinary-missing-ref")}, Next: f.plan.Next}
	if _, e := f.w.s.Capture(ctx, q, func(*CaptureTxn) (CommitPlan, error) { return plan, nil }); Code(e) != "unavailable_reuse" {
		t.Fatal(e)
	}
	var n int
	if f.w.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&n) != nil || n != 0 {
		t.Fatal("ordinary missing reuse froze owner")
	}
	p, e := f.w.s.InspectCapture(ctx, q.Occurrence)
	if e != nil || p.Progress.Version != 1 || p.Suppression.OwnerBlocked {
		t.Fatal("ordinary refusal mutated progress", p, e)
	}
}
