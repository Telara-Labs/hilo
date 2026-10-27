package sig

import (
	"context"
	"fmt"
	"testing"

	"github.com/Telara-Labs/hilo/contract/record"
)

type historyWorkContextR17 struct {
	context.Context
	checks, cancelAt int
}

func (c *historyWorkContextR17) Err() error {
	c.checks++
	if c.cancelAt > 0 && c.checks >= c.cancelAt {
		return context.Canceled
	}
	return c.Context.Err()
}
func longHistoryR17(t *testing.T, n int) *Keyring {
	w := newWorld(t)
	kr := NewKeyring(w.gid())
	parityNoError(t, kr.Add(w.ops["genesis"]))
	parent := w.id("genesis")
	for i := 1; i < n; i++ {
		sub := key(fmt.Sprint("long-", i))
		op := w.op(fmt.Sprint(i), record.KeyOpBody{Op: record.OpDeviceAdd, Subject: KeyRefOf(pub(sub), record.RoleDevice, mB), Genesis: w.gid(), Parents: []string{parent}}, w.genesis, mA, sub, w.genesis)
		parityNoError(t, kr.Add(op))
		parent = op.Rec.ID
	}
	return kr
}
func TestRetainedHistoryLinearWorkR17(t *testing.T) {
	for _, n := range []int{1000, 2048} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			kr := longHistoryR17(t, n)
			ctx := &historyWorkContextR17{Context: context.Background()}
			st, err := kr.StateContext(ctx)
			parityNoError(t, err)
			parityLen(t, st.Keys, n)
			for _, s := range st.Status {
				parityEqual(t, OpAuthorized, s)
			}
			work := kr.Work()
			parityEqual(t, n, work.Authorizations)
			parityZero(t, work.HistoryEntries)
			parityLess(t, work.FoldSteps, 20*n)
			first := ctx.checks
			_, err = kr.StateContext(ctx)
			parityNoError(t, err)
			parityEqual(t, first+1, ctx.checks)
			copy, err := kr.CloneContext(ctx)
			parityNoError(t, err)
			_, err = copy.StateContext(ctx)
			parityNoError(t, err)
			parityEqual(t, work.Authorizations, copy.Work().Authorizations)
			t.Logf("ops=%d authorizations=%d ancestor_entries=%d fold_checkpoints=%d context_checks=%d", n, work.Authorizations, work.HistoryEntries, work.FoldSteps, first)
		})
	}
}
func TestRetainedHistoryCancellationR17(t *testing.T) {
	kr := longHistoryR17(t, 1000)
	ctx := &historyWorkContextR17{Context: context.Background(), cancelAt: 750}
	st, err := kr.StateContext(ctx)
	parityErrorIs(t, err, context.Canceled)
	parityNil(t, st)
	parityNil(t, kr.cached)
	st, err = kr.StateContext(context.Background())
	parityNoError(t, err)
	parityLen(t, st.Keys, 1000)
	ctx = &historyWorkContextR17{Context: context.Background(), cancelAt: 300}
	copy, err := kr.CloneContext(ctx)
	parityErrorIs(t, err, context.Canceled)
	parityNil(t, copy)
}

func TestRevocationCutoffWorkAndCancellationR17(t *testing.T) {
	w := newWorld(t)
	b := key("cutoff-device")
	tsk := key("cutoff-tsk")
	w.add("b", b, mB, w.genesis, mA, w.id("genesis"))
	root := w.op("tsk", record.KeyOpBody{Op: record.OpTenantKey, Subject: KeyRefOf(pub(tsk), record.RoleService, ""), Genesis: "acme"}, tsk, "", tsk)
	root.FromLogin = true
	trusted := TrustedIssuer{Tenant: "acme", Role: record.RoleService, Provenance: AuthenticatedAdmission}
	for n := 0; n < 64; n++ {
		name := fmt.Sprint("revoke-", n)
		w.revoke(name, b, mB, "lost", w.genesis, mA, w.id("b"))
		op := w.ops[name]
		r, err := SignReceipt(tsk, record.Receipt{ID: op.Rec.ID, Tenant: "acme", DeviceID: mA, AcceptedAt: int64(200 + n), HSeq: int64(2 + n), Policy: hx("policy")})
		parityNoError(t, err)
		op.Receipt = &r
		op.ReceiptIssuer = trusted
	}
	kr := NewKeyring(w.gid())
	for _, op := range w.ops {
		parityNoError(t, kr.Add(op))
	}
	st, err := kr.StateContext(context.Background())
	parityNoError(t, err)
	revoked := st.Key(KeyID(pub(b)))
	parityLen(t, revoked.RevocationCauses, 64)
	rc, err := SignReceipt(tsk, record.Receipt{ID: hx("prior"), Tenant: "acme", DeviceID: mB, AcceptedAt: 100, HSeq: 1, Policy: hx("policy")})
	parityNoError(t, err)
	cancelled := &historyWorkContextR17{Context: context.Background(), cancelAt: 10}
	parityFalse(t, PreRevocation(revoked, Context{RequestContext: cancelled, RecordID: rc.ID, Receipt: &rc, ReceiptIssuer: trusted}, st))
	parityEmpty(t, st.cutoffs)
	ctx := &historyWorkContextR17{Context: context.Background()}
	c := Context{RequestContext: ctx, RecordID: rc.ID, Receipt: &rc, ReceiptIssuer: trusted}
	parityTrue(t, PreRevocation(revoked, c, st))
	first := ctx.checks
	for n := 0; n < 1000; n++ {
		parityTrue(t, PreRevocation(revoked, c, st))
	}
	parityEqual(t, first+1000, ctx.checks, "independent receipts must not be reverified per retained entry")
	later, err := SignReceipt(tsk, record.Receipt{ID: hx("later"), Tenant: "acme", DeviceID: mB, AcceptedAt: 250, HSeq: 100, Policy: hx("policy")})
	parityNoError(t, err)
	c.RecordID = later.ID
	c.Receipt = &later
	parityFalse(t, PreRevocation(revoked, c, st))
	c.ReceiptIssuer.Tenant = "foreign"
	parityFalse(t, PreRevocation(revoked, c, st))
}

func TestHistoryBudgetPrechargesR17(t *testing.T) {
	kr := NewKeyring("")
	kr.causalBytes = maxHistoryBytes - 1
	tree, err := kr.putCausal(context.Background(), nil, "binding", &Key{})
	parityErrorIs(t, err, ErrHistoryBudget)
	parityNil(t, tree)
	budget := &historyContext{Context: context.Background(), bytes: maxHistoryBytes - 1}
	parityErrorIs(t, reserveHistory(budget, 128), ErrHistoryBudget)
	parityErrorIs(t, budget.Err(), ErrHistoryBudget, "failed revoke reservation must remain a sticky refusal")
}

// Cold reconstruction of a retained linear enrollment history (no cached
// causal state), the per-import cost before the scope keyring cache applies.
func BenchmarkRetainedHistoryColdR17(b *testing.B) {
	for _, n := range []int{1000, 2048} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			kr := longHistoryBenchR17(b, n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				kr.cached, kr.causal, kr.causalBytes = nil, nil, 0
				if _, err := kr.StateContext(context.Background()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// longHistoryBenchR17 mirrors longHistoryR17 without the *testing.T world.
func longHistoryBenchR17(b *testing.B, n int) *Keyring {
	genesis := key("A")
	gid := KeyID(pub(genesis))
	at := int64(1761150000000)
	g, err := BuildKeyOp(record.KeyOpBody{Op: record.OpGenesis, Subject: KeyRefOf(pub(genesis), record.RoleDevice, mA), Genesis: gid}, pub(genesis), mA, at, genesis)
	if err != nil {
		b.Fatal(err)
	}
	kr := NewKeyring(gid)
	if err := kr.Add(g); err != nil {
		b.Fatal(err)
	}
	parent := g.Rec.ID
	for i := 1; i < n; i++ {
		sub := key(fmt.Sprint("long-", i))
		op, err := BuildKeyOp(record.KeyOpBody{Op: record.OpDeviceAdd, Subject: KeyRefOf(pub(sub), record.RoleDevice, mB), Genesis: gid, Parents: []string{parent}}, pub(genesis), mA, at+int64(i), sub, genesis)
		if err != nil {
			b.Fatal(err)
		}
		if err := kr.Add(op); err != nil {
			b.Fatal(err)
		}
		parent = op.Rec.ID
	}
	return kr
}
