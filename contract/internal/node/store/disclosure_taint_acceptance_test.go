package store

import (
	"context"
	"github.com/Telara-Labs/hilo/contract/record"
	"testing"
)

func taintedTask(k *kernelWorld, n int, goal string) SignedRecord {
	k.t.Helper()
	r := k.task(n, goal)
	parsed, err := record.Parse(r.HeaderJCS, r.BodyJCS, "")
	if err != nil {
		k.t.Fatal(err)
	}
	h := parsed.Header
	h.Trust.Taint = []string{"foreign-path", "recalled-memory", "third-party-mcp", "web"}
	return k.signed(h, parsed.Body)
}
func TestDisclosureTaintDependencySupersessionRetainsFourTagWitnesses(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	parent := taintedTask(k, 6000, "erase_tag_source_canary")
	k.append(parent)
	child := k.task(6001, "direct dependent", parent.AdvisoryID)
	k.append(child)
	grandchild := k.task(6002, "transitive dependent", child.AdvisoryID)
	k.append(grandchild)
	// A new clean head supersedes the source version. Descendants still name the
	// exact historical source and retain its observed union independently of heads.
	parsed, err := record.Parse(parent.HeaderJCS, parent.BodyJCS, "")
	if err != nil {
		t.Fatal(err)
	}
	h := parsed.Header
	h.Trust.Taint = nil
	h.Links.Supersedes = []string{parent.AdvisoryID}
	clean := k.signed(h, &record.TaskBody{Name: "clean corrected source", Goal: "clean corrected source", Status: "active"})
	k.append(clean)
	check := func() {
		t.Helper()
		for _, id := range []string{parent.AdvisoryID, child.AdvisoryID, grandchild.AdvisoryID} {
			var n int
			k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_observed_taint WHERE id=?", id).Scan(&n)
			if n != 4 {
				t.Fatal("four-tag union lost", id, n)
			}
		}
		var n int
		k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_taint_evidence WHERE id=? AND kind='dependency' AND source=?", grandchild.AdvisoryID, child.AdvisoryID).Scan(&n)
		if n != 4 {
			t.Fatal("direct transitive witness lost", n)
		}
	}
	check()
	if err = k.s.Reindex(ctx); err != nil {
		t.Fatal(err)
	}
	check()
	control := k.control(6003, record.KindErasure, parent.AdvisoryID)
	k.append(control)
	check()
	if done, err := k.s.Scrub(ctx, control.AdvisoryID); err != nil || done.State != "complete" {
		t.Fatal("taint-body scrub", done, err)
	}
	check()
	k.s.Close()
	st, err := Open(ctx, k.o)
	if err != nil {
		t.Fatal(err)
	}
	k.s = st
	check()
	var n int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_taint_evidence WHERE instr(evidence,'canary')>0 OR instr(source,'canary')>0 OR instr(boundary,'canary')>0").Scan(&n)
	if n != 0 {
		t.Fatal("taint authority retained source text")
	}
}
func TestDisclosureTaintWitnessOverflowAndInvalidCryptoAreAtomic(t *testing.T) {
	k := newKernel(t)
	ctx := context.Background()
	parent := taintedTask(k, 9000, "unaccepted_taint_source_canary")
	var inputs []SignedRecord
	for i := 0; i < 2100; i++ {
		inputs = append(inputs, k.task(10000+i, "pending dependent", parent.AdvisoryID))
	}
	k.seedPending(inputs)
	before := disclosureTransactionState(t, k)
	invalid := parent
	invalid.Sigs = append([]record.Signature(nil), parent.Sigs...)
	invalid.Sigs[0].Value = invalid.Sigs[0].Value[:85] + "A"
	if invalid.Sigs[0].Value == parent.Sigs[0].Value {
		invalid.Sigs[0].Value = parent.Sigs[0].Value[:85] + "B"
	}
	if _, err := k.s.Append(ctx, invalid); err == nil {
		t.Fatal("invalid taint signature accepted")
	}
	requireSameDisclosureState(t, k, before)
	if _, err := k.s.Append(ctx, parent); Code(err) != "taint_projection_limit" {
		t.Fatal("witness overflow did not refuse whole admission", err)
	}
	requireSameDisclosureState(t, k, before)
	var n int
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM record_observed_taint").Scan(&n)
	if n != 0 {
		t.Fatal("partial uncommitted observed authority")
	}
	k.s.conn.QueryRowContext(ctx, "SELECT count(*) FROM privacy_barrier").Scan(&n)
	if n != 0 {
		t.Fatal("unaccepted taint candidate froze owner")
	}
}
