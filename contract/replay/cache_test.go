package replay

import (
	"errors"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"testing"
)

func TestStableOperationAndDisclosureReplay(t *testing.T) {
	op, _ := record.SuppliedOpID("installed-credential", "retry-7")
	again, _ := record.SuppliedOpID("installed-credential", "retry-7")
	other, _ := record.SuppliedOpID("other-credential", "retry-7")
	if op != again || op == other {
		t.Fatal("credential namespace")
	}
	cache := New()
	args := record.H("redacted-args")
	if err := cache.Commit(op, Outcome{Tool: "conclude", ArgsHash: args, Text: "old clean", RenderVersion: "v1"}); err != nil {
		t.Fatal(err)
	}
	if err := cache.Commit(op, Outcome{Tool: "erase", ArgsHash: args}); !errors.Is(err, ErrConflict) {
		t.Fatal("changed tool accepted")
	}
	mutations := 0
	text, ok, err := cache.Replay(op, "conclude", args, true, "v2", func(o Outcome) (string, error) { return "web-tainted now", nil })
	if err != nil || !ok || text != "web-tainted now" {
		t.Fatal(text, err)
	}
	text, _, _ = cache.Replay(op, "conclude", args, false, "v2", nil)
	if text != Unavailable || mutations != 0 {
		t.Fatal("held or narrowed grant disclosed cached text")
	}
	o, _, _ := cache.Lookup(op, "conclude", args)
	if o.Text != "" {
		t.Fatal("old text retained")
	}
}
func TestDeliveryConfirmationGeneration(t *testing.T) {
	d := NewDelivery()
	g := d.Expose("r")
	if d.Confirmed("r") || !d.Exposed("r") {
		t.Fatal("exposure is not confirmation")
	}
	if !d.Confirm("r", g) {
		t.Fatal("echo failed")
	}
	d.Compact()
	g2 := d.Expose("r")
	if g2 == g || d.Confirm("r", g) || d.Confirmed("r") {
		t.Fatal("old ACK suppressed new context")
	}
	if !d.Confirm("r", g2) {
		t.Fatal("new ACK failed")
	}
}
