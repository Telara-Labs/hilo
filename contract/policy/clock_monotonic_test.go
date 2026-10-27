package policy

import (
	"fmt"
	"math"
	"testing"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
)

func TestClockAcceptsLargeRuntimeMonotonicOffsets(t *testing.T) {
	for _, base := range []int64{0, jcs.MaxSafeInteger + 1, math.MaxInt64 - 30001} {
		for _, rtt := range []int64{0, 20, 30000} {
			t.Run(fmt.Sprintf("base=%d/rtt=%d", base, rtt), func(t *testing.T) {
				c := RestoreClock(t0 + 2000)
				c.Now(t0, 0)
				o := observation(t0+3000, base, base+rtt, t0)
				if err := c.ObserveAnchor(o); err != nil || c.Rollback() || c.Floor() != t0+3000 {
					t.Fatal("runtime offset was treated as a JCS wall value", err)
				}
				// The MaxSafeInteger+1/zero-RTT case is the original fork review
				// observation, now explicitly positive under the runtime domain.
				if got := c.Now(t0, o.ReceiptMono+1); got != t0+3001 || c.Rollback() {
					t.Fatal("small delta at large offset lost safe trusted time", got)
				}
				if got := c.Now(t0, o.ReceiptMono+1); got != t0+3001 || c.Rollback() {
					t.Fatal("equal receipt baseline regressed", got)
				}
			})
		}
	}
}

// Preserve the five normative negative edits from the fork's original
// TestV3AnchorRejectsInvalidReceiptAndOrigin. That original file is unchanged.
func TestClockRetainsReceiptAndOriginRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*DateObservation)
	}{
		{"wall-over-safe", func(a *DateObservation) { a.ReceiptWall = jcs.MaxSafeInteger + 1 }},
		{"wall-negative", func(a *DateObservation) { a.ReceiptWall = -1 }},
		{"wrong-endpoint", func(a *DateObservation) { a.ConfiguredEndpoint = false }},
		{"unauthenticated", func(a *DateObservation) { a.Authenticated = false }},
		{"unbound-response", func(a *DateObservation) { a.BoundLiveResponse = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := RestoreClock(t0 + 2000)
			c.Now(t0, 0)
			a := observation(t0+3000, 100, 100, t0)
			tc.edit(&a)
			if err := c.ObserveAnchor(a); err == nil || !c.Rollback() {
				t.Fatal("invalid observation cleared rollback", a)
			}
			if c.anchored || c.Floor() < t0+2000 {
				t.Fatal("refused observation published an anchor or lowered high water")
			}
		})
	}
}

func TestClockLargeOffsetsStillRefuseRegressionAndOverflow(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*DateObservation)
	}{
		{"negative-start", func(a *DateObservation) { a.RequestStartMono = -1 }},
		{"negative-receipt", func(a *DateObservation) { a.ReceiptMono = -1 }},
		{"receipt-before-start", func(a *DateObservation) { a.RequestStartMono = a.ReceiptMono + 1 }},
		{"receipt-before-baseline", func(a *DateObservation) { a.RequestStartMono, a.ReceiptMono = 0, 100 }},
		{"large-offset-long-rtt", func(a *DateObservation) {
			a.RequestStartMono, a.ReceiptMono = jcs.MaxSafeInteger+1, jcs.MaxSafeInteger+30002
		}},
		{"negative-start-max-receipt", func(a *DateObservation) { a.RequestStartMono, a.ReceiptMono = math.MinInt64, math.MaxInt64 }},
		{"stale-upper-bound", func(a *DateObservation) { a.Date = 1 }},
		{"upper-bound-overflow", func(a *DateObservation) { a.Date = jcs.MaxSafeInteger }},
		{"server-time-disagrees", func(a *DateObservation) { a.ServerTime = a.Date + 1000 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := RestoreClock(0)
			if err := c.ObserveAnchor(observation(t0, 0, 10, t0)); err != nil {
				t.Fatal(err)
			}
			c.Now(t0, 100)
			c.Now(t0-1, 101)
			date, mono, floor := c.anchorDate, c.anchorMono, c.Floor()
			a := observation(t0+1000, 101, 110, t0-1)
			tc.edit(&a)
			if err := c.ObserveAnchor(a); err == nil || !c.Rollback() {
				t.Fatal("invalid runtime observation acknowledged rollback", err)
			}
			if c.anchorDate != date || c.anchorMono != mono || c.Floor() < floor || c.Floor() > jcs.MaxSafeInteger {
				t.Fatal("rejected observation changed anchor or wrapped high water")
			}
		})
	}
	// A huge elapsed delta cannot wrap the safe wall-time projection, even
	// though its monotonic input is a valid nonnegative int64 reading.
	c := RestoreClock(0)
	if err := c.ObserveAnchor(observation(jcs.MaxSafeInteger-1000, 0, 0, jcs.MaxSafeInteger-1000)); err != nil {
		t.Fatal(err)
	}
	if got := c.Now(jcs.MaxSafeInteger-1000, math.MaxInt64); got != jcs.MaxSafeInteger || !c.Rollback() {
		t.Fatal("elapsed-time projection overflow did not fail closed", got)
	}
}
