package policy

import (
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"testing"
)

func observation(date, start, mono, wall int64) DateObservation {
	return DateObservation{Date: date, RequestStartMono: start, ReceiptMono: mono, ReceiptWall: wall, Authenticated: true, ConfiguredEndpoint: true, BoundLiveResponse: true, NoStore: true, DateCount: 1}
}
func TestV3DatePrecisionFreshnessAndHighWater(t *testing.T) {
	for _, rtt := range []int64{0, 20, 30000} {
		c := RestoreClock(0)
		d := int64(1700000000000)
		if err := c.ObserveAnchor(observation(d, 0, rtt, d+456)); err != nil || c.Floor() != d+456 {
			t.Fatal("synchronized initial anchor rejected", rtt, err)
		}
		prior := c.Now(d+900, 30000+rtt)
		// Refresh evaluates the old anchor at receipt BEFORE accepting bounded lag.
		nextD := d + 30000
		if err := c.ObserveAnchor(observation(nextD, 30000+rtt, 30020+rtt, nextD+456)); err != nil || c.Floor() < prior {
			t.Fatal("synchronized refresh", err)
		}
		if got := c.Now(nextD+456, 30020+rtt); got < c.Floor() {
			t.Fatal("runtime time rewound")
		}
	}
	c := RestoreClock(10000)
	c.Now(9000, 0)
	if err := c.ObserveAnchor(observation(8000, 0, 20, 9000)); err == nil || !c.Rollback() || c.Floor() != 10000 {
		t.Fatal("stale U cleared rollback")
	}
	if err := c.ObserveAnchor(observation(9500, 20, 40, 9000)); err != nil || c.Rollback() || c.Floor() != 10000 {
		t.Fatal("bounded D<W recovery", err)
	}
	c.Now(8999, 41)
	if !c.Rollback() {
		t.Fatal("new wall regression not latched")
	}
	c.ObserveDate(20000, 42, 8999)
	if !c.Rollback() {
		t.Fatal("Date alone recovered")
	}
	restored := RestoreClock(c.Floor())
	if restored.Now(0, 0) < c.Floor() || !restored.Rollback() {
		t.Fatal("restart floor lost")
	}
}
func TestV3RejectsUntrustedDates(t *testing.T) {
	for _, mutate := range []func(*DateObservation){
		func(o *DateObservation) { o.Authenticated = false }, func(o *DateObservation) { o.ConfiguredEndpoint = false }, func(o *DateObservation) { o.BoundLiveResponse = false }, func(o *DateObservation) { o.NoStore = false }, func(o *DateObservation) { o.DateCount = 2 }, func(o *DateObservation) { o.Age = 1 }, func(o *DateObservation) { o.ReceiptMono = 30001 }, func(o *DateObservation) { o.RequestStartMono = 2; o.ReceiptMono = 1 }, func(o *DateObservation) { o.ServerTime = o.Date + 1000 }, func(o *DateObservation) { o.Date = jcs.MaxSafeInteger }, func(o *DateObservation) { o.Date = -1 },
	} {
		c := RestoreClock(1000)
		c.Now(900, 0)
		o := observation(1100, 0, 1, 900)
		mutate(&o)
		if c.ObserveAnchor(o) == nil || !c.Rollback() {
			t.Fatal("untrusted/stale/overflow anchor accepted")
		}
	}
	c := RestoreClock(0)
	c.Now(1000, 100)
	if c.ObserveAnchor(observation(1100, 80, 90, 1000)) == nil {
		t.Fatal("request-start monotonic regression accepted")
	}
	c = RestoreClock(0)
	c.ObserveAnchor(observation(jcs.MaxSafeInteger-1000, 0, 0, jcs.MaxSafeInteger-1000))
	c.Now(1, 2000)
	if !c.Rollback() || c.Floor() != jcs.MaxSafeInteger {
		t.Fatal("anchor arithmetic wrapped")
	}
}
func TestV3OneTenantAndOmittedCeiling(t *testing.T) {
	var s LoginState
	if s.Login("one") != nil || s.Login("one") != nil || s.Login("two") == nil || s.ActiveTenant != "one" {
		t.Fatal("second authority admitted")
	}
	s.Logout()
	if s.Login("two") != nil {
		t.Fatal("explicit logout did not release active tenant")
	}
	b := body(1)
	b.Push = record.PolicyPush{AllowRepos: []string{"*"}, RequirePreview: true}
	if MaxProfile(&b) != record.ProfileLocal || PushAllowed(&b, "github.com/acme/api") {
		t.Fatal("omitted ceiling allowed data")
	}
	b.Push.MaxProfile = record.ProfilePushMetadata
	if !PushAllowed(&b, "github.com/acme/api") {
		t.Fatal("explicit metadata ceiling refused")
	}
}

func TestV3PolicyReplacementLogoutAndTamperFacts(t *testing.T) {
	c := NewChain("acme")
	b := body(1)
	b.Salt = "AAAAAAAAAAAAAAAAAAAAAA"
	p := &Policy{ID: "p1", Body: &b}
	c.Offer(p)
	old := c.Head.Body
	// Caller mutation must never alter the accepted authority snapshot.
	b.Kill.Sync = true
	if c.Head.Body.Kill.Sync {
		t.Fatal("caller policy aliases authority")
	}
	conflict := body(1)
	conflict.Salt = "AQEBAQEBAQEBAQEBAQEBAQ"
	c.Offer(&Policy{ID: "conflict", Body: &conflict})
	if !c.Tampered {
		t.Fatal("verified same-Seq conflict not latched")
	}
	c.Logout()
	if old.Salt != "" || len(old.Applies.Users) != 0 || c.HighestSeq != 1 || !c.Tampered {
		t.Fatal("logout retained secret or erased security facts")
	}
	c.Offer(p)
	if !c.Tampered {
		t.Fatal("same-id login cleared latch")
	}
	c.Offer(&Policy{ID: "lower", Body: func() *record.PolicyBody { x := body(0); return &x }()})
	if !c.Tampered {
		t.Fatal("rollback cleared latch")
	}
	high := body(2)
	high.Salt = "AgICAgICAgICAgICAgICAg"
	prior := c.Head.Body
	c.Offer(&Policy{ID: "p2", Body: &high})
	if c.Tampered || c.HighestSeq != 2 || prior.Salt != "" || c.Head.Body.Salt != high.Salt {
		t.Fatal("higher-seq replacement lifecycle")
	}
}

func TestV3SelfReviewLogoutTamperAndMonotonicBaseline(t *testing.T) {
	c := NewChain("acme")
	b := body(1)
	c.Offer(&Policy{ID: "one", Body: &b})
	c.Offer(&Policy{ID: "conflict", Body: &b})
	c.Logout()
	if Evaluate(c, RestoreClock(0), t0, false) != TamperedHead || EffectsOf(c, NoPolicy).DataPush {
		t.Error("logout bypassed retained tamper latch")
	}
	clock := RestoreClock(0)
	clock.Now(1000, 100)
	clock.Now(900, 90)
	if clock.ObserveAnchor(observation(1100, 90, 95, 900)) == nil {
		t.Error("backward observation lowered monotonic acceptance baseline")
	}
}

func TestV3SelfReviewUnknownRepoAndGlobalBlock(t *testing.T) {
	b := body(1)
	b.Push.AllowRepos = []string{"*"}
	if PushAllowed(&b, "") {
		t.Error("unknown governed repo allowed")
	}
	b.BlockedRepos = []record.BlockedRepo{{RemoteGlob: "*", Effect: "no-capture"}}
	if PushAllowed(&b, "github.com/acme/api") {
		t.Error("global block failed across path separators")
	}
}

func TestV3TamperBlocksAllTenantReadback(t *testing.T) {
	c := NewChain("acme")
	b := body(1)
	c.Offer(&Policy{ID: "p", Body: &b})
	c.Offer(&Policy{ID: "different", Body: &b})
	for _, state := range []Freshness{TamperedHead, Expired, RolledBack, Invalid} {
		if EffectsOf(c, state).TenantReadback {
			t.Fatal("stale/tampered tenant read-back allowed", state)
		}
	}
	c.Logout()
	if EffectsOf(c, NoPolicy).TenantReadback {
		t.Fatal("logout bypassed retained tamper")
	}
	higher := body(2)
	c.Offer(&Policy{ID: "higher", Body: &higher})
	if !EffectsOf(c, Fresh).TenantReadback {
		t.Fatal("higher verified fresh policy did not restore tenant read-back")
	}
}
