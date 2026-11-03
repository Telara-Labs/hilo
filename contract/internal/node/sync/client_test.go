package sync

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
)

func TestPushMetadataReceiptAndIndependentCursors(t *testing.T) {
	f := newFixture(t, 2)
	original := f.outbox.op.Bytes()
	ack, err := f.client.Push(context.Background())
	if err != nil {
		t.Fatal(err, f.handlerErr)
	}
	if len(ack.Results) != 2 || f.outbox.completes != 1 || f.outbox.ctlCursor != 2 || f.outbox.dataCursor != 3 {
		t.Fatalf("bad completion %#v", ack)
	}
	if !bytes.Equal(original, f.requests[0]) {
		t.Fatal("mutated request")
	}
	if f.mintCount != 1 || f.pushCount != 1 {
		t.Fatal("request counts")
	}
	if ack, err = f.client.Push(context.Background()); err != nil || ack != nil {
		t.Fatal("empty outbox", err)
	}
}
func TestRetryExactBytesFreshProofAndDuplicateReceipt(t *testing.T) {
	for _, status := range []int{-1, 429, 500, 502, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newFixture(t, 2)
			f.statuses = []int{status, 200}
			f.retryAfter = "999999999999"
			original := f.outbox.op.Bytes()
			var delays []time.Duration
			f.client.wait = func(_ context.Context, d time.Duration) error { delays = append(delays, d); return nil }
			ack, err := f.client.Push(context.Background())
			if err != nil {
				t.Fatal(err, f.handlerErr)
			}
			if f.pushCount != 2 || f.outbox.authCalls != 2 || f.outbox.completes != 1 || len(delays) != 1 {
				t.Fatal("retry/completion counts")
			}
			if delays[0] < 0 || delays[0] > 5*time.Minute || status != -1 && delays[0] != 5*time.Minute {
				t.Fatal("retry delay", delays)
			}
			for _, body := range f.requests {
				if !bytes.Equal(body, original) {
					t.Fatal("changed signed bytes or op_id")
				}
			}
			if f.proofs[0] == f.proofs[1] {
				t.Fatal("proof reused")
			}
			if status == -1 && ack.Results[0].Status != "accepted-duplicate" {
				t.Fatal("lost reply did not recover stored receipt")
			}
		})
	}
}
func Test401RefreshOnceAnd403Latch(t *testing.T) {
	for _, statuses := range [][]int{{401, 200}, {401, 401}, {403}, {401, 403}} {
		t.Run(strings.TrimSpace(strings.Repeat("x", len(statuses)))+http.StatusText(statuses[len(statuses)-1]), func(t *testing.T) {
			f := newFixture(t, 1)
			f.statuses = statuses
			_, err := f.client.Push(context.Background())
			wantMints := 2
			if statuses[0] == 403 {
				wantMints = 1
			}
			if f.mintCount != wantMints || f.pushCount != len(statuses) {
				t.Fatal("refresh loop", f.mintCount, f.pushCount)
			}
			switch statuses[len(statuses)-1] {
			case 200:
				if err != nil {
					t.Fatal(err)
				}
			case 401:
				var h *httpFailure
				if !errors.As(err, &h) || h.status != 401 || f.outbox.completes != 0 {
					t.Fatal(err)
				}
			case 403:
				if !errors.Is(err, ErrForbidden) {
					t.Fatal(err)
				}
				before := f.pushCount
				_, err = f.client.Push(context.Background())
				if !errors.Is(err, ErrForbidden) || before != f.pushCount {
					t.Fatal("403 path resumed")
				}
			}
		})
	}
}
func TestBadReceiptsNeverCommitPartialBatch(t *testing.T) {
	cases := map[string]func([]Result) []Result{
		"missing-result":           func(r []Result) []Result { return r[:1] },
		"empty":                    func([]Result) []Result { return nil },
		"duplicate":                func(r []Result) []Result { r[1] = r[0]; return r },
		"unknown-id":               func(r []Result) []Result { r[0].ID = strings.Repeat("d", 64); return r },
		"missing-receipt":          func(r []Result) []Result { r[0].Receipt = nil; return r },
		"tamper-signature":         func(r []Result) []Result { r[0].Receipt.Policy = strings.Repeat("e", 64); return r },
		"wrong-hseq":               func(r []Result) []Result { r[0].HSeq++; return r },
		"wrong-device":             func(r []Result) []Result { r[0].Receipt.DeviceID = "33333333-3333-4333-8333-333333333333"; return r },
		"wrong-tenant":             func(r []Result) []Result { r[0].Receipt.Tenant = "tenant-two"; return r },
		"wrong-record":             func(r []Result) []Result { r[0].Receipt.ID = r[1].ID; return r },
		"unknown-status":           func(r []Result) []Result { r[0].Status = "success"; return r },
		"unavailable-with-receipt": func(r []Result) []Result { r[0].Status = "unavailable"; return r },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 2)
			f.response = mutate
			_, err := f.client.Push(context.Background())
			if !errors.Is(err, ErrReceipt) || f.outbox.completes != 0 || f.outbox.dataCursor != 3 || f.outbox.ctlCursor != 2 {
				t.Fatal("partial/invalid receipt committed", err)
			}
		})
	}
}
func TestUnavailableIsTerminalWithoutReceipt(t *testing.T) {
	f := newFixture(t, 2)
	f.response = func(r []Result) []Result { r[0] = Result{ID: r[0].ID, Status: "unavailable"}; return r }
	ack, err := f.client.Push(context.Background())
	if err != nil || f.outbox.completes != 1 || ack.Results[0].Receipt != nil {
		t.Fatal(err)
	}
}
func TestReceiptRequiresCurrentPinnedTenantKey(t *testing.T) {
	for _, bad := range []string{"missing", "revoked", "wrong-role", "wrong-domain", "lookup-failure"} {
		t.Run(bad, func(t *testing.T) {
			f := newFixture(t, 1)
			for _, k := range f.keys.state.Keys {
				switch bad {
				case "revoked":
					k.Status = sig.KeyRevoked
				case "wrong-role":
					k.Role = record.RolePolicy
				case "wrong-domain":
					k.Tenant = "tenant-two"
				}
			}
			if bad == "missing" {
				f.keys.state.Keys = nil
			}
			if bad == "lookup-failure" {
				f.keys.err = errors.New("private internal failure")
			}
			_, err := f.client.Push(context.Background())
			if !errors.Is(err, ErrReceipt) || f.outbox.completes != 0 {
				t.Fatal(err)
			}
		})
	}
}
func TestReceiptRetiredKeyAllowed(t *testing.T) {
	f := newFixture(t, 1)
	for _, k := range f.keys.state.Keys {
		k.Status = sig.KeyRetired
	}
	if _, err := f.client.Push(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestAuthorityRecheckedAfterRetryAndMint(t *testing.T) {
	f := newFixture(t, 1)
	f.statuses = []int{503}
	f.client.wait = func(context.Context, time.Duration) error { f.outbox.authorized = false; return nil }
	_, err := f.client.Push(context.Background())
	if !errors.Is(err, ErrCancelled) || f.pushCount != 1 || f.outbox.authCalls != 2 || f.outbox.completes != 0 {
		t.Fatal(err)
	}
}
func TestMutationOnRetryDoesNotChangeOperation(t *testing.T) {
	f := newFixture(t, 1)
	original := f.outbox.op.Bytes()
	f.statuses = []int{503}
	f.client.wait = func(context.Context, time.Duration) error { f.outbox.op.raw[0] = '['; return nil }
	_, err := f.client.Push(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range f.requests {
		if !bytes.Equal(raw, original) {
			t.Fatal("outbox mutated retry")
		}
	}
}
func TestRestoreMutationRefusedBeforeNetwork(t *testing.T) {
	f := newFixture(t, 1)
	f.outbox.op.raw[0] = '['
	_, err := f.client.Push(context.Background())
	if !errors.Is(err, ErrInvalid) || f.mintCount != 0 || f.pushCount != 0 {
		t.Fatal(err)
	}
}
func TestNoCredentialRedirects(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			f := newFixture(t, 1)
			var hits atomic.Int32
			sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
			defer sink.Close()
			f.redirect = sink.URL + "/steal"
			f.statuses = []int{code}
			_, err := f.client.Push(context.Background())
			if err == nil || hits.Load() != 0 || f.outbox.completes != 0 {
				t.Fatal("credential redirect", err, hits.Load())
			}
		})
	}
}
func TestTLSVerificationMandatory(t *testing.T) {
	f := newFixture(t, 1)
	cfg := f.client.cfg
	cfg.TLSRoots = nil
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.cfg.MaxRetries = 1
	c.wait = func(context.Context, time.Duration) error { return nil }
	defer c.http.CloseIdleConnections()
	_, err = c.Push(context.Background())
	if !errors.Is(err, errNetwork) || f.mintCount != 0 {
		t.Fatal(err)
	}
}
func TestRetryBudgetAndCancellation(t *testing.T) {
	f := newFixture(t, 1)
	f.statuses = []int{503, 503, 503, 503}
	f.client.cfg.MaxRetries = 2
	_, err := f.client.Push(context.Background())
	if err == nil || f.pushCount != 3 || f.outbox.completes != 0 {
		t.Fatal(err, f.pushCount)
	}
	f = newFixture(t, 1)
	f.statuses = []int{429}
	ctx, cancel := context.WithCancel(context.Background())
	f.client.wait = func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }
	_, err = f.client.Push(ctx)
	if !errors.Is(err, context.Canceled) || f.pushCount != 1 {
		t.Fatal(err)
	}
}
func TestMintTransientRetriesAndBootstrapDenial(t *testing.T) {
	for _, statuses := range [][]int{{503, 200}, {429, 200}, {401}, {403}} {
		t.Run(http.StatusText(statuses[0]), func(t *testing.T) {
			f := newFixture(t, 1)
			f.mintStatuses = statuses
			_, err := f.client.Push(context.Background())
			if len(statuses) == 2 {
				if err != nil || f.mintCount != 2 || f.pushCount != 1 {
					t.Fatal(err)
				}
			} else if err == nil || f.mintCount != 1 || f.pushCount != 0 {
				t.Fatal(err)
			}
		})
	}
}
func TestOutboxFailuresNoFalseCompletion(t *testing.T) {
	for _, stage := range []string{"next", "authorize", "complete"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t, 1)
			sentinel := errors.New("storage_unavailable")
			switch stage {
			case "next":
				f.outbox.nextErr = sentinel
			case "authorize":
				f.outbox.authErr = sentinel
			case "complete":
				f.outbox.completeErr = sentinel
			}
			_, err := f.client.Push(context.Background())
			if !errors.Is(err, sentinel) || f.outbox.completes != 0 {
				t.Fatal(err)
			}
		})
	}
}
func TestKeystoreUnavailableNoPlaintextFallback(t *testing.T) {
	f := newFixture(t, 1)
	f.client.cfg.Keystore = OSKeystore{}
	_, err := f.client.Push(context.Background())
	if !errors.Is(err, ErrKeystoreUnavailable) || f.mintCount != 0 {
		t.Fatal(err)
	}
	if err = (OSKeystore{}).DeleteTenant(context.Background(), f.scope); !errors.Is(err, ErrKeystoreUnavailable) {
		t.Fatal(err)
	}
}
func TestLogoutTenantIsolationAndNoMoreSends(t *testing.T) {
	f := newFixture(t, 1)
	if err := f.client.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.keystore.tenants["tenant-two"]; !ok {
		t.Fatal("other tenant deleted")
	}
	if len(f.keystore.deleted) != 1 || f.keystore.deleted[0] != f.scope.Tenant || f.outbox.logouts != 1 {
		t.Fatal("logout scope")
	}
	_, err := f.client.Push(context.Background())
	if !errors.Is(err, ErrLoggedOut) || f.pushCount != 0 {
		t.Fatal(err)
	}
}
func TestLogoutAttemptsBothCleanupPathsOnFailure(t *testing.T) {
	f := newFixture(t, 1)
	f.keystore.deleteErr = ErrKeystoreUnavailable
	f.outbox.logoutErr = ErrInvalid
	err := f.client.Logout(context.Background())
	if !errors.Is(err, ErrKeystoreUnavailable) || !errors.Is(err, ErrInvalid) || f.outbox.logouts != 1 {
		t.Fatal(err)
	}
}
func TestLogoutCancelsInFlightRetry(t *testing.T) {
	f := newFixture(t, 1)
	f.statuses = []int{503}
	waiting := make(chan struct{})
	f.client.wait = func(ctx context.Context, _ time.Duration) error { close(waiting); <-ctx.Done(); return ctx.Err() }
	done := make(chan error, 1)
	go func() { _, err := f.client.Push(context.Background()); done <- err }()
	<-waiting
	if err := f.client.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrLoggedOut) {
		t.Fatal(err)
	}
}
func TestOneRoundAtATime(t *testing.T) {
	f := newFixture(t, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	f.outbox.beforeAuth = func() { close(entered); <-release }
	done := make(chan error, 1)
	go func() { _, err := f.client.Push(context.Background()); done <- err }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.client.Push(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestProofReplayAndTokenTheft(t *testing.T) {
	f := newFixture(t, 1)
	if _, err := f.client.Push(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The actual already-consumed proof is rejected by the same HTTP endpoint.
	r, _ := http.NewRequest("POST", f.server.URL+"/v1/memory/import", bytes.NewReader(f.requests[0]))
	r.Header.Set("Authorization", "DPoP "+f.tokens[0])
	r.Header.Set("DPoP", f.proofs[0])
	resp, err := f.server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("replay accepted")
	}
	// Theft of a token does not let another P-256 key use it.
	stolen, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	stolenJWK, _ := jwk(&stolen.PublicKey)
	stolenStore := &fakeKeystore{tenants: map[string]fixtureCredentials{f.scope.Tenant: {"", stolen}}}
	p, _ := proof(context.Background(), &fakeSigner{stolenStore, f.scope, stolenJWK}, "POST", f.server.URL+"/v1/memory/import", f.tokens[0], time.Now().Unix())
	r, _ = http.NewRequest("POST", f.server.URL+"/v1/memory/import", bytes.NewReader(f.requests[0]))
	r.Header.Set("Authorization", "DPoP "+f.tokens[0])
	r.Header.Set("DPoP", p)
	resp, err = f.server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("stolen token accepted")
	}
}
func TestProofRejectsWrongBindingTimeAndPrivateKey(t *testing.T) {
	f := newFixture(t, 0)
	target := f.server.URL + "/v1/memory/import"
	for _, name := range []string{"method", "url", "ath", "old", "future", "private-key", "algorithm", "signature"} {
		t.Run(name, func(t *testing.T) {
			jw, _ := jwk(&f.dpopKey.PublicKey)
			header := map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": jw}
			hash := sha256Token("token")
			claims := map[string]any{"htm": "POST", "htu": target, "ath": hash, "jti": name, "iat": time.Now().Unix()}
			switch name {
			case "method":
				claims["htm"] = "GET"
			case "url":
				claims["htu"] = target + "-other"
			case "ath":
				claims["ath"] = "wrong"
			case "old":
				claims["iat"] = time.Now().Add(-61 * time.Second).Unix()
			case "future":
				claims["iat"] = time.Now().Add(time.Minute).Unix()
			case "private-key":
				header["jwk"] = map[string]any{"crv": jw.Crv, "kty": jw.Kty, "x": jw.X, "y": jw.Y, "d": "private"}
			case "algorithm":
				header["alg"] = "HS256"
			}
			p, _ := signJWT(f.dpopKey, header, claims)
			if name == "signature" {
				p = p[:len(p)-5] + "AAAAA"
			}
			if _, err := fixtureProof(p, "POST", target, "token", time.Now(), map[string]bool{}); err == nil {
				t.Fatal("malicious proof accepted")
			}
		})
	}
}
func sha256Token(s string) string { sum := sha256.Sum256([]byte(s)); return b64.EncodeToString(sum[:]) }
func TestResponseBoundsAndUnknownFields(t *testing.T) {
	for _, name := range []string{"oversize", "duplicate", "unknown", "trailing", "compression"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1)
			old := f.client.http.Transport
			f.client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/session") {
					return old.RoundTrip(r)
				}
				body := `{"results":[]}`
				header := http.Header{}
				switch name {
				case "oversize":
					body = strings.Repeat(" ", maxResponseBytes+1)
				case "duplicate":
					body = `{"results":[],"results":[]}`
				case "unknown":
					body = `{"results":[],"extra":true}`
				case "trailing":
					body += `{}`
				case "compression":
					header.Set("Content-Encoding", "gzip")
				}
				return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			_, err := f.client.Push(context.Background())
			if err == nil || f.outbox.completes != 0 {
				t.Fatal(err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (r roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return r(req) }

// Compile-time checks keep fake adapters aligned with the public boundaries.
var _ Outbox = (*fakeOutbox)(nil)
var _ Keystore = (*fakeKeystore)(nil)
var _ KeyState = (*fakeKeys)(nil)

func TestRetryDeadlinePersistedAndPersistenceFailure(t *testing.T) {
	f := newFixture(t, 1)
	f.statuses = []int{429, 503, 503}
	f.retryAfter = "300"
	f.client.cfg.MaxRetries = 1
	before := time.Now()
	_, err := f.client.Push(context.Background())
	var scheduled *RetryError
	if !errors.As(err, &scheduled) || scheduled.After != 5*time.Minute || len(f.outbox.retries) != 2 || f.outbox.retries[1].NotBefore.Before(before.Add(5*time.Minute)) {
		t.Fatal("missing durable retry", err)
	}
	f = newFixture(t, 1)
	f.statuses = []int{503}
	sentinel := errors.New("cannot_persist_retry")
	f.outbox.retryErr = sentinel
	if _, err = f.client.Push(context.Background()); !errors.Is(err, sentinel) || f.pushCount != 1 || f.outbox.completes != 0 {
		t.Fatal(err)
	}
}
func TestInitialAuthorityRefusalSendsNoMetadata(t *testing.T) {
	f := newFixture(t, 1)
	f.outbox.authorized = false
	_, err := f.client.Push(context.Background())
	if !errors.Is(err, ErrCancelled) || f.pushCount != 0 || f.outbox.completes != 0 {
		t.Fatal(err)
	}
}
func TestPartialAckCanBeRecoveredWithSameBytes(t *testing.T) {
	f := newFixture(t, 2)
	original := f.outbox.op.Bytes()
	f.response = func(r []Result) []Result { return r[:1] }
	_, err := f.client.Push(context.Background())
	if !errors.Is(err, ErrReceipt) || f.outbox.op == nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.response = nil
	f.mu.Unlock()
	ack, err := f.client.Push(context.Background())
	if err != nil || f.outbox.completes != 1 {
		t.Fatal(err)
	}
	for _, r := range ack.Results {
		if r.Status != "accepted-duplicate" {
			t.Fatal("missing stored duplicate receipt")
		}
	}
	if !bytes.Equal(original, f.requests[1]) {
		t.Fatal("rebuilt partial batch")
	}
}
func TestSameOriginRedirectAlsoRefused(t *testing.T) {
	f := newFixture(t, 1)
	f.statuses = []int{307}
	f.redirect = f.server.URL + "/v1/mcp/session"
	_, err := f.client.Push(context.Background())
	if err == nil || f.mintCount != 1 || f.pushCount != 1 {
		t.Fatal("same-origin proof forwarded", err)
	}
}

func TestKeychainWaitCannotBypassLateAuthorityCancellation(t *testing.T) {
	f := newFixture(t, 1)
	if err := f.client.mint(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.keystore.beforeLoad = func() { f.outbox.mu.Lock(); f.outbox.authorized = false; f.outbox.mu.Unlock() }
	_, err := f.client.Push(context.Background())
	if !errors.Is(err, ErrCancelled) || f.pushCount != 0 {
		t.Fatal("late cancellation bypass", err)
	}
}
func TestSlowAuthorizationCannotSendExpiredToken(t *testing.T) {
	f := newFixture(t, 1)
	once := true
	f.outbox.beforeAuth = func() {
		if once {
			once = false
			f.client.token.deadline = time.Now().Add(-time.Second)
		}
	}
	_, err := f.client.Push(context.Background())
	if err != nil || f.mintCount != 2 || f.pushCount != 1 || f.outbox.authCalls != 2 {
		t.Fatal("expired after authority lookup", err)
	}
	if len(f.outbox.retries) != 1 {
		t.Fatal("pre-send expiry did not consume retry budget")
	}
}

func TestRepeatedPreSendExpiryIsBoundedAndDurable(t *testing.T) {
	for _, stage := range []string{"authorize", "load", "sign"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t, 1)
			f.client.cfg.MaxRetries = 1
			op := f.outbox.op
			original, digest, id := op.Bytes(), op.Digest(), op.OpID()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			expiries := 0
			expire := func() {
				if f.client.token.token == "" {
					return
				}
				expiries++
				f.client.token.deadline = time.Now().Add(-time.Second)
				if expiries > 2 { // Bound a broken implementation without hanging the suite.
					cancel()
				}
			}
			switch stage {
			case "authorize":
				f.outbox.beforeAuth = expire
			case "load":
				f.keystore.beforeLoad = expire
			case "sign":
				f.keystore.beforeSign = expire
			}
			var waits int
			f.client.wait = func(context.Context, time.Duration) error { waits++; return nil }
			before := time.Now()
			ack, err := f.client.Push(ctx)
			var scheduled *RetryError
			if ack != nil || !errors.As(err, &scheduled) || !errors.Is(err, errSessionExpired) {
				t.Fatal("expiry did not exhaust as a retry", err)
			}
			if f.mintCount != 2 || f.pushCount != 0 || expiries != 2 || waits != 1 || len(f.outbox.retries) != 2 {
				t.Fatalf("unbounded remint mint=%d send=%d expiries=%d waits=%d retries=%d", f.mintCount, f.pushCount, expiries, waits, len(f.outbox.retries))
			}
			last := f.outbox.retries[1]
			if last.Attempt != 2 || last.OpID != id || last.Digest != digest || last.NotBefore.Before(before.Add(scheduled.After)) || scheduled.After < 0 || scheduled.After > MaxRetryDelay {
				t.Fatal("missing persistent backoff", last)
			}
			if f.outbox.op != op || op.OpID() != id || op.Digest() != digest || !bytes.Equal(original, op.Bytes()) || f.outbox.completes != 0 || f.outbox.ctlCursor != 2 || f.outbox.dataCursor != 3 || f.client.token.token != "" {
				t.Fatal("pending immutable operation or cursors changed")
			}
		})
	}
}

func TestPreSendExpirySharesNetworkRetryBudget(t *testing.T) {
	f := newFixture(t, 1)
	f.client.cfg.MaxRetries = 1
	f.statuses = []int{503}
	f.outbox.beforeAuth = func() {
		if f.outbox.authCalls == 1 {
			f.client.token.deadline = time.Now().Add(-time.Second)
		}
	}
	_, err := f.client.Push(context.Background())
	var scheduled *RetryError
	if !errors.As(err, &scheduled) || f.mintCount != 2 || f.pushCount != 1 || len(f.outbox.retries) != 2 || f.outbox.completes != 0 {
		t.Fatal("expiry budget was separate from network budget", err)
	}
}

func TestPreSendExpiryPersistenceFailureStopsRemint(t *testing.T) {
	f := newFixture(t, 1)
	f.outbox.beforeAuth = func() { f.client.token.deadline = time.Now().Add(-time.Second) }
	sentinel := errors.New("cannot_persist_expiry_backoff")
	f.outbox.retryErr = sentinel
	_, err := f.client.Push(context.Background())
	if !errors.Is(err, sentinel) || f.mintCount != 1 || f.pushCount != 0 || f.outbox.op == nil || f.outbox.completes != 0 {
		t.Fatal("persistence failure ignored", err)
	}
}

func TestSigningWaitCannotBypassLateAuthorityCancellation(t *testing.T) {
	f := newFixture(t, 1)
	if err := f.client.mint(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.keystore.beforeSign = func() { f.outbox.authorized = false }
	_, err := f.client.Push(context.Background())
	if !errors.Is(err, ErrCancelled) || f.pushCount != 0 || f.outbox.completes != 0 {
		t.Fatal("late signing cancellation bypass", err)
	}
}

func TestSlowSigningOrAuthorizationCannotSendStaleProof(t *testing.T) {
	for _, stage := range []string{"sign", "authorize"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t, 1)
			if err := f.client.mint(context.Background()); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			f.client.now = func() time.Time { return now }
			delay := func() { now = now.Add(skewMargin) }
			if stage == "sign" {
				f.keystore.beforeSign = delay
			} else {
				f.outbox.beforeAuth = delay
			}
			_, _, err := f.client.post(context.Background(), "/v1/memory/import", f.client.token.token, "DPoP", f.outbox.op.Bytes(), f.outbox.op)
			if !errors.Is(err, errSessionExpired) || f.pushCount != 0 || f.outbox.completes != 0 {
				t.Fatal("stale proof was sent", err)
			}
		})
	}
}
