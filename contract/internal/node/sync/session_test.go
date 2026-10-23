package sync

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSignedSessionClaimsFailClosed(t *testing.T) {
	cases := map[string]func(map[string]any){
		"old-token": func(c map[string]any) {
			c["iat"] = time.Now().Add(-time.Hour).Unix()
			c["nbf"] = c["iat"]
			c["exp"] = time.Now().Add(-time.Minute).Unix()
		},
		"near-expired":     func(c map[string]any) { c["exp"] = time.Now().Add(20 * time.Second).Unix() },
		"wrong-tenant":     func(c map[string]any) { c["tenant_id"] = "other" },
		"wrong-user":       func(c map[string]any) { c["sub"] = "other" },
		"wrong-config":     func(c map[string]any) { c["mcp_config_id"] = "other" },
		"wrong-issuer":     func(c map[string]any) { c["iss"] = "https://attacker.example" },
		"wrong-audience":   func(c map[string]any) { c["aud"] = []string{"ordinary-mcp"} },
		"extra-audience":   func(c map[string]any) { c["aud"] = []string{"telara-mcp-session", "ordinary-mcp"} },
		"wrong-jkt":        func(c map[string]any) { c["cnf"] = map[string]string{"jkt": "stolen"} },
		"missing-exp":      func(c map[string]any) { delete(c, "exp") },
		"missing-grant":    func(c map[string]any) { delete(c, "memory_grant") },
		"future-iat":       func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() },
		"future-nbf":       func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() },
		"too-long-session": func(c map[string]any) { c["exp"] = time.Now().Add(time.Hour).Unix() },
		"missing-cnf":      func(c map[string]any) { delete(c, "cnf") },
		"wrong-origin": func(c map[string]any) {
			g := c["memory_grant"].(MemoryGrant)
			g.Origin = "cloud"
			c["memory_grant"] = g
		},
		"broader-repos": func(c map[string]any) {
			g := c["memory_grant"].(MemoryGrant)
			g.Repos = append(g.Repos, "r1:"+strings.Repeat("f", 64))
			c["memory_grant"] = g
		},
		"missing-repos": func(c map[string]any) { g := c["memory_grant"].(MemoryGrant); g.Repos = nil; c["memory_grant"] = g },
		"missing-ops":   func(c map[string]any) { g := c["memory_grant"].(MemoryGrant); g.Ops = nil; c["memory_grant"] = g },
		"wrong-genesis": func(c map[string]any) {
			g := c["memory_grant"].(MemoryGrant)
			g.GenesisID = strings.Repeat("f", 32)
			c["memory_grant"] = g
		},
		"wrong-device": func(c map[string]any) {
			g := c["memory_grant"].(MemoryGrant)
			g.DeviceID = "33333333-3333-4333-8333-333333333333"
			c["memory_grant"] = g
		},
		"narrowed-ops": func(c map[string]any) {
			g := c["memory_grant"].(MemoryGrant)
			g.Ops = []string{"push"}
			c["memory_grant"] = g
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1)
			f.claims = change
			_, err := f.client.Push(context.Background())
			if !errors.Is(err, ErrToken) || f.pushCount != 0 || f.outbox.completes != 0 {
				t.Fatal(err)
			}
		})
	}
}
func TestSignedExpiryAndServerClockDeadline(t *testing.T) {
	f := newFixture(t, 1)
	// A token was minted five minutes ago, exp is still ten minutes ahead.
	// The local wall clock moves two hours forward after mint began. Deadlines
	// use receipt-relative duration, not local Unix time or original exp-iat.
	f.claims = func(c map[string]any) { c["iat"] = time.Now().Add(-5 * time.Minute).Unix(); c["nbf"] = c["iat"] }
	_, err := f.client.Push(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	remaining := time.Until(f.client.token.deadline)
	if remaining > 10*time.Minute-skewMargin || remaining < 9*time.Minute {
		t.Fatal("deadline extended from exp-iat", remaining)
	}
	if delta := f.client.serverNow().Sub(time.Now()); delta > 2*time.Second || delta < -2*time.Second {
		t.Fatal("bad server anchor")
	}
}
func TestServerTimeInsteadOfWallClockAndNetworkMargin(t *testing.T) {
	f := newFixture(t, 1)
	realNow := time.Now
	f.client.now = func() time.Time { return realNow().Add(2 * time.Hour) }
	// Bootstrap proof needs a sane clock before a server anchor is available.
	// Seed an already authenticated anchor to isolate the minted-token deadline.
	f.client.server = time.Now()
	f.client.anchor = f.client.now()
	_, err := f.client.Push(context.Background())
	if err != nil {
		t.Fatal(err, f.handlerErr)
	}
	remaining := f.client.token.deadline.Sub(f.client.now())
	if remaining < 9*time.Minute || remaining > 10*time.Minute-skewMargin {
		t.Fatal("used wall Unix time", remaining)
	}
}
func TestMintDelayReducesLifetime(t *testing.T) {
	f := newFixture(t, 1)
	start := time.Now()
	var elapsed atomic.Int64
	f.client.now = func() time.Time { return start.Add(time.Duration(elapsed.Load())) }
	// Advance time only when the endpoint produces its response, independent of
	// how often the client checks pre-send token/proof freshness.
	f.claims = func(map[string]any) { elapsed.Store(int64(time.Minute)) }

	if err := f.client.mint(context.Background()); err != nil {
		t.Fatal(err, f.handlerErr)
	}
	remaining := f.client.token.deadline.Sub(start.Add(time.Minute))
	if remaining > 9*time.Minute-skewMargin+time.Second {
		t.Fatal("network delay ignored", remaining)
	}
}
func TestWrapperExpiryCannotExtendSignedExp(t *testing.T) {
	f := newFixture(t, 1)
	f.mintResponse = func(r map[string]any) { r["expires_at"] = time.Now().Add(time.Hour).Unix() }
	_, err := f.client.Push(context.Background())
	if !errors.Is(err, ErrToken) || f.pushCount != 0 {
		t.Fatal(err)
	}
}
func TestForgedTokenAndKeyRotationRefused(t *testing.T) {
	t.Run("forged", func(t *testing.T) {
		f := newFixture(t, 1)
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		f.authKey = other
		_, err := f.client.Push(context.Background())
		if !errors.Is(err, ErrToken) || f.pushCount != 0 {
			t.Fatal(err)
		}
	})
	t.Run("DPoP-rotation", func(t *testing.T) {
		f := newFixture(t, 1)
		if err := f.client.mint(context.Background()); err != nil {
			t.Fatal(err)
		}
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		f.keystore.tenants[f.scope.Tenant] = fixtureCredentials{"telara_mcp_node_bootstrap", k}
		_, err := f.client.Push(context.Background())
		if !errors.Is(err, ErrToken) || f.pushCount != 0 {
			t.Fatal(err)
		}
	})
}
func TestNeverMintFromSessionToken(t *testing.T) {
	f := newFixture(t, 1)
	f.keystore.tenants[f.scope.Tenant] = fixtureCredentials{"eyJsession.token.signature", f.dpopKey}
	_, err := f.client.Push(context.Background())
	if !errors.Is(err, ErrToken) || f.mintCount != 0 {
		t.Fatal(err)
	}
}
func TestTokenExpirationRemintsAndProcessRestartRemints(t *testing.T) {
	f := newFixture(t, 1)
	if _, err := f.client.Push(context.Background()); err != nil {
		t.Fatal(err)
	}
	op, err := NewOperation("next-op", []SignedRecord{f.signed(t, 2)})
	if err != nil {
		t.Fatal(err)
	}
	f.outbox.op = op
	f.client.token.deadline = time.Now().Add(-time.Second)
	if _, err = f.client.Push(context.Background()); err != nil || f.mintCount != 2 {
		t.Fatal(err)
	}
	f.outbox.op = op
	cfg := f.client.cfg
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.http.CloseIdleConnections()
	if _, err = c.Push(context.Background()); err != nil || f.mintCount != 3 {
		t.Fatal("restart reused token", err)
	}
}
func TestInvalidConfigurationAndGrant(t *testing.T) {
	f := newFixture(t, 0)
	for _, origin := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com?x=1", "https://example.com#x", "https://example.com?", "https:///", "file:///tmp/secret"} {
		cfg := f.client.cfg
		cfg.Scope.Origin = origin
		if _, err := New(cfg); !errors.Is(err, ErrInvalid) {
			t.Fatal(origin, err)
		}
	}
	for _, which := range []string{"grant-origin", "grant-repos", "grant-ops", "grant-expiry", "issuer", "auth-key", "store", "keystore", "keyring", "retries"} {
		cfg := f.client.cfg
		switch which {
		case "grant-origin":
			cfg.Grant.Origin = "cloud"
		case "grant-repos":
			cfg.Grant.Repos = nil
		case "grant-ops":
			cfg.Grant.Ops = []string{"pull"}
		case "grant-expiry":
			cfg.Grant.ExpiresAtUnix = 1
		case "issuer":
			cfg.AuthIssuer = ""
		case "auth-key":
			cfg.AuthKey = nil
		case "store":
			cfg.Outbox = nil
		case "keystore":
			cfg.Keystore = nil
		case "keyring":
			cfg.Keys = nil
		case "retries":
			cfg.MaxRetries = 100
		}
		if _, err := New(cfg); !errors.Is(err, ErrInvalid) {
			t.Fatal(which, err)
		}
	}
}
func TestRetryAfterDatesAndJitterBounds(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, value := range []string{"0", "1", "300", "99999999999999999999", "bad", now.Add(time.Minute).Format(http.TimeFormat), now.Add(time.Hour).Format(http.TimeFormat), now.Add(-time.Hour).Format(http.TimeFormat)} {
		for attempt := 0; attempt < 12; attempt++ {
			d := retryDelay(attempt, &httpFailure{status: 429, retryAfter: value, serverDate: now}, now.Add(-time.Hour))
			if d < 0 || d > 5*time.Minute {
				t.Fatal(value, d)
			}
			if value == "300" && d != 5*time.Minute {
				t.Fatal("numeric cap")
			}
			if value == now.Add(time.Minute).Format(http.TimeFormat) && d < time.Minute {
				t.Fatal("server Date ignored")
			}
		}
	}
}

func TestSleepAndSafeErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := sleep(context.Background(), time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if (&httpFailure{status: 403}).Error() != "sync_http_403" || (&RetryError{Cause: ErrToken}).Error() != "sync_retry_scheduled" {
		t.Fatal("error contains unsafe response details")
	}
}
func TestJWTAlgorithmsHeadersAndEncoding(t *testing.T) {
	f := newFixture(t, 0)
	claims := map[string]any{"exp": time.Now().Add(time.Minute).Unix()}
	for _, head := range []map[string]any{{"alg": "none", "typ": "JWT"}, {"alg": "HS256", "typ": "JWT"}, {"alg": "ES256", "typ": "JWT", "jku": "https://evil.example/keys"}, {"alg": "ES256", "typ": "JWT", "jwk": map[string]any{}}, {"alg": "ES256", "typ": "not-JWT"}} {
		token, _ := signJWT(f.authKey, head, claims)
		if _, err := verifyJWT(token, &f.authKey.PublicKey); !errors.Is(err, ErrToken) {
			t.Fatal("header confusion", err)
		}
	}
	for _, token := range []string{"", "a.b", "a.b.c.d", "!.!.!", strings.Repeat("a", 32769)} {
		if _, err := verifyJWT(token, &f.authKey.PublicKey); !errors.Is(err, ErrToken) {
			t.Fatal(err)
		}
	}
	if _, err := proof(context.Background(), nil, "POST", "https://example.com", "token", time.Now().Unix()); err == nil {
		t.Fatal("nil key")
	}

}
func TestRetryAfterOverflowCapsAtFiveMinutes(t *testing.T) {
	if d := retryDelay(0, &httpFailure{status: 429, retryAfter: "99999999999999999999999999"}, time.Now()); d != 5*time.Minute {
		t.Fatal(d)
	}
}
