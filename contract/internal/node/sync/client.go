package sync

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

const skewMargin = 30 * time.Second
const maxResponseBytes = 256 << 10

type httpFailure struct {
	status     int
	retryAfter string
	serverDate time.Time
}

func (e *httpFailure) Error() string { return "sync_http_" + strconv.Itoa(e.status) }

var errNetwork = errors.New("sync_network_failure")
var errSessionExpired = errors.New("sync_session_expired_before_send")

type session struct {
	token    string
	deadline time.Time
}
type Client struct {
	cfg       Config
	http      *http.Client
	gate      chan struct{}
	life      context.Context
	cancel    context.CancelFunc
	stopped   atomic.Bool
	forbidden bool // protected by gate
	token     session
	server    time.Time
	anchor    time.Time
	now       func() time.Time
	wait      func(context.Context, time.Duration) error
}

func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Scope.Origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return nil, ErrInvalid
	}
	if _, err = jwk(cfg.AuthKey); err != nil || cfg.AuthIssuer == "" || cfg.Scope.Tenant == "" || cfg.Scope.User == "" || cfg.Scope.Config == "" || !record.IsKeyID(cfg.Scope.Genesis) || !record.IsUUID(cfg.Scope.Device) || cfg.Scope.Device[14] != '4' || cfg.Keystore == nil || cfg.Outbox == nil || cfg.Keys == nil || cfg.MaxRetries < 0 || cfg.MaxRetries > 12 {
		return nil, ErrInvalid
	}
	u.Host = strings.ToLower(u.Host)
	if u.Port() == "443" {
		u.Host = u.Hostname()
		if strings.Contains(u.Host, ":") {
			u.Host = "[" + u.Host + "]"
		}
	}
	u.Path = ""
	cfg.Scope.Origin = u.String()
	if !validGrant(cfg.Grant, cfg.Scope, time.Now()) {
		return nil, ErrInvalid
	}
	cfg.Grant.Ops = append([]string(nil), cfg.Grant.Ops...)
	cfg.Grant.Repos = append([]string(nil), cfg.Grant.Repos...)
	cfg.AuthKey = &ecdsa.PublicKey{Curve: cfg.AuthKey.Curve, X: new(big.Int).Set(cfg.AuthKey.X), Y: new(big.Int).Set(cfg.AuthKey.Y)}
	var roots = cfg.TLSRoots
	if roots != nil {
		roots = roots.Clone()
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, IdleConnTimeout: 60 * time.Second, MaxResponseHeaderBytes: 32 << 10, MaxConnsPerHost: 2, DisableCompression: true}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 4
	}
	life, cancel := context.WithCancel(context.Background())
	c := &Client{cfg: cfg, gate: make(chan struct{}, 1), life: life, cancel: cancel, now: time.Now, wait: sleep}
	c.http = &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c, nil
}
func validGrant(g MemoryGrant, s Scope, now time.Time) bool {
	if g.Origin != "local" || g.GenesisID != s.Genesis || g.DeviceID != s.Device || g.ExpiresAtUnix <= now.Unix() || len(g.Repos) < 1 || len(g.Repos) > 128 || len(g.Ops) < 1 || len(g.Ops) > 8 {
		return false
	}
	push := false
	seen := map[string]bool{}
	for _, op := range g.Ops {
		if seen[op] || (op != "push" && op != "erase" && op != "pull") {
			return false
		}
		seen[op] = true
		push = push || op == "push"
	}
	seen = map[string]bool{}
	for _, repo := range g.Repos {
		if !strings.HasPrefix(repo, "r1:") || !record.IsHex64(strings.TrimPrefix(repo, "r1:")) || seen[repo] {
			return false
		}
		seen[repo] = true
	}
	return push
}
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
func (c *Client) lock(ctx context.Context) error {
	select {
	case c.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *Client) unlock() { <-c.gate }
func (c *Client) serverNow() time.Time {
	if c.anchor.IsZero() {
		return c.now()
	}
	return c.server.Add(c.now().Sub(c.anchor))
}

// Push sends at most one durable operation. Nil acknowledgment means no work.
// Transient failure leaves that operation pending with exactly the same bytes.
// The caller schedules another bounded round after an exhausted retry budget.
func (c *Client) Push(ctx context.Context) (*Acknowledgment, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(c.life, cancel)
	defer stop()
	if err := c.lock(ctx); err != nil {
		return nil, c.reason(err)
	}
	defer c.unlock()
	if c.stopped.Load() {
		return nil, ErrLoggedOut
	}
	if c.forbidden {
		return nil, ErrForbidden
	}
	op, err := c.cfg.Outbox.Next(ctx, c.cfg.Scope, Limits{MaxRecords, MaxRequestBytes, MaxRequestBytes})
	if err != nil || op == nil {
		return nil, err
	}
	// Own another copy rather than retaining a caller-controlled object/buffer.
	op, err = RestoreOperation(op.Bytes(), op.Digest())
	if err != nil {
		return nil, err
	}
	if !c.operationAllowed(op) {
		return nil, ErrInvalid
	}
	refreshed := false
	retries := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, c.reason(err)
		}
		if !validGrant(c.cfg.Grant, c.cfg.Scope, c.serverNow()) {
			return nil, ErrToken
		}
		if c.token.token == "" || !c.now().Before(c.token.deadline) {
			err = c.mint(ctx)
		} else {
			err = nil
		}
		if err == nil {
			var raw []byte
			raw, _, err = c.post(ctx, "/v1/memory/import", c.token.token, "DPoP", op.raw, op)
			if errors.Is(err, errSessionExpired) {
				c.token = session{}
			}
			if err == nil {
				ack, e := c.acknowledgment(ctx, op, raw)
				if e != nil {
					return nil, e
				}
				if c.stopped.Load() {
					return nil, ErrLoggedOut
				}
				if e = c.cfg.Outbox.Complete(ctx, c.cfg.Scope, *ack); e != nil {
					return nil, e
				}
				return ack, nil
			}
			var h *httpFailure
			if errors.As(err, &h) && h.status == 401 && !refreshed {
				refreshed = true
				c.token = session{}
				continue
			}
		}
		var h *httpFailure
		if errors.As(err, &h) && h.status == 403 {
			c.forbidden = true
			c.token = session{}
			return nil, ErrForbidden
		}
		if ctx.Err() != nil {
			return nil, c.reason(ctx.Err())
		}
		if !retryable(err) {
			return nil, err
		}
		d := retryDelay(retries, err, c.serverNow())
		if e := c.cfg.Outbox.Retry(ctx, c.cfg.Scope, Retry{OpID: op.id, Digest: op.digest, NotBefore: c.now().Add(d), Attempt: retries + 1}); e != nil {
			return nil, e
		}
		if retries >= c.cfg.MaxRetries {
			return nil, &RetryError{After: d, Cause: err}
		}
		retries++
		if err = c.wait(ctx, d); err != nil {
			return nil, c.reason(err)
		}
	}
}
func (c *Client) operationAllowed(op *Operation) bool {
	for _, r := range op.records {
		if r.Header.Author.MachineID != c.cfg.Scope.Device {
			return false
		}
		if !r.Header.Type.IsControl() && !contains(c.cfg.Grant.Repos, r.Header.Subj.RepoID) {
			return false
		}
		if r.Header.Type == record.KindErasure && !contains(c.cfg.Grant.Ops, "erase") {
			return false
		}
	}
	return true
}
func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}
func (c *Client) reason(err error) error {
	if c.stopped.Load() {
		return ErrLoggedOut
	}
	return err
}

// Logout stops sends immediately, then deletes only this login tenant's secrets
// and invokes its durable cancellation/withdrawal transaction. Both operations
// are attempted even if one fails. This Client can never be reused after logout.
func (c *Client) Logout(ctx context.Context) error {
	c.stopped.Store(true)
	c.cancel()
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	c.token = session{}
	a := c.cfg.Keystore.DeleteTenant(ctx, c.cfg.Scope)
	b := c.cfg.Outbox.Logout(ctx, c.cfg.Scope)
	c.http.CloseIdleConnections()
	return errors.Join(a, b)
}
func (c *Client) post(ctx context.Context, path, token, scheme string, body []byte, op *Operation) ([]byte, time.Time, error) {
	credentials, err := c.cfg.Keystore.Load(ctx, c.cfg.Scope)
	if err != nil {
		return nil, time.Time{}, ErrKeystoreUnavailable
	}
	if credentials.DPoP == nil {
		return nil, time.Time{}, ErrKeystoreUnavailable
	}
	if path == "/v1/mcp/session" {
		token = credentials.Refresh
		if !strings.HasPrefix(token, "telara_mcp_") {
			return nil, time.Time{}, ErrToken
		}
	}
	if token == "" || len(token) > 32768 || strings.ContainsAny(token, "\r\n\t ") {
		return nil, time.Time{}, ErrToken
	}
	if path == "/v1/memory/import" { // re-check binding if OS credentials rotated
		pub, e := credentials.DPoP.PublicJWK().publicKey()
		if e != nil {
			return nil, time.Time{}, ErrToken
		}
		jkt, e := thumbprint(pub)
		if e != nil || c.tokenJKT(token) != jkt {
			return nil, time.Time{}, ErrToken
		}
	}
	// Loading and signing can both wait on the OS keystore. Authorize after
	// all keychain work, then check token and proof freshness before sending.
	proofAt := c.now()
	proof, err := proof(ctx, credentials.DPoP, "POST", c.cfg.Scope.Origin+path, token, c.serverNow().Unix())
	if err != nil {
		return nil, time.Time{}, err
	}
	if op != nil {
		ok, e := c.cfg.Outbox.Authorize(ctx, c.cfg.Scope, op.id, op.digest)
		if e != nil {
			return nil, time.Time{}, e
		}
		if !ok {
			return nil, time.Time{}, ErrCancelled
		}
		if !c.now().Before(c.token.deadline) {
			return nil, time.Time{}, errSessionExpired
		}
	}
	// A slow signer or authorization must not send a stale one-use proof.
	if c.now().Sub(proofAt) >= skewMargin {
		return nil, time.Time{}, errSessionExpired
	}
	if err := ctx.Err(); err != nil {
		return nil, time.Time{}, err
	}
	if c.stopped.Load() {
		return nil, time.Time{}, ErrLoggedOut
	}

	r, err := http.NewRequestWithContext(ctx, "POST", c.cfg.Scope.Origin+path, bytes.NewReader(body))
	if err != nil {
		return nil, time.Time{}, ErrInvalid
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", scheme+" "+token)
	r.Header.Set("DPoP", proof)
	resp, err := c.http.Do(r)
	if err != nil {
		return nil, time.Time{}, errNetwork
	}
	defer resp.Body.Close()
	date, _ := http.ParseTime(resp.Header.Get("Date"))
	if resp.StatusCode != 200 {
		return nil, date, &httpFailure{resp.StatusCode, resp.Header.Get("Retry-After"), date}
	}
	if resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity" {
		return nil, date, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, date, errNetwork
	}
	if len(raw) > maxResponseBytes {
		return nil, date, ErrInvalid
	}
	return raw, date, nil
}
func (c *Client) tokenJKT(token string) string {
	raw, err := verifyJWT(token, c.cfg.AuthKey)
	if err != nil {
		return ""
	}
	var v struct {
		Cnf struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	return v.Cnf.JKT
}
func (c *Client) acknowledgment(ctx context.Context, op *Operation, raw []byte) (*Acknowledgment, error) {
	var response struct {
		Results []Result `json:"results"`
	}
	if strictJSON(raw, &response) != nil || len(response.Results) != len(op.records) {
		return nil, ErrReceipt
	}
	st, err := c.cfg.Keys.State(ctx)
	if err != nil || st == nil {
		return nil, ErrReceipt
	}
	issuer := sig.TrustedIssuer{Tenant: c.cfg.Scope.Tenant, Role: record.RoleService, Provenance: sig.PinnedTLSLogin}
	want := map[string]bool{}
	for _, r := range op.records {
		want[r.ID] = true
	}
	for _, r := range response.Results {
		if !want[r.ID] {
			return nil, ErrReceipt
		}
		delete(want, r.ID)
		switch r.Status {
		case "accepted", "accepted-duplicate":
			if r.Receipt == nil || r.HSeq != r.Receipt.HSeq || r.Receipt.ID != r.ID || r.Receipt.DeviceID != c.cfg.Scope.Device || r.Receipt.HSeq > jcs.MaxSafeInteger || r.Receipt.AcceptedAt > jcs.MaxSafeInteger || sig.VerifyReceipt(*r.Receipt, st, issuer) != nil {
				return nil, ErrReceipt
			}
		case "unavailable":
			if r.Receipt != nil || r.HSeq != 0 || r.HostedTaskID != "" {
				return nil, ErrReceipt
			}
		default:
			return nil, ErrReceipt
		}
	}
	return &Acknowledgment{OpID: op.id, Digest: op.digest, Results: response.Results}, nil
}
func retryable(err error) bool {
	var h *httpFailure
	return errors.Is(err, errSessionExpired) || errors.Is(err, errNetwork) || errors.As(err, &h) && (h.status == 429 || h.status >= 500 && h.status <= 599)
}
func retryDelay(attempt int, err error, now time.Time) time.Duration {
	base := time.Second << min(max(attempt, 0), 8)
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(base)))
	if n != nil {
		base = time.Duration(n.Int64())
	} // full jitter
	var h *httpFailure
	if errors.As(err, &h) {
		anchor := now
		if !h.serverDate.IsZero() {
			anchor = h.serverDate
		}
		var d time.Duration
		if seconds, e := strconv.ParseUint(h.retryAfter, 10, 64); e == nil {
			if seconds >= 300 {
				d = MaxRetryDelay
			} else {
				d = time.Duration(seconds) * time.Second
			}
		} else if errors.Is(e, strconv.ErrRange) {
			d = MaxRetryDelay
		} else if at, e := http.ParseTime(h.retryAfter); e == nil {
			d = at.Sub(anchor)
		}
		if d > base {
			base = d
		}
	}
	return min(base, MaxRetryDelay)
}
