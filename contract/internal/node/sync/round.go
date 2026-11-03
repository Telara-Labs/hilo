package sync

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/transport"
)

// MaxPageItems bounds one filtered log page request.
const MaxPageItems = 64

// maxPageResponseBytes admits a 4 MiB decoded page after base64 expansion and
// envelope framing. Decoded bodies are bounded again per item.
const maxPageResponseBytes = 8 << 20

// HTTPStatus reports the hosted HTTP status of a refused request, if any.
// Callers use it to separate rejected operations from retryable failures.
func HTTPStatus(err error) (int, bool) {
	var h *httpFailure
	if errors.As(err, &h) {
		return h.status, true
	}
	return 0, false
}

// Retryable reports whether err is a transient transport failure.
func Retryable(err error) bool { return retryable(err) }

// Hello posts the node's durable cursors and returns the hosted snapshot heads.
// The reply is checked against the contract version gate before it is returned.
func (c *Client) Hello(ctx context.Context, h transport.Hello) (transport.HelloReply, error) {
	var reply transport.HelloReply
	if h.DeviceID != c.cfg.Scope.Device {
		return reply, ErrInvalid
	}
	body, err := json.Marshal(h)
	if err != nil {
		return reply, ErrInvalid
	}
	raw, err := c.authorized(ctx, "POST", "/sync/v1/hello", "", body, maxResponseBytes)
	if err != nil {
		return reply, err
	}
	if strictJSON(raw, &reply) != nil {
		return reply, ErrInvalid
	}
	if transport.CheckHello(h, reply) != nil {
		return reply, ErrInvalid
	}
	return reply, nil
}

// Log fetches one filtered page of a single class. A cursor of one class is
// never combined with the other class; there is no class=all request.
func (c *Client) Log(ctx context.Context, class string, after, through int64, limit int) (transport.Page, error) {
	var page transport.Page
	if class != "control" && class != "data" || after < 0 || through < after || limit < 1 || limit > MaxPageItems {
		return page, ErrInvalid
	}
	q := url.Values{}
	q.Set("class", class)
	q.Set("after", strconv.FormatInt(after, 10))
	q.Set("through", strconv.FormatInt(through, 10))
	q.Set("limit", strconv.Itoa(limit))
	if class == "data" {
		q.Set("exclude_own", "true")
	}
	raw, err := c.authorized(ctx, "GET", "/sync/v1/log", q.Encode(), nil, maxPageResponseBytes)
	if err != nil {
		return page, err
	}
	if strictJSON(raw, &page) != nil || page.Items == nil || len(page.Items) > limit {
		return transport.Page{}, ErrInvalid
	}
	total := 0
	for i := range page.Items {
		x := &page.Items[i]
		if x.Class != class {
			return transport.Page{}, ErrInvalid
		}
		if x.Envelope.Body == nil {
			continue
		}
		compressed, err := decode64(x.Envelope.Body.Bytes, record.MaxBodyBytes+65536)
		if err != nil {
			continue
		}
		// Only the bounded raw-block frame is decoded. Any other encoding stays
		// undecoded, so the caller blocks a control or quarantines data.
		if body, err := readRawZstd(compressed); err == nil {
			total += len(body)
			if total > MaxRequestBytes {
				return transport.Page{}, ErrInvalid
			}
			x.DecodedBody = body
		}
	}
	return page, nil
}

// Ack reports exactly the enforced control cursor and applied data cursor.
func (c *Client) Ack(ctx context.Context, a transport.Ack) error {
	if a.CtlEnforcedThrough < 0 || a.DataAppliedThrough < 0 {
		return ErrInvalid
	}
	body, err := json.Marshal(a)
	if err != nil {
		return ErrInvalid
	}
	raw, err := c.authorized(ctx, "POST", "/sync/v1/ack", "", body, maxResponseBytes)
	if err != nil {
		return err
	}
	if len(raw) > 0 {
		var empty struct{}
		if strictJSON(raw, &empty) != nil {
			return ErrInvalid
		}
	}
	return nil
}

// authorized sends one request under the minted memory session. A 401 remints
// once; a 403 latches the client like Push. Retry scheduling is the caller's.
func (c *Client) authorized(ctx context.Context, method, path, query string, body []byte, limit int) ([]byte, error) {
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
	refreshed := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, c.reason(err)
		}
		if !validGrant(c.cfg.Grant, c.cfg.Scope, c.serverNow()) {
			return nil, ErrToken
		}
		var err error
		if c.token.token == "" || !c.now().Before(c.token.deadline) {
			err = c.mint(ctx)
		}
		var raw []byte
		if err == nil {
			raw, _, err = c.send(ctx, method, path, query, c.token.token, "DPoP", body, nil, limit)
			if err == nil {
				return raw, nil
			}
		}
		var h *httpFailure
		if (errors.Is(err, errSessionExpired) || errors.As(err, &h) && h.status == 401) && !refreshed {
			refreshed = true
			c.token = session{}
			continue
		}
		if errors.As(err, &h) && h.status == 403 {
			c.forbidden = true
			c.token = session{}
			return nil, ErrForbidden
		}
		return nil, c.reason(err)
	}
}

// LoginReply is the hosted login response, read under a session minted with
// the device's DPoP key over validated TLS to the requested origin. It names
// the authenticated destination and device it was issued for, and carries the
// tenant keys the node pins with pinned-TLS-login provenance: the policy root
// and the receipt issuer's service keys. Each is the exact signed tenant_key
// key operation envelope for that tenant, with role policy or service.
type LoginReply struct {
	Origin      string            `json:"origin"`
	Tenant      string            `json:"tenant"`
	User        string            `json:"user"`
	Config      string            `json:"config"`
	DeviceID    string            `json:"device_id"`
	PolicyRoot  record.Envelope   `json:"policy_root"`
	ServiceKeys []record.Envelope `json:"service_keys"`
}

// Login fetches the login response for this client's scope. The session mint
// already binds issuer, user, tenant, config, grant genesis and device and the
// DPoP key; the reply must name exactly that origin, destination and device.
func (c *Client) Login(ctx context.Context) (LoginReply, error) {
	var reply LoginReply
	raw, err := c.authorized(ctx, "GET", "/sync/v1/login", "", nil, maxResponseBytes)
	if err != nil {
		return reply, err
	}
	if strictJSON(raw, &reply) != nil {
		return LoginReply{}, ErrInvalid
	}
	s := c.cfg.Scope
	if reply.Origin != s.Origin || reply.Tenant != s.Tenant || reply.User != s.User || reply.Config != s.Config || reply.DeviceID != s.Device {
		return LoginReply{}, ErrInvalid
	}
	return reply, nil
}
