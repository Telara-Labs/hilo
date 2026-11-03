package sync

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/Telara-Labs/hilo/contract/jcs"
)

type tokenClaims struct {
	Exp      int64           `json:"exp"`
	Iat      int64           `json:"iat"`
	Nbf      int64           `json:"nbf"`
	Issuer   string          `json:"iss"`
	Subject  string          `json:"sub"`
	Audience json.RawMessage `json:"aud"`
	Tenant   string          `json:"tenant_id"`
	Config   string          `json:"mcp_config_id"`
	Cnf      struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
	Grant MemoryGrant `json:"memory_grant"`
}

func (c *Client) mint(ctx context.Context) error {
	g := c.cfg.Grant
	// Protojson accepts snake_case fields; int64 is transmitted as a string.
	body, err := json.Marshal(struct {
		Grant any `json:"memory_grant"`
	}{struct {
		Ops     []string `json:"ops"`
		Repos   []string `json:"repos"`
		Origin  string   `json:"origin"`
		Genesis string   `json:"genesis_id"`
		Device  string   `json:"device_id"`
		Expiry  string   `json:"expires_at_unix"`
	}{g.Ops, g.Repos, g.Origin, g.GenesisID, g.DeviceID, strconv.FormatInt(g.ExpiresAtUnix, 10)}})
	if err != nil {
		return ErrToken
	}
	start := c.now()
	raw, date, err := c.post(ctx, "/v1/mcp/session", "", "Bearer", body, nil)
	if err != nil {
		return err
	}
	received := c.now()
	var response struct {
		Token   string `json:"session_token"`
		Expires int64  `json:"expires_at"`
	}
	if date.IsZero() || strictJSON(raw, &response) != nil {
		return ErrToken
	}
	claimsRaw, err := verifyJWT(response.Token, c.cfg.AuthKey)
	if err != nil {
		return ErrToken
	}
	if _, err = jcs.CanonicalizeRecord(claimsRaw); err != nil {
		return ErrToken
	}
	var v tokenClaims
	if json.Unmarshal(claimsRaw, &v) != nil {
		return ErrToken
	}
	var aud []string
	var single string
	if json.Unmarshal(v.Audience, &single) == nil {
		aud = []string{single}
	} else if json.Unmarshal(v.Audience, &aud) != nil {
		return ErrToken
	}
	if len(aud) != 1 || aud[0] != "telara-mcp-session" || v.Issuer != c.cfg.AuthIssuer || v.Subject != c.cfg.Scope.User || v.Tenant != c.cfg.Scope.Tenant || v.Config != c.cfg.Scope.Config || v.Exp != response.Expires || v.Exp <= 0 || v.Iat <= 0 || v.Nbf <= 0 || v.Exp < v.Iat || v.Iat > date.Add(skewMargin).Unix() || v.Nbf > date.Add(skewMargin).Unix() {
		return ErrToken
	}
	if !validGrant(v.Grant, c.cfg.Scope, date) || v.Grant.ExpiresAtUnix < v.Exp || v.Grant.ExpiresAtUnix > g.ExpiresAtUnix || len(v.Grant.Ops) != len(g.Ops) || len(v.Grant.Repos) != len(g.Repos) || !subset(v.Grant.Ops, g.Ops) || !subset(v.Grant.Repos, g.Repos) {
		return ErrToken
	}
	credentials, err := c.cfg.Keystore.Load(ctx, c.cfg.Scope)
	if err != nil || credentials.DPoP == nil {
		return ErrKeystoreUnavailable
	}
	pub, err := credentials.DPoP.PublicJWK().publicKey()
	if err != nil {
		return ErrToken
	}
	jkt, err := thumbprint(pub)
	if err != nil || v.Cnf.JKT != jkt {
		return ErrToken
	}
	// exp is signed. expires_at and exp-iat are never treated as a fresh TTL.
	// Date is authenticated by TLS. Subtract full mint time, Date granularity,
	// and skew margin, then retain only an in-process monotonic deadline.
	lifetime := time.Unix(v.Exp, 0).Sub(date) - received.Sub(start) - skewMargin - time.Second
	if lifetime <= 0 || lifetime > 15*time.Minute {
		return ErrToken
	}
	c.server = date
	c.anchor = received
	c.token = session{response.Token, received.Add(lifetime)}
	return nil
}
func subset(xs, ys []string) bool {
	for _, x := range xs {
		if !contains(ys, x) {
			return false
		}
	}
	return true
}
