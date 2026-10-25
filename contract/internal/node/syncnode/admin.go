package syncnode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
)

// Enrollment is the hosted enrollment result for this device's DPoP key. It is
// read from the owner's terminal input, never from a file argument or the
// environment. RefreshToken goes straight into the native vault.
type Enrollment struct {
	Origin       string               `json:"origin"`
	Tenant       string               `json:"tenant"`
	User         string               `json:"user"`
	Config       string               `json:"config"`
	AuthIssuer   string               `json:"auth_issuer"`
	AuthKey      nodesync.PublicJWK   `json:"auth_key"`
	ServiceKeys  []ServiceKey         `json:"service_keys"`
	Grant        nodesync.MemoryGrant `json:"grant"`
	RefreshToken string               `json:"refresh_token"`
}

// ParseEnrollment strictly decodes one enrollment document.
func ParseEnrollment(r io.Reader) (Enrollment, error) {
	var e Enrollment
	b, err := io.ReadAll(io.LimitReader(r, 65537))
	if err != nil || len(b) > 65536 {
		return e, ErrEnrollment
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil || d.Decode(new(any)) != io.EOF {
		clear(b)
		return Enrollment{}, ErrEnrollment
	}
	clear(b)
	return e, nil
}

// CreateKey provisions this device's DPoP key once and records a disabled,
// unenrolled profile. It returns the jkt the hosted enrollment must bind.
func CreateKey(ctx context.Context, dir string, vault SecretVault) (string, error) {
	p, err := LoadProfile(dir)
	if err == nil {
		return CredentialThumbprint(ctx, vault, p.Credential)
	}
	if !Disabled(err) {
		return "", err
	}
	genesis, machine, err := store.InstalledIdentity(dir)
	if err != nil {
		return "", ErrIdentity
	}
	handle, jkt, err := NewCredential(ctx, vault)
	if err != nil {
		return "", err
	}
	if err = SaveProfile(dir, Profile{Version: ProfileVersion, Genesis: genesis, Device: machine, Credential: handle}); err != nil {
		_ = vault.Delete(ctx, handle)
		return "", err
	}
	return jkt, nil
}

// Enroll binds a hosted enrollment to the existing DPoP key and enables sync.
// The grant must name this installation's genesis and device exactly.
func Enroll(ctx context.Context, dir string, vault SecretVault, e Enrollment) error {
	defer func() { e.RefreshToken = "" }()
	p, err := LoadProfile(dir)
	if Disabled(err) {
		return ErrNotEnrolled
	}
	if err != nil {
		return err
	}
	if e.Grant.GenesisID != p.Genesis || e.Grant.DeviceID != p.Device {
		return ErrIdentity
	}
	if _, err := CredentialThumbprint(ctx, vault, p.Credential); err != nil {
		return ErrCredential
	}
	next := p
	next.Enabled = true
	next.Origin, next.Tenant, next.User, next.Config = e.Origin, e.Tenant, e.User, e.Config
	next.AuthIssuer = e.AuthIssuer
	key := e.AuthKey
	next.AuthKey = &key
	next.ServiceKeys = append([]ServiceKey(nil), e.ServiceKeys...)
	grant := e.Grant
	next.Grant = &grant
	if !validRefresh(e.RefreshToken) {
		return ErrEnrollment
	}
	refresh, err := StoreRefresh(ctx, vault, e.RefreshToken)
	if err != nil {
		return err
	}
	next.Refresh = refresh
	if err := next.validate(); err != nil {
		_ = vault.Delete(ctx, refresh)
		return ErrEnrollment
	}
	if err := SaveProfile(dir, next); err != nil {
		_ = vault.Delete(ctx, refresh)
		return err
	}
	if p.Refresh != "" && p.Refresh != refresh {
		_ = vault.Delete(ctx, p.Refresh)
	}
	return nil
}

// SetEnabled switches sync on or off without touching credentials or state.
// A running daemon observes the change at its next round.
func SetEnabled(dir string, enabled bool) error {
	p, err := LoadProfile(dir)
	if Disabled(err) {
		if enabled {
			return ErrNotEnrolled
		}
		return nil
	}
	if err != nil {
		return err
	}
	if enabled && !p.Enrolled() {
		return ErrNotEnrolled
	}
	p.Enabled = enabled
	return SaveProfile(dir, p)
}

// Logout cancels this destination's queue, removes its cursors and fetched
// controls, deletes both credential slots and removes the profile.
func Logout(ctx context.Context, dir string, vault SecretVault) error {
	p, err := LoadProfile(dir)
	if Disabled(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	if p.Enrolled() {
		st, err := OpenState(ctx, dir)
		if err != nil {
			errs = append(errs, err)
		} else {
			errs = append(errs, st.purgeDestination(ctx, destination(p.Scope())))
			errs = append(errs, st.Close())
		}
	}
	errs = append(errs, DeleteCredentials(ctx, vault, p.Credential, p.Refresh))
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return store.RemoveSyncProfile(dir)
}

// StatusReport is the public, secret-free sync state.
type StatusReport struct {
	Configured     bool             `json:"configured"`
	Enabled        bool             `json:"enabled"`
	Enrolled       bool             `json:"enrolled"`
	Origin         string           `json:"origin,omitempty"`
	Tenant         string           `json:"tenant,omitempty"`
	User           string           `json:"user,omitempty"`
	Config         string           `json:"config,omitempty"`
	Repos          []string         `json:"repos,omitempty"`
	GrantExpiresAt int64            `json:"grant_expires_at,omitempty"`
	Rules          []Rule           `json:"rules"`
	Outbox         map[string]int64 `json:"outbox"`
	Receipts       int64            `json:"receipts"`
	Quarantined    int64            `json:"quarantined"`
	CtlCursor      int64            `json:"ctl_cursor"`
	DataCursor     int64            `json:"data_cursor"`
	AckedCtl       int64            `json:"acked_ctl"`
	AckedData      int64            `json:"acked_data"`
	BarrierHSeq    int64            `json:"barrier_hseq,omitempty"`
	BarrierReason  string           `json:"barrier_reason,omitempty"`
	LastError      string           `json:"last_error,omitempty"`
	LastRound      int64            `json:"last_round,omitempty"`
}

// Status reads the profile and sync database without contacting the network.
func Status(ctx context.Context, dir string) (StatusReport, error) {
	out := StatusReport{Rules: []Rule{}, Outbox: map[string]int64{}}
	p, err := LoadProfile(dir)
	if Disabled(err) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Configured, out.Enabled, out.Enrolled = true, p.Enabled, p.Enrolled()
	st, err := OpenState(ctx, dir)
	if err != nil {
		return out, err
	}
	defer st.Close()
	if out.Rules, err = st.Rules(ctx); err != nil {
		return out, err
	}
	if !p.Enrolled() {
		return out, nil
	}
	out.Origin, out.Tenant, out.User, out.Config = p.Origin, p.Tenant, p.User, p.Config
	out.Repos, out.GrantExpiresAt = append([]string(nil), p.Grant.Repos...), p.Grant.ExpiresAtUnix
	dest := destination(p.Scope())
	c, err := st.cursors(ctx, dest)
	if err != nil {
		return out, err
	}
	out.CtlCursor, out.DataCursor, out.AckedCtl, out.AckedData = c.Ctl, c.Data, c.AckedCtl, c.AckedData
	out.BarrierHSeq, out.BarrierReason, out.LastError, out.LastRound = c.BarrierHSeq, c.BarrierReason, c.LastError, c.LastRound
	err = st.tx(ctx, func(q querier) error {
		rows, err := q.QueryContext(ctx, "SELECT state,count(*) FROM outbox WHERE destination=? GROUP BY state", dest)
		if err != nil {
			return errStateInvalid
		}
		defer rows.Close()
		for rows.Next() {
			var state string
			var n int64
			if rows.Scan(&state, &n) != nil {
				return errStateInvalid
			}
			out.Outbox[state] = n
		}
		if rows.Err() != nil {
			return errStateInvalid
		}
		if q.QueryRowContext(ctx, "SELECT count(*) FROM delivery_receipt WHERE destination=?", dest).Scan(&out.Receipts) != nil {
			return errStateInvalid
		}
		if q.QueryRowContext(ctx, "SELECT count(*) FROM data_quarantine WHERE destination=?", dest).Scan(&out.Quarantined) != nil {
			return errStateInvalid
		}
		return nil
	})
	return out, err
}

// validRefresh accepts only the bootstrap memory credential shape the client
// presents at mint, never a session token.
func validRefresh(s string) bool {
	if !strings.HasPrefix(s, "telara_mcp_") || len(s) > maxRefresh {
		return false
	}
	return !strings.ContainsAny(s, "\r\n\t ")
}

// Blockers lists the durable reasons sync is not making progress, in a fixed
// order, from a status report alone. An unconfigured profile has none: sync
// is simply off. The last round failure code is reported verbatim, for example
// sync_hosted_log_unavailable when the hosted control log is absent.
func Blockers(r StatusReport, now time.Time) []string {
	out := []string{}
	if !r.Configured {
		return out
	}
	if !r.Enrolled {
		out = append(out, "not_enrolled")
	}
	if !r.Enabled {
		out = append(out, "disabled")
	}
	if r.Enrolled && r.GrantExpiresAt > 0 && now.Unix() >= r.GrantExpiresAt {
		out = append(out, "grant_expired")
	}
	if r.BarrierReason != "" {
		out = append(out, ErrControlBlocked.Error()+":"+r.BarrierReason)
	}
	if r.LastError != "" && r.LastError != "cancelled" {
		out = append(out, r.LastError)
	}
	if r.Quarantined > 0 {
		out = append(out, "hosted_data_quarantined")
	}
	return out
}
