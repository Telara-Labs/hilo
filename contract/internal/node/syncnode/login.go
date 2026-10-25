package syncnode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

var (
	// ErrTenantConflict refuses a login while another tenant authority is
	// active. Only an explicit logout of the first tenant clears it.
	ErrTenantConflict = errors.New("tenant_conflict")
	// ErrLogin reports a login document that is not one complete login.
	ErrLogin = errors.New("login_invalid")
	// ErrPolicyState reports installed tenant state that cannot be evaluated,
	// so a login cannot prove that no other tenant is active.
	ErrPolicyState = errors.New("policy_state_unavailable")
	// ErrPolicyNotCurrent reports a login whose policy is not the tenant's
	// current verified policy, for example one a logout already purged.
	ErrPolicyNotCurrent = errors.New("login_policy_not_current")
)

// maxLoginDocument bounds one login document read from standard input.
const maxLoginDocument = 1 << 20

// LoginDocument is the result of one authenticated hosted login: the device
// enrollment plus the tenant policy root and the current signed policy that the
// same login returned. It is read from the owner's terminal input only; sync,
// bundles and control pages can never supply a tenant root.
type LoginDocument struct {
	Enrollment
	PolicyRoot record.Envelope `json:"policy_root"`
	Policy     record.Envelope `json:"policy"`
}

// ParseLogin strictly decodes one login document.
func ParseLogin(r io.Reader) (LoginDocument, error) {
	var d LoginDocument
	b, err := io.ReadAll(io.LimitReader(r, maxLoginDocument+1))
	if err != nil || len(b) > maxLoginDocument {
		clear(b)
		return d, ErrLogin
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil || dec.Decode(new(any)) != io.EOF {
		clear(b)
		return LoginDocument{}, ErrLogin
	}
	clear(b)
	return d, nil
}

// LoginReport is the public, secret-free login result.
type LoginReport struct {
	State  string `json:"state"`
	Tenant string `json:"tenant"`
	Policy string `json:"policy"`
	Seq    int64  `json:"seq"`
}

// LogoutReport is the public logout result. Physical is "complete" when the
// purged policy configuration is also scrubbed from the database files, and
// "pending" when a reader held the scrub back; the logical logout is done
// either way. HostedHistory is fixed: logout deletes nothing hosted.
type LogoutReport struct {
	State         string `json:"state"`
	Physical      string `json:"physical"`
	HostedHistory string `json:"hosted_history"`
}

// sameScope reports whether an enrollment names the profile's exact
// authenticated destination.
func sameScope(p Profile, e Enrollment) bool {
	return p.Origin == e.Origin && p.Tenant == e.Tenant && p.User == e.User && p.Config == e.Config
}

// activeTenant reads the installed tenant authority without writing. It
// returns "" when none is active.
func activeTenant(ctx context.Context, dir string) (string, error) {
	d, err := store.Inspect(ctx, dir)
	if errors.Is(err, store.ErrNoDatabase) {
		return "", nil
	}
	if err != nil || d.Policy.EvaluationCode != "" {
		return "", ErrPolicyState
	}
	if !d.Policy.Installed {
		return "", nil
	}
	return d.Policy.Tenant, nil
}

// checkSecondLogin refuses any login whose destination differs from an
// enrolled profile, and any login to a tenant other than the active tenant
// authority. Re-login to the identical destination replaces its credential.
func checkSecondLogin(ctx context.Context, dir string, p Profile, e Enrollment) (bool, error) {
	if p.Enrolled() && !sameScope(p, e) {
		return false, ErrTenantConflict
	}
	active, err := activeTenant(ctx, dir)
	if err != nil {
		return false, err
	}
	if active != "" && active != e.Tenant {
		return false, ErrTenantConflict
	}
	return active == e.Tenant, nil
}

// bindProfile returns the enrolled profile for e without touching the vault.
// The refresh slot is a placeholder until the credential is stored.
func bindProfile(ctx context.Context, vault SecretVault, p Profile, e Enrollment) (Profile, error) {
	if e.Grant.GenesisID != p.Genesis || e.Grant.DeviceID != p.Device {
		return Profile{}, ErrIdentity
	}
	if _, err := CredentialThumbprint(ctx, vault, p.Credential); err != nil {
		return Profile{}, ErrCredential
	}
	if !validRefresh(e.RefreshToken) {
		return Profile{}, ErrEnrollment
	}
	next := p
	next.Enabled = true
	next.Origin, next.Tenant, next.User, next.Config = e.Origin, e.Tenant, e.User, e.Config
	next.AuthIssuer = e.AuthIssuer
	key := e.AuthKey
	next.AuthKey = &key
	next.ServiceKeys = append([]ServiceKey(nil), e.ServiceKeys...)
	grant := e.Grant
	grant.Repos = append([]string(nil), e.Grant.Repos...)
	grant.Ops = append([]string(nil), e.Grant.Ops...)
	next.Grant = &grant
	next.Refresh = strings.Repeat("0", 32)
	if next.Refresh == next.Credential || next.validate() != nil {
		return Profile{}, ErrEnrollment
	}
	return next, nil
}

// commitProfile stores the refresh credential and atomically saves next. The
// previous refresh slot is deleted only after the new profile is durable.
func commitProfile(ctx context.Context, dir string, vault SecretVault, p, next Profile, refreshToken string) error {
	refresh, err := StoreRefresh(ctx, vault, refreshToken)
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

func signedOf(e record.Envelope) (store.SignedRecord, *record.Record, error) {
	r, err := nodesync.OpenEnvelope(e)
	if err != nil {
		return store.SignedRecord{}, nil, ErrLogin
	}
	return store.SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: append([]record.Signature(nil), e.Sigs...), AdvisoryID: r.ID}, r, nil
}

// Login binds one authenticated hosted login to this device. It pins the
// tenant policy root and admits the login's signed policy in the node store,
// then enables sync for that one destination. A login to a different
// destination or tenant is refused with ErrTenantConflict until an explicit
// Logout; nothing from an earlier tenant is reused or copied.
func Login(ctx context.Context, dir string, vault SecretVault, d LoginDocument) (LoginReport, error) {
	defer func() { d.RefreshToken = "" }()
	var out LoginReport
	p, err := LoadProfile(dir)
	if Disabled(err) {
		return out, ErrNotEnrolled
	}
	if err != nil {
		return out, err
	}
	wasActive, err := checkSecondLogin(ctx, dir, p, d.Enrollment)
	if err != nil {
		return out, err
	}
	next, err := bindProfile(ctx, vault, p, d.Enrollment)
	if err != nil {
		return out, err
	}
	root, rootRec, err := signedOf(d.PolicyRoot)
	if err != nil {
		return out, err
	}
	if b, ok := rootRec.Body.(*record.KeyOpBody); !ok || rootRec.Header.Type != record.KindKeyOp || b.Op != record.OpTenantKey || b.Subject.Role != record.RolePolicy || b.Genesis != d.Tenant {
		return out, ErrLogin
	}
	pol, polRec, err := signedOf(d.Policy)
	if err != nil {
		return out, err
	}
	pb, ok := polRec.Body.(*record.PolicyBody)
	if !ok || polRec.Header.Type != record.KindPolicy || pb.Tenant != d.Tenant {
		return out, ErrLogin
	}
	st, err := store.Open(ctx, store.Options{Dir: dir, PinnedGenesisID: p.Genesis, LocalMachineID: p.Device})
	if err != nil {
		return out, err
	}
	defer st.Close()
	// A failure after the tenant authority was installed by this login
	// deactivates it again. Its pin and admission facts remain, as after any
	// logout; a re-login of an already active tenant is never rolled back.
	undo := func(cause error) error {
		if wasActive {
			return cause
		}
		if e := st.LogoutTenant(context.WithoutCancel(ctx)); e != nil && store.Code(e) != "physical_pending" {
			return errors.Join(cause, e)
		}
		return cause
	}
	if err = st.InstallTenantPolicyContext(ctx, store.TenantPolicyContext{Tenant: d.Tenant, UserID: d.User, Origin: d.Origin, Root: root}); err != nil {
		if store.Code(err) == "tenant_conflict" {
			return out, ErrTenantConflict
		}
		return out, err
	}
	if _, err = st.Append(ctx, pol); err != nil {
		return out, undo(err)
	}
	// The login's policy must now be the verified head with its body. A
	// replay of a policy whose body logout already purged cannot reopen it.
	if id, body, err := st.CapturePolicy(ctx); err != nil || id != polRec.ID || body == nil {
		return out, undo(ErrPolicyNotCurrent)
	}
	if err = commitProfile(ctx, dir, vault, p, next, d.RefreshToken); err != nil {
		return out, undo(err)
	}
	return LoginReport{State: "logged_in", Tenant: d.Tenant, Policy: polRec.ID, Seq: pb.Seq}, nil
}

// LogoutDetailed ends the active login. In order it stops sync, cancels the
// destination's outbox and drops its cursors, fetched controls and
// quarantined hosted data, logs the tenant authority out of the node store
// (purging every policy body and salt while keeping pins, rollback, tamper
// and per-record logout facts), deletes the DPoP and refresh credentials and
// removes the profile. Records sealed under the tenant's policy stay local,
// non-pushable and non-bundleable. It never deletes hosted history.
func LogoutDetailed(ctx context.Context, dir string, vault SecretVault) (LogoutReport, error) {
	out := LogoutReport{State: "logged_out", Physical: "complete", HostedHistory: "not_deleted"}
	p, err := LoadProfile(dir)
	configured := err == nil
	if err != nil && !Disabled(err) {
		return LogoutReport{}, err
	}
	active, err := activeTenant(ctx, dir)
	stateUnknown := errors.Is(err, ErrPolicyState)
	if err != nil && !stateUnknown {
		return LogoutReport{}, err
	}
	if !configured && active == "" && !stateUnknown {
		return out, nil
	}
	var errs []error
	if configured && p.Enabled {
		disabled := p
		disabled.Enabled = false
		errs = append(errs, SaveProfile(dir, disabled))
	}
	purge := func() {
		if !configured || !p.Enrolled() {
			return
		}
		st, err := OpenState(ctx, dir)
		if err != nil {
			errs = append(errs, err)
			return
		}
		errs = append(errs, st.purgeDestination(ctx, destination(p.Scope())), st.Close())
	}
	purge()
	if active != "" || stateUnknown {
		genesis, machine := p.Genesis, p.Device
		if !configured {
			if genesis, machine, err = store.InstalledIdentity(dir); err != nil {
				return LogoutReport{}, errors.Join(append(errs, ErrIdentity)...)
			}
		}
		st, err := store.Open(ctx, store.Options{Dir: dir, PinnedGenesisID: genesis, LocalMachineID: machine})
		if err != nil {
			errs = append(errs, err)
		} else {
			if err = st.LogoutTenant(ctx); store.Code(err) == "physical_pending" {
				out.Physical = "pending"
			} else if err != nil {
				errs = append(errs, err)
			}
			errs = append(errs, st.Close())
		}
	}
	if configured {
		errs = append(errs, DeleteCredentials(ctx, vault, p.Credential, p.Refresh))
	}
	if err := errors.Join(errs...); err != nil {
		return LogoutReport{}, err
	}
	if configured {
		if err := store.RemoveSyncProfile(dir); err != nil {
			return LogoutReport{}, err
		}
		// A round that was already running when sync stopped may have
		// queued rows; cancel them too.
		purge()
		if err := errors.Join(errs...); err != nil {
			return LogoutReport{}, err
		}
	}
	return out, nil
}
