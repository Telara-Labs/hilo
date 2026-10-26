package syncnode

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
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
	// ErrLoginUnverified reports a login document whose tenant policy root is
	// not the one the authenticated TLS login response of its origin returned
	// for this device and tenant, or a login that response could not confirm.
	ErrLoginUnverified = errors.New("login_root_unverified")
)

// maxLoginDocument bounds one login document read from standard input.
const maxLoginDocument = 1 << 20

// LoginDocument is the result of one authenticated hosted login: the device
// enrollment plus the tenant policy root and the current signed policy that the
// same login returned. It is read from the owner's terminal input, which is not
// an authority for the root: Login pins only a root the origin itself returns
// over validated TLS under a session bound to this device's key, and refuses a
// document naming any other. Sync, bundles and control pages never supply one.
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

// LoginReport is the public, secret-free login result. CredentialCleanup is
// "complete" when every retired credential slot is deleted, and "pending" when
// a deletion failed; the slot stays recorded and is retried by the next login,
// enrollment or logout until its deletion is established.
type LoginReport struct {
	State             string `json:"state"`
	Tenant            string `json:"tenant"`
	Policy            string `json:"policy"`
	Seq               int64  `json:"seq"`
	CredentialCleanup string `json:"credential_cleanup"`
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
	if err := checkBinding(ctx, vault, p, e); err != nil {
		return Profile{}, err
	}
	next := p
	next.Enabled = true
	next.Origin, next.Tenant, next.User, next.Config = e.Origin, e.Tenant, e.User, e.Config
	next.AuthIssuer = e.AuthIssuer
	key := e.AuthKey
	next.AuthKey = &key
	// Keys named by terminal input are never pins; only LoginTLS replaces
	// them with keys the authenticated TLS login response returned.
	next.ServiceKeys = append([]ServiceKey(nil), e.ServiceKeys...)
	next.ServiceKeyPins = ""
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

// checkBinding checks that e is for this installation's genesis and device,
// that the device key is in custody and that the refresh credential has the
// bootstrap shape.
func checkBinding(ctx context.Context, vault SecretVault, p Profile, e Enrollment) error {
	if e.Grant.GenesisID != p.Genesis || e.Grant.DeviceID != p.Device {
		return ErrIdentity
	}
	if _, err := CredentialThumbprint(ctx, vault, p.Credential); err != nil {
		return ErrCredential
	}
	if !validRefresh(e.RefreshToken) {
		return ErrEnrollment
	}
	return nil
}

// crashPoint is called between the durable steps of a credential
// replacement. It does nothing; tests replace it to stop the process there.
var crashPoint = func(string) {}

// commitProfile stores the refresh credential and atomically saves next. The
// caller holds the profile lock and read p under it.
// Credential slots are never forgotten: the new slot is recorded as retired
// before it is created, so a crash before next is durable deletes it, and next
// records the replaced refresh slot as retired in the same atomic replacement
// that stops using it. Retired slots are then deleted; any whose deletion
// fails stays recorded and is retried later. It reports whether cleanup is
// complete.
func commitProfile(ctx context.Context, dir string, vault SecretVault, p, next Profile, refreshToken string) (bool, error) {
	if len(refreshToken) == 0 || len(refreshToken) > maxRefresh {
		return false, ErrEnrollment
	}
	refresh, err := newHandle()
	if err != nil {
		return false, err
	}
	intent := p
	intent.Retired = retire(p.Retired, refresh)
	if err = SaveProfile(dir, intent); err != nil {
		return false, err
	}
	crashPoint("intent_saved")
	secret := []byte(refreshToken)
	err = vault.Put(ctx, refresh, secret)
	clear(secret)
	if err != nil {
		_, _ = retireCredentials(context.WithoutCancel(ctx), dir, vault)
		return false, err
	}
	crashPoint("refresh_stored")
	next.Refresh = refresh
	next.Retired = without(intent.Retired, refresh)
	if p.Refresh != "" && p.Refresh != refresh {
		next.Retired = retire(next.Retired, p.Refresh)
	}
	if err = next.validate(); err != nil {
		_, _ = retireCredentials(context.WithoutCancel(ctx), dir, vault)
		return false, ErrEnrollment
	}
	if err = SaveProfile(dir, next); err != nil {
		_, _ = retireCredentials(context.WithoutCancel(ctx), dir, vault)
		return false, err
	}
	crashPoint("profile_replaced")
	return retireCredentials(ctx, dir, vault)
}

// retireCredentials deletes every retired slot of the current profile and
// records each established deletion. The caller holds the profile lock. It reports whether none remains; a
// deletion that fails leaves its slot recorded for the next attempt.
func retireCredentials(ctx context.Context, dir string, vault SecretVault) (bool, error) {
	p, err := LoadProfile(dir)
	if Disabled(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if len(p.Retired) == 0 {
		return true, nil
	}
	var kept []string
	for _, h := range p.Retired {
		if vault == nil || vault.Delete(ctx, h) != nil {
			kept = append(kept, h)
		}
	}
	crashPoint("retired_deleted")
	if len(kept) == len(p.Retired) {
		return false, nil
	}
	// Reload so a concurrent replacement's own intent is never dropped.
	current, err := LoadProfile(dir)
	if err != nil {
		return false, err
	}
	deleted := map[string]bool{}
	for _, h := range p.Retired {
		deleted[h] = !contains(kept, h)
	}
	var left []string
	for _, h := range current.Retired {
		if !deleted[h] {
			left = append(left, h)
		}
	}
	current.Retired = left
	if err = SaveProfile(dir, current); err != nil {
		return false, err
	}
	return len(left) == 0, nil
}

func retire(xs []string, h string) []string {
	if contains(xs, h) {
		return append([]string(nil), xs...)
	}
	return append(append([]string(nil), xs...), h)
}

func without(xs []string, h string) []string {
	var out []string
	for _, x := range xs {
		if x != h {
			out = append(out, x)
		}
	}
	return out
}

// loginKeystore presents the device's DPoP key from the vault and the login's
// refresh credential from memory, before either is committed to the profile.
type loginKeystore struct {
	vault   SecretVault
	key     string
	refresh string
	tenant  string
}

func (k loginKeystore) Load(ctx context.Context, s nodesync.Scope) (nodesync.Credentials, error) {
	if s.Tenant != k.tenant || len(k.refresh) == 0 || len(k.refresh) > maxRefresh {
		return nodesync.Credentials{}, nodesync.ErrKeystoreUnavailable
	}
	v := VaultKeystore{Vault: k.vault, Key: k.key}
	key, err := v.read(ctx)
	if err != nil {
		return nodesync.Credentials{}, nodesync.ErrKeystoreUnavailable
	}
	public, err := nodesync.PublicJWKOf(&key.PublicKey)
	if err != nil {
		return nodesync.Credentials{}, nodesync.ErrKeystoreUnavailable
	}
	return nodesync.Credentials{Refresh: k.refresh, DPoP: &vaultSigner{store: v, public: public}}, nil
}

// DeleteTenant deletes nothing: the login has not committed any slot.
func (loginKeystore) DeleteTenant(context.Context, nodesync.Scope) error { return nil }

// loginOutbox sends nothing; a login client only reads its login response.
type loginOutbox struct{}

func (loginOutbox) Next(context.Context, nodesync.Scope, nodesync.Limits) (*nodesync.Operation, error) {
	return nil, nil
}
func (loginOutbox) Authorize(context.Context, nodesync.Scope, string, string) (bool, error) {
	return false, nil
}
func (loginOutbox) Complete(context.Context, nodesync.Scope, nodesync.Acknowledgment) error {
	return nodesync.ErrInvalid
}
func (loginOutbox) Retry(context.Context, nodesync.Scope, nodesync.Retry) error {
	return nodesync.ErrInvalid
}
func (loginOutbox) Logout(context.Context, nodesync.Scope) error { return nil }

// verifiedLogin performs the authenticated login exchange with the document's
// origin over validated TLS (roots nil means the system pool) and returns the
// tenant policy root and the receipt issuer's service keys that response
// carries. The session is minted with this device's DPoP key and the
// document's refresh credential and verified against the document's pinned
// issuer key, so the tenant, user and config are authenticated; the response
// must name the same origin, destination and device, its root must be a
// policy tenant_key for that tenant, and each service key a service
// tenant_key for that tenant with a verifying possession signature. The
// document's own root must be exactly that root, and any service keys it
// names exactly that set.
func verifiedLogin(ctx context.Context, p Profile, vault SecretVault, roots *x509.CertPool, d LoginDocument) (store.SignedRecord, []ServiceKey, error) {
	root, keys, err := verifiedLoginReply(ctx, p, vault, roots, d)
	if err != nil {
		return store.SignedRecord{}, nil, err
	}
	if len(d.ServiceKeys) > 0 && !sameServiceKeys(d.ServiceKeys, keys) {
		return store.SignedRecord{}, nil, ErrLoginUnverified
	}
	return root, keys, nil
}

func verifiedLoginReply(ctx context.Context, p Profile, vault SecretVault, roots *x509.CertPool, d LoginDocument) (store.SignedRecord, []ServiceKey, error) {
	authKey, err := d.AuthKey.PublicKey()
	if err != nil {
		return store.SignedRecord{}, nil, ErrLogin
	}
	scope := nodesync.Scope{Origin: d.Origin, Tenant: d.Tenant, User: d.User, Config: d.Config, Genesis: p.Genesis, Device: p.Device}
	client, err := nodesync.New(nodesync.Config{Scope: scope, Grant: d.Grant, Keystore: loginKeystore{vault: vault, key: p.Credential, refresh: d.RefreshToken, tenant: d.Tenant}, Outbox: loginOutbox{}, Keys: pinnedKeys{&sig.State{Genesis: p.Genesis, Keys: map[string]*sig.Key{}}}, AuthKey: authKey, AuthIssuer: d.AuthIssuer, TLSRoots: roots, MaxRetries: 1})
	if err != nil {
		return store.SignedRecord{}, nil, ErrLogin
	}
	defer client.Logout(context.WithoutCancel(ctx))
	reply, err := client.Login(ctx)
	if err != nil {
		return store.SignedRecord{}, nil, errors.Join(ErrLoginUnverified, err)
	}
	root, rootRec, err := signedOf(reply.PolicyRoot)
	if err != nil || !policyRootOf(rootRec, d.Tenant) {
		return store.SignedRecord{}, nil, ErrLoginUnverified
	}
	claimed, claimedRec, err := signedOf(d.PolicyRoot)
	if err != nil {
		return store.SignedRecord{}, nil, err
	}
	if claimedRec.ID != rootRec.ID || !bytes.Equal(claimed.BodyJCS, root.BodyJCS) || !sameSigs(claimed.Sigs, root.Sigs) {
		return store.SignedRecord{}, nil, ErrLoginUnverified
	}
	keys, err := pinnedServiceKeys(p.Genesis, d.Tenant, reply.ServiceKeys)
	if err != nil {
		return store.SignedRecord{}, nil, err
	}
	return root, keys, nil
}

// maxServiceKeys bounds the service keys one login response may pin.
const maxServiceKeys = 16

// pinnedServiceKeys verifies the service keys of an authenticated login
// response. Each must be an exact tenant_key operation of the authenticated
// tenant with role service, no parents and one verifying possession signature
// by its subject, verified as a login-pinned service key; the set must be
// non-empty, bounded and free of duplicates. Anything else refuses the whole
// login: a partial pin set is never recorded.
func pinnedServiceKeys(genesis, tenant string, envs []record.Envelope) ([]ServiceKey, error) {
	if len(envs) == 0 || len(envs) > maxServiceKeys {
		return nil, ErrLoginUnverified
	}
	seen := map[string]bool{}
	var out []ServiceKey
	for _, e := range envs {
		r, err := nodesync.OpenEnvelope(e)
		if err != nil {
			return nil, ErrLoginUnverified
		}
		b, ok := r.Body.(*record.KeyOpBody)
		if !ok || r.Header.Type != record.KindKeyOp || b.Op != record.OpTenantKey || b.Subject.Role != record.RoleService || b.Genesis != tenant || len(b.Parents) != 0 {
			return nil, ErrLoginUnverified
		}
		op := &sig.KeyOp{Rec: r, Body: b, Sigs: append([]record.Signature(nil), e.Sigs...), FromLogin: true, Issuer: sig.TrustedIssuer{Tenant: tenant, Role: record.RoleService, Provenance: sig.PinnedTLSLogin}}
		if sig.VerifyKeyOp(sig.NewKeyring(genesis), op).Status != sig.OpAuthorized {
			return nil, ErrLoginUnverified
		}
		k := ServiceKey{KeyID: b.Subject.KeyID, Public: b.Subject.Pub}
		if _, err := k.public(); err != nil || seen[k.KeyID] {
			return nil, ErrLoginUnverified
		}
		seen[k.KeyID] = true
		out = append(out, k)
	}
	return out, nil
}

// sameServiceKeys reports whether two key lists name the same set.
func sameServiceKeys(a, b []ServiceKey) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[ServiceKey]bool{}
	for _, k := range b {
		set[k] = true
	}
	for _, k := range a {
		if !set[k] {
			return false
		}
	}
	return true
}

func policyRootOf(r *record.Record, tenant string) bool {
	b, ok := r.Body.(*record.KeyOpBody)
	return ok && r.Header.Type == record.KindKeyOp && b.Op == record.OpTenantKey && b.Subject.Role == record.RolePolicy && b.Genesis == tenant
}

func sameSigs(a, b []record.Signature) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func signedOf(e record.Envelope) (store.SignedRecord, *record.Record, error) {
	r, err := nodesync.OpenEnvelope(e)
	if err != nil {
		return store.SignedRecord{}, nil, ErrLogin
	}
	return store.SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: append([]record.Signature(nil), e.Sigs...), AdvisoryID: r.ID}, r, nil
}

// Login is LoginTLS against the system certificate pool.
func Login(ctx context.Context, dir string, vault SecretVault, d LoginDocument) (LoginReport, error) {
	return LoginTLS(ctx, dir, vault, nil, d)
}

// LoginTLS binds one authenticated hosted login to this device. It obtains the
// tenant policy root from the origin's authenticated login response over TLS
// validated against roots (nil means the system pool), bound to the requested
// origin, this device and the authenticated tenant, and refuses a document
// whose root differs. It then pins that root, admits the login's signed policy
// in the node store and enables sync for that one destination. A login to a
// different destination or tenant is refused with ErrTenantConflict until an
// explicit Logout; nothing from an earlier tenant is reused or copied.
func LoginTLS(ctx context.Context, dir string, vault SecretVault, roots *x509.CertPool, d LoginDocument) (LoginReport, error) {
	defer func() { d.RefreshToken = "" }()
	var out LoginReport
	_, rootRec, err := signedOf(d.PolicyRoot)
	if err != nil {
		return out, err
	}
	if !policyRootOf(rootRec, d.Tenant) {
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
	// The profile is read and checked under the profile lock, which is not
	// held across the network exchange; the commit below takes it again and
	// proceeds only if the profile is still exactly the one checked here.
	var p Profile
	err = withProfileLock(ctx, dir, func() error {
		var err error
		if p, err = LoadProfile(dir); Disabled(err) {
			return ErrNotEnrolled
		} else if err != nil {
			return err
		}
		// Retry any earlier retirement first; its outcome is reported below.
		if _, err = retireCredentials(ctx, dir, vault); err != nil {
			return err
		}
		if p, err = LoadProfile(dir); err != nil {
			return err
		}
		if _, err = checkSecondLogin(ctx, dir, p, d.Enrollment); err != nil {
			return err
		}
		return checkBinding(ctx, vault, p, d.Enrollment)
	})
	if err != nil {
		return out, err
	}
	root, keys, err := verifiedLogin(ctx, p, vault, roots, d)
	if err != nil {
		return out, err
	}
	err = withProfileLock(ctx, dir, func() error {
		current, err := LoadProfile(dir)
		if Disabled(err) || err == nil && profileDigest(current) != profileDigest(p) {
			return ErrProfileChanged
		}
		if err != nil {
			return err
		}
		wasActive, err := checkSecondLogin(ctx, dir, current, d.Enrollment)
		if err != nil {
			return err
		}
		// Receipt authority comes only from the authenticated response.
		e := d.Enrollment
		e.ServiceKeys = keys
		next, err := bindProfile(ctx, vault, current, e)
		if err != nil {
			return err
		}
		next.ServiceKeyPins = string(sig.PinnedTLSLogin)
		st, err := store.Open(ctx, store.Options{Dir: dir, PinnedGenesisID: current.Genesis, LocalMachineID: current.Device})
		if err != nil {
			return err
		}
		defer st.Close()
		// A failure after the tenant authority was installed by this login
		// deactivates it again. Its pin and admission facts remain, as after
		// any logout; a re-login of an already active tenant is never rolled
		// back.
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
				return ErrTenantConflict
			}
			return err
		}
		if _, err = st.Append(ctx, pol); err != nil {
			return undo(err)
		}
		// The login's policy must now be the verified head with its body. A
		// replay of a policy whose body logout already purged cannot reopen
		// it.
		if id, body, err := st.CapturePolicy(ctx); err != nil || id != polRec.ID || body == nil {
			return undo(ErrPolicyNotCurrent)
		}
		clean, err := commitProfile(ctx, dir, vault, current, next, d.RefreshToken)
		if err != nil {
			return undo(err)
		}
		out = LoginReport{State: "logged_in", Tenant: d.Tenant, Policy: polRec.ID, Seq: pb.Seq, CredentialCleanup: cleanupState(clean)}
		return nil
	})
	if err != nil {
		return LoginReport{}, err
	}
	return out, nil
}

func cleanupState(clean bool) string {
	if clean {
		return "complete"
	}
	return "pending"
}

// LogoutDetailed ends the active login. In order it stops sync, cancels the
// destination's outbox and drops its cursors, fetched controls and
// quarantined hosted data, logs the tenant authority out of the node store
// (purging every policy body and salt while keeping pins, rollback, tamper
// and per-record logout facts), deletes the DPoP and refresh credentials and
// removes the profile. Records sealed under the tenant's policy stay local,
// non-pushable and non-bundleable. It never deletes hosted history.
func LogoutDetailed(ctx context.Context, dir string, vault SecretVault) (LogoutReport, error) {
	var out LogoutReport
	err := withProfileLock(ctx, dir, func() error {
		var err error
		out, err = logoutLocked(ctx, dir, vault)
		return err
	})
	if err != nil {
		return LogoutReport{}, err
	}
	return out, nil
}

// logoutLocked is LogoutDetailed under the profile lock.
func logoutLocked(ctx context.Context, dir string, vault SecretVault) (LogoutReport, error) {
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
		// Retired slots are deleted with the current ones; a failure keeps
		// the profile, and with it every recorded slot, for the next logout.
		errs = append(errs, DeleteCredentials(ctx, vault, append([]string{p.Credential, p.Refresh}, p.Retired...)...))
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
