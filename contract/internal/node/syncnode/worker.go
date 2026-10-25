package syncnode

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"os"
	"strconv"
	gosync "sync"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	nodesync "github.com/Telara-Labs/telara-memory/contract/internal/node/sync"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

// Round timing is fixed in code. A successful round waits Interval; failures
// back off exponentially with full jitter between MinBackoff and MaxBackoff.
const (
	Interval   = time.Minute
	MinBackoff = 5 * time.Second
	MaxBackoff = 5 * time.Minute
	// maxPages bounds one class scan per round; the next round resumes.
	maxPages = 256
	// maxPushes bounds operations sent per round.
	maxPushes = 16
)

var (
	// ErrControlBlocked reports a control that cannot be enforced. PUSH and
	// PULL(data) are skipped and ctl_cursor stays below it until it can.
	ErrControlBlocked = errors.New("sync_control_blocked")
	ErrHostedLog      = errors.New("sync_hosted_log_unavailable")
)

// Config assembles a worker. Dir is the owner-only data directory holding the
// profile and sync database. TLSRoots overrides the system pool for a private
// test or enterprise deployment and is code configuration, never environment.
type Config struct {
	Dir      string
	Store    Store
	Signer   RecordSigner
	Vault    SecretVault
	TLSRoots *x509.CertPool
	// Clock and wait hooks exist for deterministic tests.
	Now      func() time.Time
	MaxRetry int
}

// Worker runs one sync round at a time under the daemon.
type Worker struct {
	cfg    Config
	state  *State
	mu     gosync.Mutex // the single round mutex
	client *nodesync.Client
	digest string
	ob     *outbox
	cancel context.CancelFunc
	done   chan struct{}
	wake   chan struct{}
}

// NewWorker opens the sync database. It does not start a goroutine or read
// credentials; Start or Round does that only for an enabled profile.
func NewWorker(ctx context.Context, cfg Config) (*Worker, error) {
	if cfg.Store == nil || cfg.Dir == "" {
		return nil, ErrUnsupported
	}
	st, err := OpenState(ctx, cfg.Dir)
	if err != nil {
		return nil, err
	}
	if cfg.Now != nil {
		st.now = cfg.Now
	}
	return &Worker{cfg: cfg, state: st, wake: make(chan struct{}, 1)}, nil
}

// Start runs rounds until Stop or parent cancellation.
func (w *Worker) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	w.cancel = cancel
	w.done = make(chan struct{})
	go w.loop(ctx)
}

// Kick requests an immediate round without waiting.
func (w *Worker) Kick() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Stop cancels any in-flight round, waits for it, and closes the database.
func (w *Worker) Stop() error {
	if w.cancel != nil {
		w.cancel()
		<-w.done
	}
	return w.state.Close()
}

func (w *Worker) loop(ctx context.Context) {
	defer close(w.done)
	failures := 0
	delay := time.Duration(0)
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-w.wake:
			timer.Stop()
		case <-timer.C:
		}
		err := w.Round(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil && !errors.Is(err, ErrNotEnrolled) {
			failures++
			delay = backoff(failures)
			continue
		}
		failures = 0
		delay = Interval
	}
}

func backoff(failures int) time.Duration {
	ceiling := MinBackoff << min(failures-1, 10)
	if ceiling > MaxBackoff || ceiling <= 0 {
		ceiling = MaxBackoff
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(ceiling-MinBackoff)+1))
	if err != nil {
		return ceiling
	}
	return MinBackoff + time.Duration(n.Int64())
}

// Round runs HELLO, PULL(control), ENFORCE, PUSH, PULL(data), APPLY and ACK
// once. A disabled or missing profile does nothing and sends nothing.
func (w *Worker) Round(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	p, err := LoadProfile(w.cfg.Dir)
	if Disabled(err) || err == nil && (!p.Enabled || !p.Enrolled()) {
		return ErrNotEnrolled
	}
	if err != nil {
		return err
	}
	client, ob, err := w.clientFor(p)
	if err != nil {
		return err
	}
	err = w.round(ctx, p, client, ob)
	failure := ""
	if err != nil {
		failure = publicCode(err)
	}
	if ctx.Err() == nil {
		_ = w.state.recordRound(ctx, ob.dest, failure)
	}
	return err
}

func (w *Worker) clientFor(p Profile) (*nodesync.Client, *outbox, error) {
	digest := profileDigest(p)
	if w.client != nil && w.digest == digest {
		return w.client, w.ob, nil
	}
	if w.cfg.Vault == nil {
		return nil, nil, ErrCredential
	}
	authKey, err := p.AuthKey.PublicKey()
	if err != nil {
		return nil, nil, ErrProfile
	}
	keys := &sig.State{Genesis: p.Genesis, Keys: map[string]*sig.Key{}}
	for _, k := range p.ServiceKeys {
		pub, err := k.public()
		if err != nil {
			return nil, nil, ErrProfile
		}
		keys.Keys[record.H("authority", string(record.RoleService), p.Tenant, k.KeyID)] = &sig.Key{KeyID: k.KeyID, Pub: ed25519.PublicKey(pub), Role: record.RoleService, Tenant: p.Tenant, Status: sig.KeyActive}
	}
	scope := p.Scope()
	ob := newOutbox(w.state, w.cfg.Store, scope)
	client, err := nodesync.New(nodesync.Config{Scope: scope, Grant: *p.Grant, Keystore: VaultKeystore{Vault: w.cfg.Vault, Key: p.Credential, Refresh: p.Refresh, Tenant: p.Tenant}, Outbox: ob, Keys: pinnedKeys{keys}, AuthKey: authKey, AuthIssuer: p.AuthIssuer, TLSRoots: w.cfg.TLSRoots, MaxRetries: w.cfg.MaxRetry})
	if err != nil {
		return nil, nil, err
	}
	w.client, w.digest, w.ob = client, digest, ob
	return client, ob, nil
}

type pinnedKeys struct{ st *sig.State }

func (k pinnedKeys) State(context.Context) (*sig.State, error) { return k.st, nil }

func (w *Worker) round(ctx context.Context, p Profile, client *nodesync.Client, ob *outbox) error {
	c, err := w.state.cursors(ctx, ob.dest)
	if err != nil {
		return err
	}
	depth, err := w.state.outboxDepth(ctx, ob.dest)
	if err != nil {
		return err
	}
	hello := transport.Hello{DeviceID: p.Device, Contract: record.ContractVersion, CtlCursor: c.Ctl, DataCursor: c.Data, KeysetVersion: c.Keyset, OutboxDepth: depth}
	reply, err := client.Hello(ctx, hello)
	if err != nil {
		if status, ok := nodesync.HTTPStatus(err); ok && (status == 404 || status == 405 || status == 501) {
			return ErrHostedLog
		}
		return err
	}
	if reply.KeysetVersion != c.Keyset {
		if err := w.state.recordKeyset(ctx, ob.dest, reply.KeysetVersion); err != nil {
			return err
		}
	}
	if err = w.pullControl(ctx, client, ob.dest, c.Ctl, reply.CtlHead); err != nil {
		return err
	}
	blocked, err := w.enforce(ctx, ob.dest, p.Device)
	if err != nil {
		return err
	}
	// Every control to the HELLO head is now enforced, which is the
	// reconciliation a restored node needs before serving restored data.
	if r, ok := w.cfg.Store.(restoreReconciler); ok && !blocked {
		if err = r.CompleteRestoreReconciliation(ctx); err != nil {
			return err
		}
	}
	var pushErr error
	if !blocked {
		pushErr = w.push(ctx, p, client, ob)
		if pushErr == nil || !errors.Is(pushErr, nodesync.ErrForbidden) && !errors.Is(pushErr, nodesync.ErrLoggedOut) {
			c, err = w.state.cursors(ctx, ob.dest)
			if err != nil {
				return err
			}
			if err = w.pullData(ctx, client, ob.dest, c.Data, reply.DataHead); err != nil {
				return err
			}
		}
	}
	c, err = w.state.cursors(ctx, ob.dest)
	if err != nil {
		return err
	}
	// ACK reports exactly the durable cursors, never the scan position.
	ack := transport.Ack{CtlEnforcedThrough: c.Ctl, DataAppliedThrough: c.Data}
	if err = client.Ack(ctx, ack); err != nil {
		return err
	}
	if err = w.state.recordAck(ctx, ob.dest, ack); err != nil {
		return err
	}
	if blocked {
		return ErrControlBlocked
	}
	return pushErr
}

// pullControl fetches every control page to ctl_head and persists exact
// envelopes. The scan position is in-round only; it is never a cursor or ACK.
func (w *Worker) pullControl(ctx context.Context, client *nodesync.Client, dest string, cursor, head int64) error {
	pos := cursor
	for i := 0; i < maxPages && pos < head; i++ {
		page, err := client.Log(ctx, "control", pos, head, nodesync.MaxPageItems)
		if err != nil {
			return err
		}
		if err = checkPage(page, "control", pos, head); err != nil {
			return err
		}
		if err = w.state.persistControls(ctx, dest, page.Items); err != nil {
			return err
		}
		pos = page.NextAfter
		if !page.More {
			break
		}
	}
	return nil
}

func checkPage(page transport.Page, class string, pos, head int64) error {
	if _, _, err := transport.ApplyPage(page, class, pos, head, func(transport.LogItem) bool { return true }); err != nil {
		return ErrHostedLog
	}
	if page.More && page.NextAfter <= pos || !page.More && page.NextAfter != head {
		return ErrHostedLog
	}
	return nil
}

// enforce applies fetched controls strictly in hseq order. The first control
// that is unknown, of a higher version, undecodable or refused by the store is
// a barrier: it stays pending and ctl_cursor stays below it.
//
// A control the store admitted while it still reports the owner blocked, such
// as an erasure whose event coverage is pending, is not yet enforced. Later
// recognized controls are scanned in a verification-only recovery so a
// supplement can complete it: restrictions apply durably at once, while key
// activation and policy relaxation are staged. A staged control stays in
// ctl_pending, marked staged, and is usable only to verify a supplemental
// erasure. Once the earlier control completes, staged controls are applied in
// log order with revalidation, and ctl_cursor advances only through the
// contiguous prefix that is complete. Restart rebuilds the view from the exact
// pending envelopes; nothing staged is ever live before that.
func (w *Worker) enforce(ctx context.Context, dest, device string) (bool, error) {
	var after, held int64
	var applied []int64
	staged := map[int64]pendingControl{}
	var view []store.SignedRecord
	for {
		pending, err := w.state.pendingControls(ctx, dest, after, 64)
		if err != nil {
			return false, err
		}
		if len(pending) == 0 {
			break
		}
		for _, c := range pending {
			after = c.HSeq
			var reason string
			if held == 0 {
				reason = w.applyControl(ctx, c, device)
			} else {
				var in *store.SignedRecord
				if reason, in = w.lookahead(ctx, c, device, view); in != nil {
					if err = w.state.stageControl(ctx, dest, c.HSeq); err != nil {
						return false, err
					}
					staged[c.HSeq] = c
					view = append(view, *in)
				}
			}
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			if reason != "" {
				if err = w.state.blockControl(ctx, dest, c.HSeq, reason); err != nil || held == 0 {
					return true, err
				}
				return true, w.state.blockControl(ctx, dest, held, "coverage_pending")
			}
			incomplete, err := w.enforcementIncomplete(ctx, c.Envelope.ID)
			if err != nil {
				return false, err
			}
			applied = append(applied, c.HSeq)
			if incomplete {
				if held == 0 {
					held = c.HSeq
				}
				continue
			}
			for _, h := range applied {
				if sc, ok := staged[h]; ok {
					if reason := w.commitStaged(ctx, sc, device); reason != "" {
						return true, w.state.blockControl(ctx, dest, h, reason)
					}
				}
				if err = w.state.completeControl(ctx, dest, h); err != nil {
					return false, err
				}
			}
			applied, held, staged, view = nil, 0, map[int64]pendingControl{}, nil
		}
	}
	if held != 0 {
		return true, w.state.blockControl(ctx, dest, held, "coverage_pending")
	}
	return false, nil
}

// enforcementIncomplete reports whether the store still holds the owner
// blocked after a control, which a coverage-pending erasure does until a
// supplement or the missing membership completes it.
func (w *Worker) enforcementIncomplete(ctx context.Context, id string) (bool, error) {
	if !record.IsHex64(id) {
		return false, nil
	}
	_, err := w.cfg.Store.Snapshot(ctx, store.ReadRequest{IDs: []string{id}})
	var e *store.Error
	if errors.As(err, &e) && e.OwnerBlocked {
		return true, nil
	}
	return false, err
}

// stagedAuthority is implemented by the node store. It admits erasure and
// retraction controls signed by any enrolled device of the pinned genesis
// without a local private key, and verifies controls against a
// verification-only view of completed authority plus staged controls.
type stagedAuthority interface {
	ApplySupplement(context.Context, store.SignedRecord, []store.SignedRecord) (store.AdmissionResult, error)
	VerifyStaged(context.Context, []store.SignedRecord) error
	StagePolicy(context.Context, store.SignedRecord, []store.SignedRecord) (bool, error)
}

// checkControl decodes a fetched control. A non-empty reason is a barrier.
func checkControl(c pendingControl) (*record.Record, store.SignedRecord, string) {
	r, err := transport.CheckEnvelope(c.Envelope, c.Body)
	if err != nil {
		if c.Envelope.V != record.Version {
			return nil, store.SignedRecord{}, "unsupported_version"
		}
		return nil, store.SignedRecord{}, "unknown_control"
	}
	if !r.Header.Type.IsControl() {
		return nil, store.SignedRecord{}, "class_mismatch"
	}
	return r, store.SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: c.Envelope.Sigs, AdvisoryID: r.ID}, ""
}

func storeReason(err error) string {
	if err != nil {
		return "store_" + store.Code(err)
	}
	return ""
}

// applyErasure admits an erasure or retraction. Another device's control goes
// through the store's supplement path, which needs no local signing key; view
// is the staged authority an erasure may be verified against.
func (w *Worker) applyErasure(ctx context.Context, r *record.Record, in store.SignedRecord, device string, view []store.SignedRecord) error {
	if sa, ok := w.cfg.Store.(stagedAuthority); ok && r.Header.Author.MachineID != device {
		_, err := sa.ApplySupplement(ctx, in, view)
		return err
	}
	_, err := w.cfg.Store.ApplyControl(ctx, in)
	return err
}

func (w *Worker) applyControl(ctx context.Context, c pendingControl, device string) string {
	r, in, reason := checkControl(c)
	if reason != "" {
		return reason
	}
	var err error
	switch r.Header.Type {
	case record.KindErasure, record.KindRetraction:
		err = w.applyErasure(ctx, r, in, device, nil)
	case record.KindPolicy:
		_, err = w.cfg.Store.Append(ctx, in)
	case record.KindKeyOp:
		b, ok := r.Body.(*record.KeyOpBody)
		switch {
		case !ok:
			return "unknown_control"
		case b.Op == record.OpTenantKey:
			// Tenant roots are pinned only by an authenticated login.
			return "tenant_root_requires_login"
		case b.Subject.Role == record.RoleDevice:
			_, err = w.cfg.Store.Append(ctx, in)
		default:
			err = w.cfg.Store.OfferTenantKeyOperation(ctx, in)
		}
	default:
		return "unsupported_control"
	}
	return storeReason(err)
}

// lookahead handles a control that follows a coverage-pending erasure. Erasures
// and retractions, revocations and policies that relax nothing are applied
// durably now. Key activation and relaxing policies are verified against the
// staged view and returned for staging; they are not applied, though a staged
// policy's restrictions apply at once as the intersection with the committed
// head. Anything invalid in that view is a barrier.
func (w *Worker) lookahead(ctx context.Context, c pendingControl, device string, view []store.SignedRecord) (string, *store.SignedRecord) {
	r, in, reason := checkControl(c)
	if reason != "" {
		return reason, nil
	}
	sa, ok := w.cfg.Store.(stagedAuthority)
	if !ok {
		return "staging_unavailable", nil
	}
	switch r.Header.Type {
	case record.KindErasure, record.KindRetraction:
		return storeReason(w.applyErasure(ctx, r, in, device, view)), nil
	case record.KindPolicy:
		// A relaxing policy's restrictions join the store's effective-policy
		// overlay durably before it is staged, so a mixed policy tightens now.
		relaxes, err := sa.StagePolicy(ctx, in, view)
		if err != nil {
			return storeReason(err), nil
		}
		if relaxes {
			return "", &in
		}
		_, err = w.cfg.Store.Append(ctx, in)
		return storeReason(err), nil
	case record.KindKeyOp:
		b, ok := r.Body.(*record.KeyOpBody)
		switch {
		case !ok:
			return "unknown_control", nil
		case b.Op == record.OpTenantKey:
			return "tenant_root_requires_login", nil
		case b.Op == record.OpDeviceRevoke && sa.VerifyStaged(ctx, []store.SignedRecord{in}) == nil:
			// A revocation authorized by completed authority alone is a
			// restriction and applies durably at once. One whose subject or
			// parents are only staged applies within the view until then.
			_, err := w.cfg.Store.Append(ctx, in)
			return storeReason(err), nil
		}
		if err := sa.VerifyStaged(ctx, append(append([]store.SignedRecord(nil), view...), in)); err != nil {
			return storeReason(err), nil
		}
		return "", &in
	}
	return "unsupported_control", nil
}

// commitStaged applies a staged control durably once the erasure before it
// completed, revalidating it under current authority. A staged policy that a
// later, already committed policy superseded is complete.
func (w *Worker) commitStaged(ctx context.Context, c pendingControl, device string) string {
	reason := w.applyControl(ctx, c, device)
	if reason == "store_policy_rollback" {
		return ""
	}
	return reason
}

// push reconciles invalidated sources, exports newly selected metadata and
// drains the outbox one durable operation at a time.
func (w *Worker) push(ctx context.Context, p Profile, client *nodesync.Client, ob *outbox) error {
	if pol, err := w.cfg.Store.SyncPushPolicy(ctx); err == nil && pol.CancelOutbox {
		if err := w.state.cancelAll(ctx, ob.dest, "policy_kill"); err != nil {
			return err
		}
		return nil
	}
	if err := w.reconcile(ctx, ob.dest); err != nil {
		return err
	}
	// An export failure does not block draining already sealed operations;
	// the next round retries the export from current local state.
	_, _ = w.export(ctx, p, ob)
	for i := 0; i < maxPushes; i++ {
		ack, err := client.Push(ctx)
		if err == nil && ack == nil {
			return nil
		}
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch {
		case errors.Is(err, nodesync.ErrCancelled):
			// Authorize cancelled the whole operation durably.
			continue
		case errors.Is(err, nodesync.ErrInvalid):
			if op := ob.lastServed(); op != "" {
				if e := w.state.rejectOp(ctx, ob.dest, op, "invalid_operation"); e != nil {
					return e
				}
				continue
			}
			return err
		}
		if status, ok := nodesync.HTTPStatus(err); ok && status >= 400 && status < 500 && status != 401 && status != 403 && status != 429 {
			if op := ob.lastServed(); op != "" {
				if e := w.state.rejectOp(ctx, ob.dest, op, "hosted_refused"); e != nil {
					return e
				}
				continue
			}
		}
		return err
	}
	return nil
}

// pullData quarantines every hosted data item to data_head. v1 imports no
// hosted-origin records; data_cursor advances only with its page transaction.
func (w *Worker) pullData(ctx context.Context, client *nodesync.Client, dest string, cursor, head int64) error {
	pos := cursor
	for i := 0; i < maxPages && pos < head; i++ {
		page, err := client.Log(ctx, "data", pos, head, nodesync.MaxPageItems)
		if err != nil {
			return err
		}
		if err = checkPage(page, "data", pos, head); err != nil {
			return err
		}
		if err = w.state.applyData(ctx, dest, page.Items, page.NextAfter); err != nil {
			return err
		}
		pos = page.NextAfter
		if !page.More {
			break
		}
	}
	return nil
}

func publicCode(err error) string {
	for _, known := range []error{ErrControlBlocked, ErrHostedLog, ErrCredential, ErrProfile, nodesync.ErrForbidden, nodesync.ErrToken, nodesync.ErrReceipt, nodesync.ErrKeystoreUnavailable, nodesync.ErrInvalid, nodesync.ErrLoggedOut, errControlConflict, errStateInvalid} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	var retry *nodesync.RetryError
	if errors.As(err, &retry) {
		return retry.Error()
	}
	if status, ok := nodesync.HTTPStatus(err); ok {
		return "sync_http_" + strconv.Itoa(status)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "cancelled"
	}
	if errors.Is(err, os.ErrNotExist) {
		return "not_configured"
	}
	return "sync_error"
}

// restoreReconciler is implemented by the node store, which fences data
// restored from another device until a complete control enforcement pass.
type restoreReconciler interface {
	CompleteRestoreReconciliation(context.Context) error
}
