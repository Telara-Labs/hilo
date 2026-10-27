package capture

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/store"
	"github.com/Telara-Labs/telara-memory/contract/record"
)

type Root struct{ Client, AbsPath string }
type Config struct {
	Home, OwnerGenesis, MachineID string
	Roots                         map[string]Root
	CaptureEnabled                bool
}

// Unit cannot select a session mapping, source identity, author or seal input.
type Unit struct{ RootID, RelativePath string }
type Result struct {
	Status              string
	OwnerBlocked        bool
	CommittedRecordIDs  []string
	CurrentAvailability map[string]string
	ProgressVersion     int64
}
type Pipeline struct {
	mu       sync.Mutex
	store    *store.Store
	signals  SignalStore
	config   Config
	keys     PreloadedKeyMaterial
	ruleset  record.Ruleset
	instance string
	closed   bool
}

// NewPipeline binds the real store and immutable trusted configuration. It does
// not install identity, read a keystore, configure a client or prove native use.
func NewPipeline(ctx context.Context, st *store.Store, cfg Config, keys PreloadedKeyMaterial) (*Pipeline, error) {
	defer keys.Clear()
	if ctx == nil || ctx.Err() != nil {
		return nil, hold("cancelled")
	}
	if st == nil || !record.IsKeyID(cfg.OwnerGenesis) || !record.IsUUIDv4(cfg.MachineID) || !keys.valid || !record.IsKeyID(keys.keyID) {
		return nil, hold("invalid_config")
	}
	if !filepath.IsAbs(cfg.Home) || filepath.Clean(cfg.Home) != cfg.Home || len(cfg.Roots) == 0 || len(cfg.Roots) > 16 {
		return nil, hold("invalid_config")
	}
	roots := map[string]Root{}
	for id, root := range cfg.Roots {
		if !identifier(id) || !supportedClient(root.Client) || !filepath.IsAbs(root.AbsPath) || filepath.Clean(root.AbsPath) != root.AbsPath {
			return nil, hold("invalid_config")
		}
		rel, err := filepath.Rel(cfg.Home, root.AbsPath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, hold("invalid_config")
		}
		roots[id] = root
	}
	cfg.Roots = roots
	rs, err := checkedRuleset()
	if err != nil {
		return nil, err
	}
	identity, err := st.Identity(ctx)
	if err != nil {
		return nil, storeFailure(err)
	}
	if identity.OwnerGenesis != cfg.OwnerGenesis || identity.MachineID != cfg.MachineID || identity.StoreInstanceID == "" {
		return nil, hold("store_identity")
	}
	signals, _ := any(st).(SignalStore)
	return &Pipeline{store: st, signals: signals, config: cfg, keys: keys, ruleset: rs, instance: identity.StoreInstanceID}, nil
}

func storeFailure(err error) error {
	var failure *store.Error
	if errors.As(err, &failure) && failure.OwnerBlocked {
		switch failure.Code {
		case "privacy_hold_required", "bulk_confirmation_required":
			return hold(failure.Code)
		default:
			return hold("owner_blocked")
		}
	}
	switch store.Code(err) {
	case "outcome_unknown":
		return hold("outcome_unknown")
	case "owner_blocked":
		return hold("owner_blocked")
	case "stale_progress", "ordinal_limit", "history_limit", "suppressed", "unauthorized_capture", "capture_txn_expired", "invalid_causal_state", "producer_refused",
		"policy_violation", "policy_unavailable", "signal_conflict", "invalid_signal", "not_suppressed":
		return hold(store.Code(err))
	default:
		return hold("store_refused")
	}
}

func refused(err error) (Result, error) {
	status := "held"
	if Code(err) == "outcome_unknown" {
		status = "outcome_unknown"
	}
	blocked := Code(err) == "owner_blocked" || Code(err) == "privacy_hold_required" || Code(err) == "bulk_confirmation_required"
	if blocked {
		status = "owner_blocked"
	}
	return Result{Status: status, OwnerBlocked: blocked}, err
}

// skipSuppressed reports a unit that erasure suppressed. An ordinary capture is
// held with "suppressed". A hook signal is acknowledged by its backend, which
// rechecks suppression and records the hint as done without reading or sealing
// anything, so the drain continues with other units and sources.
func skipSuppressed(ctx context.Context, q store.SourceOccurrence) (Result, error) {
	empty := Result{Status: "held"}
	admission, ok := ctx.Value(signalAdmissionKey{}).(signalAdmission)
	if !ok {
		return empty, hold("suppressed")
	}
	backend, ok := admission.store.(SuppressedSignalStore)
	if !ok {
		return empty, hold("suppressed")
	}
	if ctx.Err() != nil {
		return empty, hold("cancelled")
	}
	if err := backend.SkipSuppressedSignal(ctx, admission.signal, admission.ulid, q); err != nil {
		return refused(storeFailure(err))
	}
	return Result{Status: "suppressed"}, nil
}

func (p *Pipeline) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys.Clear()
	p.closed = true
	return nil
}

func (p *Pipeline) Capture(ctx context.Context, unit Unit) (Result, error) {
	return p.capture(ctx, unit, prepareHeld)
}

func sourceSettlement(h *openedUnitHandle) error {
	if !h.quiet(time.Now()) {
		if !h.bound() {
			return hold("source_changed")
		}
		return hold("source_unsettled")
	}
	return nil
}

type preparationStep func(context.Context, preparationConfig, unitLocator, preOpenGate) (preparedBatch, *openedUnitHandle, error)

// Private seam keeps the production opener fixed while allowing deterministic
// filesystem/SQLite interleavings in component tests.
func (p *Pipeline) capture(ctx context.Context, unit Unit, prepare preparationStep) (Result, error) {
	empty := Result{Status: "held"}
	if p == nil || ctx == nil || ctx.Err() != nil {
		return empty, hold("cancelled")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.keys.valid {
		return empty, hold("closed")
	}
	if !p.config.CaptureEnabled {
		return empty, hold("no_capture")
	}
	root, ok := p.config.Roots[unit.RootID]
	if !ok {
		return empty, hold("unknown_root")
	}
	policy, _ := selectLocalPolicy("local", false)
	policyID, tenant, err := p.store.CapturePolicy(ctx)
	if err != nil {
		return refused(storeFailure(err))
	}
	policy.overlay, err = localpolicy.TenantOverlay(tenant)
	if err != nil {
		return refused(hold("policy_unavailable"))
	}
	c := preparationConfig{root: root.AbsPath, home: p.config.Home, owner: p.config.OwnerGenesis, machine: p.config.MachineID, enabled: true, policy: policy}
	// Derive keys from the validated UUID filename before any source read.
	u := unitLocator{client: root.Client, relative: unit.RelativePath, source: strings.Repeat("0", 64), session: "sk1:" + strings.Repeat("0", 64)}
	native, err := resolve(c, u)
	if err != nil {
		return empty, err
	}
	if !record.IsUUID(native) {
		return empty, hold("unresolved_session")
	}
	u.session, err = record.SessionKey(u.client, "local", record.NativeGlobal, native, c.machine)
	if err != nil {
		return empty, hold("unresolved_identity")
	}
	rootRelative, _ := filepath.Rel(c.home, c.root)
	u.source, err = record.SourceKey(u.client, c.machine, filepath.ToSlash(filepath.Join(rootRelative, u.relative)))
	if err != nil {
		return empty, hold("unresolved_identity")
	}
	occ, err := occurrence(c, u, native)
	if err != nil {
		return empty, err
	}
	identity, err := p.store.Identity(ctx)
	if err != nil {
		return refused(storeFailure(err))
	}
	if identity.StoreInstanceID != p.instance || identity.OwnerGenesis != p.config.OwnerGenesis || identity.MachineID != p.config.MachineID {
		return refused(hold("outcome_unknown"))
	}
	query := store.SourceOccurrence{Owner: occ.owner, Source: occ.source, SessionKey: occ.session}
	inspection, err := p.store.InspectCapture(ctx, query)
	if err != nil {
		return refused(storeFailure(err))
	}
	if inspection.Suppression.OwnerBlocked {
		return refused(hold("owner_blocked"))
	}
	if inspection.Suppression.Suppressed {
		return skipSuppressed(ctx, query)
	}
	repository, err := p.store.CaptureRepository(ctx, query)
	if err != nil {
		return refused(storeFailure(err))
	}
	batch, h, err := prepare(ctx, c, u, func(ctx context.Context, _ sourceOccurrence) (gateState, error) {
		gate, e := p.store.Suppressed(ctx, query)
		return gateState{suppressed: gate.Suppressed, ownerBlocked: gate.OwnerBlocked}, e
	})
	if Code(err) == "suppressed" {
		return skipSuppressed(ctx, query)
	}
	if err != nil {
		return refused(err)
	}
	defer h.close()
	if err := sourceSettlement(h); err != nil {
		return empty, err
	}
	events, err := normalize(batch, p.ruleset)
	if err != nil {
		return empty, err
	}
	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	request := store.CaptureRequest{PolicyID: policyID, Occurrence: query, AuthorKeyID: p.keys.keyID, ExpectedVersion: inspection.Progress.Version, Reader: record.SourceRef{Reader: root.Client, ReaderVersion: runtimeReaderVersion}, RulesetFingerprint: p.ruleset.Fingerprint(), EventIDs: ids, Range: store.CaptureRange{First: 0, LastExclusive: int64(len(events))}}
	if repository.ID != "" {
		request.RepositoryBinding = repository.ID
		request.RepositoryGeneration = repository.Generation
		request.Repository = &record.RepoRef{ID: repository.Repo, Remote: repository.Remote}
	}
	if ctx.Err() != nil {
		return empty, hold("cancelled")
	}
	commit := p.store.Capture
	if admission, ok := ctx.Value(signalAdmissionKey{}).(signalAdmission); ok {
		commit = func(ctx context.Context, q store.CaptureRequest, produce func(*store.CaptureTxn) (store.CommitPlan, error)) (store.CaptureReceipt, error) {
			return admission.store.CaptureSignal(ctx, admission.signal, admission.ulid, q, produce)
		}
	}
	var producerErr, planErr error
	receipt, err := commit(ctx, request, func(tx *store.CaptureTxn) (store.CommitPlan, error) {
		if ctx.Err() != nil {
			return store.CommitPlan{}, hold("cancelled")
		}
		if producerErr = sourceSettlement(h); producerErr != nil {
			planErr = producerErr
			return store.CommitPlan{}, producerErr
		}
		plan, e := p.produce(tx, request, batch, events, h)
		planErr = e
		if e != nil && Code(e) == "source_changed" {
			producerErr = sourceSettlement(h)
			planErr = producerErr
		}
		return plan, e
	})
	if err != nil {
		// Only a confirmed callback refusal (rolled back by Store) may carry
		// our local settling classification. Never mask storage/outcome errors.
		if store.Code(err) == "producer_refused" && Code(producerErr) == "source_unsettled" {
			return empty, producerErr
		}
		if Code(err) != "capture_failure" {
			return empty, err
		}
		if err = storeFailure(err); Code(err) == "suppressed" {
			// Erasure landed between inspection and the writer, which rolled back.
			return skipSuppressed(ctx, query)
		}
		if Code(err) == "producer_refused" {
			// Keep the public code; retain only the fixed local refusal code.
			if local, ok := planErr.(*Error); ok && local.cause == "" {
				err = &Error{code: "producer_refused", cause: local.code}
			}
		}
		return refused(err)
	}
	if receipt.Status != "committed" && receipt.Status != "no_change" && receipt.Status != "prior_transition_committed" {
		return Result{Status: "outcome_unknown"}, hold("outcome_unknown")
	}
	result := Result{Status: receipt.Status, ProgressVersion: receipt.ResultingProgress.Version, CurrentAvailability: map[string]string{}}
	for _, r := range receipt.ActualRecordRefs {
		result.CommittedRecordIDs = append(result.CommittedRecordIDs, r.ID)
	}
	sort.Strings(result.CommittedRecordIDs)
	for id, state := range receipt.CurrentAvailability {
		result.CurrentAvailability[id] = state
	}
	return result, nil
}
