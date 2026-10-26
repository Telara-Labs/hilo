package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/telara-memory/contract/invalidate"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/policy"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/transport"
)

const bundleSchema = `
CREATE TABLE IF NOT EXISTS restore_fence(singleton INTEGER PRIMARY KEY CHECK(singleton=1), generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS imported_exposure(id TEXT PRIMARY KEY, fact BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS bundle_export(id TEXT PRIMARY KEY, staging TEXT NOT NULL, digest TEXT NOT NULL, cancelled INTEGER NOT NULL DEFAULT 0 CHECK(cancelled IN(0,1)));
CREATE TABLE IF NOT EXISTS bundle_export_item(export TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY(export,id));
CREATE TABLE IF NOT EXISTS bundle_export_variant(export TEXT NOT NULL, source TEXT NOT NULL, id TEXT NOT NULL, header BLOB NOT NULL, body BLOB NOT NULL, sigs BLOB NOT NULL, PRIMARY KEY(export,source));
CREATE TABLE IF NOT EXISTS bundle_receipt(id TEXT PRIMARY KEY, receipt BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS bundle_receipt_issuer(tenant TEXT NOT NULL, key_id TEXT NOT NULL, pub BLOB NOT NULL, PRIMARY KEY(tenant,key_id));
`

// maxBundleFacts bounds exposure facts and their array entries (07 §8.4.1).
const maxBundleFacts = 8192

// BundleExclusion names one selected or carried record that a bundle does not
// transfer, with a fixed content-free reason.
type BundleExclusion struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// Exclusion reasons.
const (
	ExcludedNotPresent        = "not_present"
	ExcludedNotData           = "not_bundle_data"
	ExcludedUnavailable       = "unavailable"
	ExcludedPolicy            = "policy_denied"
	ExcludedLineageIncomplete = "lineage_incomplete"
	ExcludedExposurePending   = "exposure_facts_pending"
	ExcludedForeign           = "foreign_owner"
	// ExcludedReceiptPending is a record whose verification depends on a
	// hosted receipt this device cannot verify without an existing TLS pin
	// of the receipt issuer. Restoring the same bundle after login resumes it.
	ExcludedReceiptPending = "receipt_pending"
)

// BundleSelection is the exact signed content of one bundle: the complete
// device keyring, the exposure facts relevant to the selected data as exact
// canonical 07 §8.4.1 lines, every erasure and retraction control, then the
// selected eligible data, each in admission order.
type BundleSelection struct {
	Keyring        []SignedRecord
	Facts          [][]byte
	Controls, Data []SignedRecord
	Excluded       []BundleExclusion
	// Receipts are verified hosted acceptance receipts this device holds for
	// carried keyring or data records, by record id. They are never grants.
	Receipts map[string]record.Receipt
}

// bundleDataKind is the §2.1 device-authored data allowlist for full-body
// bundles. Policy, key and control records are never bundle data.
func bundleDataKind(k record.Kind) bool {
	switch k {
	case record.KindSession, record.KindChunk, record.KindConclusion, record.KindTask, record.KindCheckpoint, record.KindPause, record.KindCall, record.KindBinding, record.KindDigest, record.KindRollup:
		return true
	}
	return false
}

func signedOf(x *stored) SignedRecord {
	return SignedRecord{HeaderJCS: append([]byte(nil), x.rec.HeaderJCS...), BodyJCS: append([]byte(nil), x.rec.BodyJCS...), Sigs: append([]record.Signature(nil), x.sigs...), AdvisoryID: x.rec.ID}
}

// bundleAuthorization is the complete current authority for one record under
// the same policy facts disclosure uses, evaluated under the store writer.
// Any installed active tenant makes data policy-governed; a retained
// per-record pol always does. A retained pol of another tenant, or of a
// policy this device never verified, has no provenance here.
func (d *databaseState) bundleAuthorization(r *record.Record) transport.BundleAuthorization {
	pol := r.Header.Pol
	a := transport.BundleAuthorization{ProvenanceKnown: true, LogoutRestricted: pol != "" && d.policyLogout[pol], ActivePolicy: d.tenant != nil}
	t := d.tenant
	if t == nil {
		return a
	}
	if pol != "" && d.policyTenants[pol] != t.tenant {
		a.ProvenanceKnown = false
		return a
	}
	a.LoggedIn = true
	a.Freshness = t.freshness
	b := t.body()
	if b == nil {
		return a
	}
	a.Policy = b
	a.Applicable = t.effects.DataPush && policy.AppliesTo(b, t.user)
	if meta, ok := r.Body.(*record.SessionMetaBody); ok && meta.Repo != nil {
		a.Repo = meta.Repo.Remote
	}
	if overlay, err := localpolicy.TenantOverlay(b); err == nil && r.Body != nil {
		a.ShapesSatisfied = bodyPolicyAllowed(r.Body, overlay)
	}
	// No bundle preview flow exists; a policy that requires preview denies.
	return a
}

// localFact converts one local exposure ledger entry to the wire fact. The
// node records no per-scope operation ordinal, so the boundary is unknown and
// attribution pending: the receiver keeps every potentially downstream record
// held. It reports false when the entry cannot be expressed exactly.
func localFact(f *exposureFact, exported map[string]bool) ([]byte, bool) {
	if !record.ValidScopeID(f.scope, f.machine) || !record.IsCallRef(f.source) || !record.IsHex64(f.root) {
		return nil, false
	}
	fact := transport.ExposureFact{OriginMachine: f.machine, ScopeID: f.scope, Boundary: transport.Boundary{Kind: "unknown"}, RecalledID: f.root, SourceCallOrEvent: transport.ExposureSource{Kind: "call", ID: f.source}, PendingAttribution: true}
	for id := range f.affects {
		if exported[id] {
			fact.AffectsIDs = append(fact.AffectsIDs, id)
		}
	}
	sort.Strings(fact.AffectsIDs)
	line, err := jcs.MarshalRecord(fact)
	if err != nil {
		return nil, false
	}
	if _, err = transport.ParseExposure(line); err != nil {
		return nil, false
	}
	return line, true
}

// factAffects reports whether an imported fact may affect r: an affects_ids
// entry or, because the origin's operation order is unknown here, any record
// in the fact's session or any call in its origin scope. The recalled root
// itself is never its own dependent.
func factAffects(f transport.ExposureFact, r *record.Record) bool {
	if r.ID == f.RecalledID || r.Header.Type.IsControl() || r.Header.Type == record.KindKeyOp {
		return false
	}
	for _, id := range f.AffectsIDs {
		if id == r.ID {
			return true
		}
	}
	if f.SessionKey != "" && r.Header.Subj.SessionKey == f.SessionKey {
		return true
	}
	if call, ok := r.Body.(*record.CallBody); ok && f.ScopeID != "" && call.ScopeID == f.ScopeID {
		return true
	}
	return false
}

// importedTargets is every present record an imported fact may affect, plus
// its affects_ids that have not arrived yet.
func (d *databaseState) importedTargets(f transport.ExposureFact) []string {
	targets := map[string]bool{}
	for _, id := range f.AffectsIDs {
		targets[id] = true
	}
	for _, x := range d.records {
		if x.owner == d.store.opts.PinnedGenesisID && factAffects(f, x.rec) {
			targets[x.rec.ID] = true
		}
	}
	delete(targets, f.RecalledID)
	out := make([]string, 0, len(targets))
	for id := range targets {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// importedSemanticFacts unions every imported exposure fact into the model
// before evaluation. Facts only add semantic roots and holds; a target whose
// recalled root is absent is ancestry-pending, and invalidating a present root
// holds every target. Nothing here can release a restriction.
func (d *databaseState) importedSemanticFacts() error {
	for _, f := range d.importedFacts {
		targets := d.importedTargets(f)
		for _, id := range targets {
			if d.byID[id] == nil {
				continue
			}
			if d.semantic[id] == nil {
				d.semantic[id] = map[string]bool{}
			}
			d.semantic[id][f.RecalledID] = true
		}
		d.model.Expose(invalidate.Exposure{OriginMachine: f.OriginMachine, Scope: f.ScopeID, SessionKey: f.SessionKey, ID: f.RecalledID, UnknownOrder: true, AffectsIDs: targets})
	}
	return nil
}

func (s *Store) loadImportedFacts(ctx context.Context, d *databaseState) error {
	if err := s.loadReceipts(ctx, d); err != nil {
		return err
	}
	d.importedFacts = nil
	rows, err := s.conn.QueryContext(ctx, "SELECT id,fact FROM imported_exposure ORDER BY id LIMIT ?", maxBundleFacts+1)
	if err != nil {
		return failure("storage_error")
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var raw []byte
		if rows.Scan(&id, &raw) != nil {
			return failure("storage_error")
		}
		f, err := transport.ParseExposure(raw)
		if err != nil || factID(raw) != id {
			return failure("corrupt_database")
		}
		d.importedFacts = append(d.importedFacts, f)
		if len(d.importedFacts)+len(d.exposures) > maxBundleFacts {
			return &projectionLimit{}
		}
	}
	if rows.Err() != nil {
		return failure("storage_error")
	}
	return nil
}

func factID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// bundleIDs validates an explicit selection.
func bundleIDs(ids []string) (map[string]bool, error) {
	if len(ids) == 0 || len(ids) > 8192 {
		return nil, failure("invalid_request")
	}
	selected := map[string]bool{}
	for _, id := range ids {
		if !record.IsHex64(id) {
			return nil, failure("invalid_request")
		}
		selected[id] = true
	}
	return selected, nil
}

// SelectBundle evaluates an explicit selection under the store writer. It
// never adds unselected roots: a selected record whose recursive roots are not
// also selected, complete and eligible is excluded with its dependents. It
// selects existing records only; RegisterBundleExport also builds governed
// metadata variants.
func (s *Store) SelectBundle(ctx context.Context, ids []string) (BundleSelection, error) {
	selected, err := bundleIDs(ids)
	if err != nil {
		return BundleSelection{}, err
	}
	var out BundleSelection
	err = s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked {
			return d.blockedError()
		}
		out, _, err = s.selectLocked(ctx, d, selected, variantNone, nil)
		return err
	})
	if err != nil {
		return BundleSelection{}, err
	}
	return out, nil
}

// Variant modes of a selection.
const (
	variantNone  = iota // existing records only
	variantCheck        // eligibility of governed metadata variants, unsigned
	variantSign         // eligible governed metadata variants, signed
)

// bundleSelection is the evaluated content of a selection: the signed
// selection and, for the erasure lifecycle, the identity of every item and
// every data or variant source id it carries. A variant's identity is its
// source id together with its salt-free content identity, so a variant built
// under different redaction, authority or key is a different selection.
type bundleSelection struct {
	items    []string
	sources  []string
	variants []bundleVariantItem
}

// bundleVariantItem is one governed metadata variant a selection carries,
// with the source it was built from.
type bundleVariantItem struct {
	source string
	rec    SignedRecord
}

func (b bundleSelection) digest() string {
	items := append([]string(nil), b.items...)
	sort.Strings(items)
	h := sha256.New()
	for _, it := range items {
		h.Write([]byte(it))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// selectLocked evaluates selected ids under the caller's writer transaction.
func (s *Store) selectLocked(ctx context.Context, d *databaseState, ids map[string]bool, variants int, signer ControlSigner) (BundleSelection, bundleSelection, error) {
	var meta bundleSelection
	selected := map[string]bool{}
	for id := range ids {
		selected[id] = true
	}
	out := BundleSelection{}
	// Data affected by a ledger entry that cannot travel exactly is not
	// exported without the restriction that must accompany it.
	unserializable := map[string]bool{}
	ledger := map[string]bool{}
	for _, f := range d.exposures {
		ledger[f.root] = true
		for id := range f.affects {
			ledger[id] = true
		}
		if _, ok := localFact(f, nil); !ok {
			unserializable[f.root] = true
			for id := range f.affects {
				unserializable[id] = true
			}
		}
	}
	candidates := map[string]transport.BundleRecord{}
	for _, x := range d.records {
		h := x.rec.Header
		switch {
		case h.Type == record.KindKeyOp:
			if b, ok := x.rec.Body.(*record.KeyOpBody); ok && b.Subject.Role == record.RoleDevice && b.Genesis == s.opts.PinnedGenesisID {
				out.Keyring = append(out.Keyring, signedOf(x))
				meta.items = append(meta.items, "k:"+x.rec.ID)
			}
			continue
		case h.Type == record.KindErasure || h.Type == record.KindRetraction:
			if x.rec.Body != nil && x.sigStatus == sig.StatusVerified {
				out.Controls = append(out.Controls, signedOf(x))
				meta.items = append(meta.items, "c:"+x.rec.ID)
			}
			continue
		case !bundleDataKind(h.Type) || x.owner != s.opts.PinnedGenesisID:
			continue
		}
		c := transport.BundleRecord{Record: x.rec, ID: x.rec.ID, Authorization: d.bundleAuthorization(x.rec), Selected: selected[x.rec.ID], SelectorIdentity: true}
		c.CompleteSigned = x.rec.Body != nil && x.bodySeen && x.sigStatus == sig.StatusVerified && len(x.sigs) == 1
		c.Live = x.state == "live"
		c.Pending = x.state != "live" || unserializable[x.rec.ID]
		for _, r := range x.recalls {
			c.RecalledRoots = append(c.RecalledRoots, r.ID)
		}
		for root := range d.semantic[x.rec.ID] {
			c.RecalledRoots = append(c.RecalledRoots, root)
		}
		sort.Strings(c.RecalledRoots)
		if c.Selected {
			c.Grants = d.model.Grants(x.rec.ID)
		}
		candidates[x.rec.ID] = c
	}
	exported := map[string]bool{}
	for _, x := range d.records {
		id := x.rec.ID
		if !selected[id] {
			continue
		}
		delete(selected, id)
		c, ok := candidates[id]
		reason := ""
		switch {
		case !bundleDataKind(x.rec.Header.Type):
			reason = ExcludedNotData
		case x.owner != s.opts.PinnedGenesisID || !ok:
			reason = ExcludedForeign
		case !c.Live || !c.CompleteSigned || len(c.Grants) > 0:
			reason = ExcludedUnavailable
		case !transport.BundlePolicyAllowed(x.rec, c.Authorization):
			reason = ExcludedPolicy
			if variants == variantNone || unserializable[id] || ledger[id] || len(c.RecalledRoots) > 0 {
				break
			}
			// A governed full body never travels. Its fresh push-metadata
			// variant may, under the complete current authorization.
			v, err := s.bundleVariant(d, x, signer, variants == variantSign)
			if err != nil {
				return BundleSelection{}, meta, err
			}
			if v == nil {
				break
			}
			identity, ok := variantIdentity(*v)
			if !ok {
				return BundleSelection{}, meta, failure("invalid_record")
			}
			meta.items = append(meta.items, "v:"+id+":"+identity)
			meta.sources = append(meta.sources, id)
			meta.variants = append(meta.variants, bundleVariantItem{source: id, rec: *v})
			if variants == variantSign {
				out.Data = append(out.Data, *v)
			}
			continue
		case unserializable[id]:
			reason = ExcludedExposurePending
		case !transport.BundleEligible(id, candidates):
			reason = ExcludedLineageIncomplete
		}
		if reason != "" {
			out.Excluded = append(out.Excluded, BundleExclusion{ID: id, Reason: reason})
			meta.items = append(meta.items, "x:"+id+":"+reason)
			continue
		}
		exported[id] = true
		out.Data = append(out.Data, signedOf(x))
		meta.items = append(meta.items, "d:"+id)
		meta.sources = append(meta.sources, id)
	}
	missing := make([]string, 0, len(selected))
	for id := range selected {
		missing = append(missing, id)
	}
	sort.Strings(missing)
	for _, id := range missing {
		out.Excluded = append(out.Excluded, BundleExclusion{ID: id, Reason: ExcludedNotPresent})
		meta.items = append(meta.items, "x:"+id+":"+ExcludedNotPresent)
	}
	if err := s.bundleFacts(ctx, d, exported, &out); err != nil {
		return BundleSelection{}, meta, err
	}
	for _, f := range out.Facts {
		meta.items = append(meta.items, "f:"+factID(f))
	}
	out.Receipts = map[string]record.Receipt{}
	for _, part := range [][]SignedRecord{out.Keyring, out.Data} {
		for _, r := range part {
			if rc, ok := d.receipts[r.AdvisoryID]; ok {
				out.Receipts[r.AdvisoryID] = rc
			}
		}
	}
	return out, meta, nil
}

// bundleFacts carries every local ledger entry whose root or affected record
// is exported and forwards every imported fact relevant to exported data
// unchanged, preserving its origin namespace.
func (s *Store) bundleFacts(ctx context.Context, d *databaseState, exported map[string]bool, out *BundleSelection) error {
	lines := map[string][]byte{}
	for _, f := range d.exposures {
		relevant := exported[f.root]
		for id := range f.affects {
			relevant = relevant || exported[id]
		}
		if !relevant {
			continue
		}
		line, ok := localFact(f, exported)
		if !ok {
			return failure("invalid_exposure")
		}
		lines[string(line)] = line
	}
	rows, err := s.conn.QueryContext(ctx, "SELECT fact FROM imported_exposure ORDER BY id")
	if err != nil {
		return failure("storage_error")
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			return failure("storage_error")
		}
		f, err := transport.ParseExposure(raw)
		if err != nil {
			return failure("corrupt_database")
		}
		relevant := exported[f.RecalledID]
		for _, id := range d.importedTargets(f) {
			relevant = relevant || exported[id]
		}
		if relevant {
			lines[string(raw)] = raw
		}
	}
	if rows.Err() != nil {
		return failure("storage_error")
	}
	keys := make([]string, 0, len(lines))
	for k := range lines {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	entries := 0
	for _, k := range keys {
		f, _ := transport.ParseExposure(lines[k])
		entries += len(f.AffectsIDs) + len(f.BindingEvidenceIDs)
		out.Facts = append(out.Facts, lines[k])
	}
	if len(out.Facts) > maxBundleFacts || entries > maxBundleFacts {
		return failure("bundle_limit")
	}
	return nil
}

// BundleImport is verified bundle content. The adapter has already decrypted
// it, verified the manifest signature under this pinned genesis and checked
// framing, including every fact line against 07 §8.4.1.
type BundleImport struct {
	LocalKeyID     string
	Keyring        []SignedRecord
	Facts          [][]byte
	Controls, Data []SignedRecord
	// Receipts are the carried hosted acceptance receipts by record id. They
	// verify only under ReceiptIssuer, this device's existing TLS-pinned
	// receipt authority; a bundle never supplies that authority.
	Receipts      map[string]record.Receipt
	ReceiptIssuer *ReceiptIssuer
	// ConfirmedControls are the carried controls with unbounded selector
	// effect that the receiving owner reviewed and confirmed locally.
	ConfirmedControls []string
}

// BundleImportReport counts admitted items, including exact duplicates.
type BundleImportReport struct {
	Keyring, Facts, Controls, Data int
	Excluded                       []BundleExclusion
	Fenced                         bool
}

// ImportBundle admits one bundle through the ordinary admission path in a
// single transaction: keyring, then the exposure fact union, then controls,
// then eligible data. Local tombs and bans are applied by admission, so a
// restored older bundle cannot resurrect erased data. Any invalid item
// refuses the whole bundle, as does any carried control with unbounded
// selector effect that the receiving owner has not confirmed.
func (s *Store) ImportBundle(ctx context.Context, in BundleImport) (BundleImportReport, error) {
	var report BundleImportReport
	if !record.IsKeyID(in.LocalKeyID) || len(in.Keyring)+len(in.Controls)+len(in.Data) > 16384 || len(in.Facts) > maxBundleFacts || len(in.Receipts) > 16384 || len(in.ConfirmedControls) > 16384 {
		return report, failure("invalid_request")
	}
	_, statErr := os.Lstat(filepath.Join(s.opts.Dir, SyncProfileName))
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return report, failure("storage_error")
	}
	hosted := statErr == nil
	err := s.write(ctx, func() error {
		// Verify carried receipts under current receiver authority inside the
		// writer. A concurrent service rotation cannot race this decision.
		issuer := in.ReceiptIssuer
		if issuer != nil && issuer.valid() {
			current := *issuer
			if kr, err := s.serviceKeyring(ctx, issuer.Tenant); err == nil {
				current.state = kr.State()
			} else if Code(err) != "service_pins_required" {
				return err
			}
			issuer = &current
		}
		verified := issuer.verify(in.Receipts)
		s.bundleImport = true
		s.controlConfirm = map[string]bool{}
		for _, id := range in.ConfirmedControls {
			s.controlConfirm[id] = true
		}
		defer func() { s.bundleImport, s.controlConfirm = false, nil }()
		report = BundleImportReport{}
		admit := func(in SignedRecord, allowed func(record.Kind) bool) error {
			r, signatures, err := parseBundleItem(in)
			if err != nil {
				return err
			}
			if !allowed(r.Header.Type) {
				return failure("invalid_bundle")
			}
			_, err = s.appendLocked(ctx, r, signatures)
			return err
		}
		if len(verified) > 0 {
			if err := s.persistReceiptIssuer(ctx, in.ReceiptIssuer); err != nil {
				return err
			}
		}
		for _, item := range in.Keyring {
			if err := admit(item, func(k record.Kind) bool { return k == record.KindKeyOp }); err != nil {
				return err
			}
			if rc, ok := verified[item.AdvisoryID]; ok {
				if err := s.persistReceipt(ctx, rc); err != nil {
					return err
				}
			}
			report.Keyring++
		}
		// The restoring device must itself be enrolled in this genesis by the
		// carried or local keyring: a co-signed device_add for any device that
		// is not the genesis key. A bundle cannot enroll the receiver.
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		k := d.kr.State().KeyFor(in.LocalKeyID, record.RoleDevice, "")
		if k == nil || k.Status != sig.KeyActive || k.Genesis != s.opts.PinnedGenesisID || k.MachineID != s.opts.LocalMachineID {
			return failure("device_not_enrolled")
		}
		// Union exposure restrictions before any control or data, durably.
		machines := map[string]bool{}
		for _, key := range d.kr.State().Keys {
			if key.Role == record.RoleDevice && key.Genesis == s.opts.PinnedGenesisID {
				machines[key.MachineID] = true
			}
		}
		for _, raw := range in.Facts {
			f, err := transport.ParseExposure(raw)
			if err != nil || !machines[f.OriginMachine] {
				return failure("invalid_bundle")
			}
			if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO imported_exposure VALUES(?,?)", factID(raw), raw); err != nil {
				return failure("storage_error")
			}
			report.Facts++
		}
		for _, item := range in.Controls {
			if err := admit(item, func(k record.Kind) bool { return k == record.KindErasure || k == record.KindRetraction }); err != nil {
				return err
			}
			report.Controls++
		}
		eligible, excluded, err := s.importEligibility(ctx, in, verified)
		if err != nil {
			return err
		}
		report.Excluded = excluded
		for _, item := range eligible {
			if rc, ok := verified[item.AdvisoryID]; ok {
				if err := s.persistReceipt(ctx, rc); err != nil {
					return err
				}
			}
			if err := admit(item, bundleDataKind); err != nil {
				return err
			}
			report.Data++
		}
		if hosted && report.Data > 0 {
			// A hosted-enrolled node must complete PULL(control)+ENFORCE before
			// imported data from another device can be served.
			if _, err = s.conn.ExecContext(ctx, "INSERT INTO restore_fence VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation", d.generation+1); err != nil {
				return failure("storage_error")
			}
			report.Fenced = true
		}
		return nil
	})
	if err != nil {
		return BundleImportReport{}, err
	}
	return report, nil
}

// importEligibility rechecks current receiver policy and requires every
// recursive root of each data record, including every recalled root named by
// a persisted exposure fact, to be carried complete in this bundle,
// independent of line order. A record signed by a since-revoked key is
// complete only through a receipt verified under this device's existing
// receipt pin; without that pin it stays out and resumable.
func (s *Store) importEligibility(ctx context.Context, in BundleImport, verified map[string]record.Receipt) ([]SignedRecord, []BundleExclusion, error) {
	var excluded []BundleExclusion
	d, err := s.load(ctx)
	if err != nil {
		return nil, nil, err
	}
	st := d.kr.State()
	candidates := map[string]transport.BundleRecord{}
	parsed := map[string]*record.Record{}
	pending := map[string]bool{}
	for _, item := range in.Data {
		r, signatures, err := parseBundleItem(item)
		if err != nil {
			return nil, nil, err
		}
		if !bundleDataKind(r.Header.Type) || candidates[r.ID].Record != nil {
			return nil, nil, failure("invalid_bundle")
		}
		res := sig.VerifyRecord(r, signatures, st, sig.Context{Route: record.RouteBundleImport})
		if res.Status == sig.StatusSignerRevoked {
			if rc, ok := verified[r.ID]; ok {
				res = d.verifyWithReceipt(r, signatures, st, 0, &rc)
			} else if rc, carried := in.Receipts[r.ID]; carried && (in.ReceiptIssuer == nil || in.ReceiptIssuer.Tenant != rc.Tenant) {
				pending[r.ID] = true
			}
		}
		x := &stored{rec: r}
		material(x)
		c := transport.BundleRecord{Record: r, ID: r.ID, Selected: true, Live: true, SelectorIdentity: true, Authorization: d.bundleAuthorization(r)}
		c.CompleteSigned = r.Body != nil && res.Status == sig.StatusVerified && res.Owner == s.opts.PinnedGenesisID && len(signatures) == 1
		for _, rc := range x.recalls {
			c.RecalledRoots = append(c.RecalledRoots, rc.ID)
		}
		for _, f := range d.importedFacts {
			if factAffects(f, r) {
				c.RecalledRoots = append(c.RecalledRoots, f.RecalledID)
			}
		}
		candidates[r.ID] = c
		parsed[r.ID] = r
	}
	var out []SignedRecord
	for _, item := range in.Data {
		r := parsed[item.AdvisoryID]
		if r == nil {
			return nil, nil, failure("invalid_bundle")
		}
		c := candidates[r.ID]
		reason := ""
		switch {
		case pending[r.ID]:
			reason = ExcludedReceiptPending
		case !c.CompleteSigned:
			reason = ExcludedUnavailable
		case !transport.BundlePolicyAllowed(r, c.Authorization) || d.tenant.validateBody(r) != nil:
			// Admission seals governed data to the current head; a record
			// that admission would refuse is a policy exclusion, not a
			// refusal of the whole bundle.
			reason = ExcludedPolicy
		case !transport.BundleEligible(r.ID, candidates):
			reason = ExcludedLineageIncomplete
		}
		if reason != "" {
			excluded = append(excluded, BundleExclusion{ID: r.ID, Reason: reason})
			continue
		}
		out = append(out, item)
	}
	return out, excluded, nil
}

// CompleteRestoreReconciliation releases the restore fence after a hosted
// round completed PULL(control) and ENFORCE without a blocked control.
func (s *Store) CompleteRestoreReconciliation(ctx context.Context) error {
	return s.write(ctx, func() error {
		fenced, err := s.restoreFenced(ctx)
		if err != nil || !fenced {
			return err
		}
		if _, err = s.conn.ExecContext(ctx, "DELETE FROM restore_fence"); err != nil {
			return failure("storage_error")
		}
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		d.generation++
		if _, err = s.conn.ExecContext(ctx, "UPDATE meta SET generation=? WHERE singleton=1", d.generation); err != nil {
			return failure("storage_error")
		}
		return s.persistState(ctx, d)
	})
}

// RestorePending reports whether restored data from another device is held
// until a hosted control enforcement pass completes.
func (s *Store) RestorePending(ctx context.Context) (bool, error) {
	var fenced bool
	err := s.write(ctx, func() error {
		var err error
		fenced, err = s.restoreFenced(ctx)
		return err
	})
	return fenced, err
}

func (s *Store) restoreFenced(ctx context.Context) (bool, error) {
	var n int
	if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM restore_fence").Scan(&n) != nil {
		return false, failure("storage_error")
	}
	return n > 0, nil
}

// Keyring returns every stored device key operation of the pinned genesis in
// admission order, the public keyring a bundle or an enrollment carries.
func (s *Store) Keyring(ctx context.Context) ([]SignedRecord, error) {
	var out []SignedRecord
	err := s.write(ctx, func() error {
		rows, err := s.conn.QueryContext(ctx, "SELECT r.id,r.header,r.sigs,b.body FROM record r JOIN record_body b ON b.id=r.id WHERE json_extract(CAST(r.header AS TEXT),'$.type')='key_op' ORDER BY r.seq")
		if err != nil {
			return failure("storage_error")
		}
		defer rows.Close()
		out = nil
		for rows.Next() {
			var id string
			var header, sigs, body []byte
			if rows.Scan(&id, &header, &sigs, &body) != nil {
				return failure("storage_error")
			}
			r, err := record.Parse(header, body, id)
			if err != nil {
				return failure("corrupt_database")
			}
			b, ok := r.Body.(*record.KeyOpBody)
			if !ok || b.Subject.Role != record.RoleDevice || b.Genesis != s.opts.PinnedGenesisID {
				continue
			}
			var signatures []record.Signature
			if json.Unmarshal(sigs, &signatures) != nil {
				return failure("corrupt_database")
			}
			out = append(out, SignedRecord{HeaderJCS: r.HeaderJCS, BodyJCS: r.BodyJCS, Sigs: signatures, AdvisoryID: id})
		}
		if rows.Err() != nil {
			return failure("storage_error")
		}
		return nil
	})
	return out, err
}
