package store

import (
	"context"
	"database/sql"
	"math"
	"sort"
	"strconv"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

func validOccurrence(o Options, q SourceOccurrence) bool {
	if q.Owner != o.PinnedGenesisID || !record.IsHex64(q.Source) || !record.IsSessionKey(q.SessionKey) || len(q.EventIDs) > 4096 {
		return false
	}
	for _, id := range q.EventIDs {
		if !record.IsEventID(id) {
			return false
		}
	}
	return true
}
func readerValid(r record.SourceRef) bool {
	if r.Reader != "claude-code" && r.Reader != "codex" && r.Reader != "cursor-agent" && r.Reader != "pi" {
		return false
	}
	if len(r.ReaderVersion) == 0 || len(r.ReaderVersion) > 128 {
		return false
	}
	for _, c := range r.ReaderVersion {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == '+') {
			return false
		}
	}
	return true
}
func (s *Store) checkInstance(ctx context.Context) error {
	var id string
	if s.conn.QueryRowContext(ctx, "SELECT id FROM capture_instance WHERE singleton=1").Scan(&id) != nil || id != s.instanceID {
		s.poisoned = true
		return failure("outcome_unknown")
	}
	return nil
}

// Identity is factual configuration, never proof against restored old copies.
func (s *Store) Identity(ctx context.Context) (CaptureIdentity, error) {
	var out CaptureIdentity
	err := s.writeMode(ctx, true, func() error {
		if e := s.checkInstance(ctx); e != nil {
			return e
		}
		out = CaptureIdentity{s.opts.PinnedGenesisID, s.opts.LocalMachineID, s.instanceID}
		return nil
	})
	if err != nil {
		return CaptureIdentity{}, err
	}
	return out, nil
}
func (s *Store) InspectCapture(ctx context.Context, q SourceOccurrence) (CaptureInspection, error) {
	if !validOccurrence(s.opts, q) {
		return CaptureInspection{}, failure("invalid_request")
	}
	var out CaptureInspection
	err := s.writeMode(ctx, true, func() error {
		if e := s.checkInstance(ctx); e != nil {
			return e
		}
		d, e := s.load(ctx)
		if e != nil {
			if _, settled := e.(*postCommitRefusal); settled {
				return e
			}
			s.poisoned = true
			return failure("outcome_unknown")
		}
		p, e := s.captureProgress(ctx, q)
		if e != nil {
			s.poisoned = true
			return failure("outcome_unknown")
		}
		out = CaptureInspection{p, suppression(d, q)}
		return nil
	})
	if err != nil {
		return CaptureInspection{}, err
	}
	return out, nil
}
func (s *Store) captureProgress(ctx context.Context, q SourceOccurrence) (CaptureProgress, error) {
	p := CaptureProgress{SettledThrough: -1}
	var session string
	e := s.conn.QueryRowContext(ctx, "SELECT session,version,settled,reader,reader_version,ruleset,first,last_exclusive FROM capture_progress WHERE source=?", q.Source).Scan(&session, &p.Version, &p.SettledThrough, &p.Reader.Reader, &p.Reader.ReaderVersion, &p.RulesetFingerprint, &p.Range.First, &p.Range.LastExclusive)
	if e == sql.ErrNoRows {
		return p, nil
	}
	if e != nil {
		return p, failure("storage_error")
	}
	if session != q.SessionKey || p.Version <= 0 || !readerValid(p.Reader) || !record.IsHex64(p.RulesetFingerprint) || p.Range.First != 0 || p.Range.LastExclusive <= 0 || p.SettledThrough != p.Range.LastExclusive-1 {
		return p, failure("corrupt_database")
	}
	rows, e := s.conn.QueryContext(ctx, "SELECT c.record_id,r.seq FROM capture_source c JOIN record r ON r.id=c.record_id WHERE c.source=? ORDER BY c.position", q.Source)
	if e != nil {
		return p, failure("storage_error")
	}
	for rows.Next() {
		var r RecordRef
		if rows.Scan(&r.ID, &r.Sequence) != nil {
			rows.Close()
			return p, failure("storage_error")
		}
		p.LastSourceRecords = append(p.LastSourceRecords, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return p, failure("storage_error")
	}
	rows, e = s.conn.QueryContext(ctx, "SELECT page,record_id FROM capture_page WHERE source=? ORDER BY page", q.Source)
	if e != nil {
		return p, failure("storage_error")
	}
	for rows.Next() {
		var r PageRef
		if rows.Scan(&r.Page, &r.ID) != nil {
			rows.Close()
			return p, failure("storage_error")
		}
		p.SessionPages = append(p.SessionPages, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(p.LastSourceRecords) == 0 || len(p.LastSourceRecords) > 64 || len(p.SessionPages) == 0 || len(p.SessionPages) > 16 {
		return p, failure("corrupt_database")
	}
	return p, nil
}
func (s *Store) Capture(ctx context.Context, q CaptureRequest, producer func(*CaptureTxn) (CommitPlan, error)) (CaptureReceipt, error) {
	return s.capture(ctx, q, producer, nil)
}

func (s *Store) capture(ctx context.Context, q CaptureRequest, producer func(*CaptureTxn) (CommitPlan, error), signal *spoolAdmission) (CaptureReceipt, error) {
	if !validOccurrence(s.opts, q.Occurrence) || q.ExpectedVersion < 0 || !record.IsKeyID(q.AuthorKeyID) || !readerValid(q.Reader) || !record.IsHex64(q.RulesetFingerprint) || len(q.EventIDs) == 0 || len(q.EventIDs) > 4096 || q.Range.First != 0 || q.Range.LastExclusive <= 0 || producer == nil {
		return CaptureReceipt{}, failure("invalid_request")
	}
	seen := map[string]bool{}
	for _, id := range q.EventIDs {
		if !record.IsEventID(id) || seen[id] {
			return CaptureReceipt{}, failure("invalid_request")
		}
		seen[id] = true
	}
	// Native payload, reader and range do not choose transition identity.
	q.EventIDs = append([]string(nil), q.EventIDs...)
	q.Occurrence.EventIDs = append([]string(nil), q.Occurrence.EventIDs...)
	transition := record.H("capture-transition", s.opts.PinnedGenesisID, s.opts.LocalMachineID, q.Occurrence.Source, strconv.FormatInt(q.ExpectedVersion, 10))
	var out CaptureReceipt
	finish := func() error {
		if signal == nil {
			return nil
		}
		return s.persistSpool(ctx, *signal, out)
	}
	err := s.writeMode(ctx, true, func() error {
		if e := s.checkInstance(ctx); e != nil {
			return e
		}
		var spoolPrior CaptureReceipt
		var spoolFound bool
		if signal != nil {
			var err error
			spoolPrior, spoolFound, err = s.spoolReceipt(ctx, *signal)
			if err != nil {
				return err
			}
		}
		d, e := s.load(ctx)
		if e != nil {
			if _, settled := e.(*postCommitRefusal); settled {
				return e
			}
			s.poisoned = true
			return failure("outcome_unknown")
		}
		if spoolFound {
			if spoolPrior.Status == "committed" {
				spoolPrior.Status = "prior_transition_committed"
			}
			spoolPrior.CurrentAvailability = currentAvailability(d, spoolPrior.ActualRecordRefs)
			out = spoolPrior
			return nil
		}
		receipt, ok, e := s.captureReceipt(ctx, d, transition, q)
		if e != nil {
			s.poisoned = true
			return failure("outcome_unknown")
		}
		if ok {
			out = receipt
			return finish()
		}
		p, e := s.captureProgress(ctx, q.Occurrence)
		if e != nil {
			s.poisoned = true
			return failure("outcome_unknown")
		}
		if q.Range.LastExclusive != int64(len(q.EventIDs)) {
			return failure("invalid_request")
		}
		if p.Version != q.ExpectedVersion {
			return failure("stale_progress")
		}
		if p.Version == math.MaxInt64 || d.nextSeq > math.MaxInt64-maxCaptureNewRecords || d.generation > math.MaxInt64-maxCaptureNewRecords {
			return failure("ordinal_limit")
		}
		if g := suppression(d, q.Occurrence); g.Suppressed {
			if g.OwnerBlocked {
				return ownerBlocked()
			}
			return failure("suppressed")
		}
		k := d.kr.State().KeyFor(q.AuthorKeyID, record.RoleDevice, "")
		if k == nil || k.Status != sig.KeyActive || k.Genesis != s.opts.PinnedGenesisID || k.MachineID != s.opts.LocalMachineID {
			return failure("unauthorized_capture")
		}
		rs, err := localpolicy.Ruleset()
		if err != nil {
			return failure("policy_unavailable")
		}
		if d.tenant != nil && (!d.tenant.sealAllowed("", rs.Epoch) || q.PolicyID != d.tenant.chain.HighestID) || d.tenant == nil && q.PolicyID != "" {
			return failure("policy_violation")
		}
		t, e := s.makeCaptureTxn(ctx, d, q, p)
		if e != nil {
			// Complete producer history has its own broader copy set. A
			// pre-callback work refusal is known and has changed no SQL state.
			if _, limited := e.(*projectionLimit); limited {
				return failure("lineage_evaluation_required")
			}
			if Code(e) == "storage_error" || Code(e) == "corrupt_database" {
				s.poisoned = true
				return failure("outcome_unknown")
			}
			return e
		}
		if d.tenant != nil {
			t.context.PolicyID = d.tenant.chain.HighestID
		}
		var plan CommitPlan
		func() { defer t.valid.Store(false); plan, e = producer(t) }()
		if e != nil {
			// Callback errors carry no storage durability authority and never
			// choose public diagnostics, even when they resemble store errors.
			return failure("producer_refused")
		}
		refs, changed, e := s.admitCapturePlan(ctx, d, q, p, t, plan)
		if e != nil {
			return e
		}
		if !changed {
			out = CaptureReceipt{Status: "no_change", ActualRecordRefs: refs, CurrentAvailability: currentAvailability(d, refs), ResultingProgress: p}
			return finish()
		}
		next := CaptureProgress{Version: p.Version + 1, SettledThrough: plan.Next.SettledThrough, Reader: plan.Next.Reader, RulesetFingerprint: plan.Next.RulesetFingerprint, Range: plan.Next.Range, SessionPages: append([]PageRef(nil), plan.Next.SessionPageIDs...)}
		for _, id := range plan.Next.LastSourceRecordIDs {
			x := d.byID[id]
			next.LastSourceRecords = append(next.LastSourceRecords, RecordRef{id, x.seq})
		}
		if e = s.persistCapture(ctx, q, transition, next, refs); e != nil {
			return e
		}
		out = CaptureReceipt{Status: "committed", ActualRecordRefs: refs, CurrentAvailability: currentAvailability(d, refs), ResultingProgress: next, TransitionID: transition}
		return finish()
	})
	if err != nil {
		return CaptureReceipt{}, err
	}
	return detached(out), nil
}
func currentAvailability(d *databaseState, refs []RecordRef) map[string]string {
	out := map[string]string{}
	for _, r := range refs {
		if d.blocked {
			out[r.ID] = "owner_blocked"
		} else {
			out[r.ID] = availability(d.byID[r.ID])
		}
	}
	return out
}
func sameProgress(p CaptureProgress, n CaptureNext) bool {
	if p.SettledThrough != n.SettledThrough || p.Reader != n.Reader || p.RulesetFingerprint != n.RulesetFingerprint || p.Range != n.Range || len(p.LastSourceRecords) != len(n.LastSourceRecordIDs) || len(p.SessionPages) != len(n.SessionPageIDs) {
		return false
	}
	for i, r := range p.LastSourceRecords {
		if r.ID != n.LastSourceRecordIDs[i] {
			return false
		}
	}
	for i, r := range p.SessionPages {
		if r != n.SessionPageIDs[i] {
			return false
		}
	}
	return true
}
func (s *Store) admitCapturePlan(ctx context.Context, d *databaseState, q CaptureRequest, p CaptureProgress, t *CaptureTxn, plan CommitPlan) ([]RecordRef, bool, error) {
	n := plan.Next
	if n.Reader != q.Reader || n.RulesetFingerprint != q.RulesetFingerprint || n.Range != q.Range || n.SettledThrough != n.Range.LastExclusive-1 || len(n.LastSourceRecordIDs) == 0 || len(n.LastSourceRecordIDs) > 64 || len(n.SessionPageIDs) == 0 || len(n.SessionPageIDs) > 16 || len(plan.NewRecords) > maxCaptureNewRecords || len(plan.ReuseRecordIDs) > maxCaptureReuseRecords || len(plan.NewRecords)+len(plan.ReuseRecordIDs) > maxCaptureRecordRefs {
		return nil, false, failure("invalid_plan")
	}
	used := map[string]bool{}
	var refs []RecordRef
	for _, id := range plan.ReuseRecordIDs {
		if !record.IsHex64(id) || used[id] {
			return nil, false, failure("invalid_plan")
		}
		x := d.byID[id]
		// Retained identity/namespace is structural. Missing bodies, current signer
		// revocation and ancestry holds are availability, not new producer authority.
		if x != nil && (x.owner != q.Occurrence.Owner || !captureBound(x.rec, q, s.opts, false)) {
			return nil, false, failure("invalid_plan")
		}
		used[id] = true
		ref := RecordRef{ID: id}
		if x != nil {
			ref.Sequence = x.seq
		}
		refs = append(refs, ref)
	}
	// Parse the whole batch before changing even the in-memory admission projection.
	var parsed []*record.Record
	var signatures [][]record.Signature
	size := 0
	for _, in := range plan.NewRecords {
		size += len(in.HeaderJCS) + len(in.BodyJCS)
		if size > 16<<20 {
			return nil, false, failure("plan_limit")
		}
		r, sg, e := parse(in)
		if e != nil {
			return nil, false, e
		}
		if used[r.ID] || !captureBound(r, q, s.opts, true) || len(sg) != 1 || sg[0].KeyID != q.AuthorKeyID {
			return nil, false, failure("invalid_plan")
		}
		used[r.ID] = true
		parsed = append(parsed, r)
		signatures = append(signatures, sg)
	}
	// Verify the entire batch before interpreting any candidate identity or
	// body-availability state. A valid existing header can carry unknown body
	// facts; wrong New-vs-Reuse spelling must not erase that trusted proof.
	for i, r := range parsed {
		if e := s.verifyCandidate(d, r, signatures[i], d.nextSeq); e != nil {
			return nil, false, e
		}
	}
	duplicateExisting := false
	var added []*stored
	for i, r := range parsed {
		if old := d.byID[r.ID]; old != nil {
			duplicateExisting = true
			if old.rec.Body == nil && !old.bodySeen {
				// Transient only. An already erased body is never refilled or revived.
				// Existing SQL admission order, signatures and all prior provenance stay.
				old.rec = r
				old.events = nil
				old.recalls = nil
				old.orderKnown = false
				old.firstSeq = 0
				old.lastSeq = 0
				material(old)
			}
			continue
		}

		x, e := s.prepareNew(d, r, signatures[i])
		if e != nil {
			return nil, false, e
		}
		added = append(added, x)
		refs = append(refs, RecordRef{x.rec.ID, x.seq})
	}
	if e := d.rebuild(s.opts); e != nil {
		return nil, false, s.refuseVerified(ctx, d, e)
	}
	// Trusted candidate proof is evaluated before state-based refusal can
	// discard a newly discovered link to a durably accepted erasure.
	if _, e := s.effectDelta(ctx, d); e != nil {
		return nil, false, s.refuseBulk(ctx, d, e)
	}
	refuse := func(err error) ([]RecordRef, bool, error) {
		if cause := lateErasureCause(d); cause != "" {
			return nil, false, s.commitPrivacyBarrier(ctx, cause, "late_erasure_discovery", "privacy_hold_required")
		}
		return nil, false, err
	}
	if duplicateExisting {
		return refuse(failure("invalid_plan"))
	}
	if n.SettledThrough < p.SettledThrough {
		return refuse(failure("invalid_plan"))
	}
	for _, id := range plan.ReuseRecordIDs {
		if !available(d.byID[id]) {
			return refuse(failure("unavailable_reuse"))
		}
	}
	if e := s.validateCaptureMembership(d, q, p, t, plan, used); e != nil {
		return refuse(e)
	}
	for _, x := range added {
		if !available(x) {
			return refuse(failure("unavailable_candidate"))
		}
	}
	if len(added) == 0 && sameProgress(p, n) {
		return refs, false, nil
	}
	// A no-mint repack/progress change still needs an atomic transition receipt.
	if e := s.persistPrepared(ctx, d, added); e != nil {
		return nil, false, e
	}
	sort.SliceStable(refs, func(i, j int) bool { return refs[i].Sequence < refs[j].Sequence })
	return refs, true, nil
}
func captureBound(r *record.Record, q CaptureRequest, o Options, newRecord bool) bool {
	h := r.Header
	if h.Type != record.KindChunk && h.Type != record.KindSession || h.Prov != record.ProvTranscript || h.Subj.SessionKey != q.Occurrence.SessionKey || h.Subj.Source != q.Occurrence.Source || h.Author.MachineID != o.LocalMachineID || h.Subj.TaskID != "" || h.Subj.RepoID != "" || h.Subj.Client == nil || h.Subj.Client.ID != q.Reader.Reader || h.Subj.Client.Surface != "cli" {
		return false
	}
	if newRecord && (h.Author.KeyID != q.AuthorKeyID || h.Red.Fingerprint != q.RulesetFingerprint) {
		return false
	}
	if b, ok := r.Body.(*record.SessionBody); ok {
		if b.Reader == nil || *b.Reader != q.Reader {
			return false
		}
		if newRecord && (b.End != "" || b.EndedAt != 0) {
			return false
		}
	}
	if newRecord {
		if b, ok := r.Body.(*record.ChunkBody); ok {
			for _, e := range b.Events {
				if e.Prov != string(record.ProvTranscript) || e.Kind == "assistant_final" || e.Seq < 0 || e.Seq >= q.Range.LastExclusive {
					return false
				}
			}
		}
	}
	return !newRecord || r.Body != nil
}
