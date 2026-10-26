package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"math"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/invalidate"
	"github.com/Telara-Labs/telara-memory/contract/jcs"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

func parse(in SignedRecord) (*record.Record, []record.Signature, error) {
	if len(in.HeaderJCS) > record.MaxHeaderBytes || len(in.BodyJCS) > record.MaxBodyBytes || len(in.Sigs) == 0 || len(in.Sigs) > 2 {
		return nil, nil, failure("invalid_record")
	}
	for _, sg := range in.Sigs {
		if !record.IsKeyID(sg.KeyID) || sg.Alg != sig.AlgEd25519 || sg.Ctx != sig.CtxRecord || len(sg.Value) != 86 {
			return nil, nil, failure("invalid_record")
		}
		b, e := base64.RawURLEncoding.Strict().DecodeString(sg.Value)
		if e != nil || len(b) != 64 || base64.RawURLEncoding.EncodeToString(b) != sg.Value {
			return nil, nil, failure("invalid_record")
		}
	}

	r, err := record.Parse(append([]byte(nil), in.HeaderJCS...), append([]byte(nil), in.BodyJCS...), in.AdvisoryID)
	if err != nil {
		return nil, nil, failure("invalid_record")
	}
	h := r.Header
	if h.Red.Profile != record.ProfileLocal || h.Prov == record.ProvGateway || h.Type == record.KindWithdrawal {
		return nil, nil, failure("unsupported_context")
	}
	if h.Type.IsControl() {
		if r.Body == nil {
			return nil, nil, failure("invalid_record")
		}
		b, err := jcs.MarshalRecord(r.Body)
		if err != nil || !bytes.Equal(b, r.BodyJCS) {
			return nil, nil, failure("non_minimal_control")
		}
	}
	if b, ok := r.Body.(*record.KeyOpBody); ok {
		if b.Subject.Role != record.RoleDevice || b.Op == record.OpTenantKey || b.Op == record.OpTenantKeyRotate {
			return nil, nil, failure("unsupported_context")
		}
	}
	return r, append([]record.Signature(nil), in.Sigs...), nil
}
func (s *Store) Append(ctx context.Context, in SignedRecord) (AdmissionResult, error) {
	r, signatures, err := parse(in)
	if err != nil {
		return AdmissionResult{}, err
	}
	if r.Header.Type == record.KindPolicy {
		return s.OfferTenantPolicy(ctx, in)
	}
	var result AdmissionResult
	err = s.write(ctx, func() error {
		var e error
		result, e = s.appendLocked(ctx, r, signatures)
		return e
	})
	return result, err
}

// appendLocked is the admission body. The caller holds the store writer.
func (s *Store) appendLocked(ctx context.Context, r *record.Record, signatures []record.Signature) (AdmissionResult, error) {
	var result AdmissionResult
	err := func() error {
		if held, e := s.guarded(ctx); e != nil {
			return e
		} else if held {
			if r.Header.Type == record.KindKeyOp {
				var e error
				result, e = s.appendGuardedKeyOp(ctx, r, signatures)
				return e
			}
			var projections int
			if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_hold").Scan(&projections) != nil {
				return failure("storage_error")
			}
			if projections > 0 {
				return &Error{Code: "lineage_evaluation_required", OwnerBlocked: true}
			}
			if !r.Header.Type.IsControl() {
				return ownerBlocked()
			}
		}
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if old := d.byID[r.ID]; old != nil {
			a, _ := jcs.MarshalRecord(old.sigs)
			b, _ := jcs.MarshalRecord(signatures)
			if !bytes.Equal(a, b) || !bytes.Equal(old.rec.HeaderJCS, r.HeaderJCS) {
				return failure("invalid_record")
			}
			// A repeated delivery cannot refill an erased body or obtain a new admission cutoff.
			if old.rec.Body == nil && !old.bodySeen && r.Body != nil && !r.Header.Type.IsControl() {
				var enrichErr error
				result, enrichErr = s.enrichBody(ctx, d, old, r)
				return enrichErr
			}
			result = AdmissionResult{ID: r.ID, Sequence: old.seq, Generation: old.generation, State: old.state, Duplicate: true}
			return nil
		}
		x, err := s.prepareNew(d, r, signatures)
		if err != nil {
			return err
		}
		// Pending coverage admits restrictive verified late-body facts only.
		// A new ordinary live/held record cannot bypass owner unavailability.
		if d.blocked && !r.Header.Type.IsControl() && x.state != "invalidated" {
			return ownerBlocked()
		}
		if err = s.persistPrepared(ctx, d, []*stored{x}); err != nil {
			return err
		}
		result = AdmissionResult{ID: r.ID, Sequence: x.seq, Generation: x.generation, State: x.state}
		return nil
	}()
	return result, err
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func (s *Store) ApplyControl(ctx context.Context, in SignedRecord) (EraseResult, error) {
	r, _, err := parse(in)
	if err != nil {
		return EraseResult{}, err
	}
	if r.Header.Type != record.KindErasure && r.Header.Type != record.KindRetraction {
		return EraseResult{}, failure("unsupported_context")
	}
	a, err := s.Append(ctx, in)
	if err != nil {
		return EraseResult{}, err
	}
	return EraseResult{AdmissionResult: a, Physical: "pending"}, nil
}
func (s *Store) insertRecord(ctx context.Context, x *stored) error {
	r := x.rec
	signatures, err := jcs.MarshalRecord(x.sigs)
	if err != nil {
		return failure("invalid_record")
	}
	if _, err = s.conn.ExecContext(ctx, "INSERT INTO record VALUES(?,?,?,?,?,?,?,?)", r.ID, r.HeaderJCS, signatures, x.owner, x.seq, x.generation, string(x.sigStatus), x.state); err != nil {
		return failure("storage_error")
	}
	if r.Header.Type == record.KindKeyOp {
		// A staged key operation admitted durably no longer needs its overlay.
		if _, err = s.conn.ExecContext(ctx, "DELETE FROM key_restriction WHERE id=?", r.ID); err != nil {
			return failure("storage_error")
		}
	}
	if r.BodyJCS != nil && x.state != string(invalidate.Invalidated) {
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO record_body VALUES(?,?)", r.ID, r.BodyJCS); err != nil {
			return failure("storage_error")
		}
	}
	return s.insertMaterial(ctx, x)
}
func (s *Store) insertMaterial(ctx context.Context, x *stored) error {
	var err error
	r := x.rec

	if x.bodySeen {
		if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO body_seen VALUES(?)", r.ID); err != nil {
			return failure("storage_error")
		}
	}
	if _, err = s.conn.ExecContext(ctx, "INSERT INTO item_order VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET known=excluded.known,first_seq=excluded.first_seq,last_seq=excluded.last_seq", r.ID, boolInt(x.orderKnown), x.firstSeq, x.lastSeq); err != nil {
		return failure("storage_error")
	}

	for _, p := range x.deps {
		if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO dep VALUES(?,?)", r.ID, p); err != nil {
			return failure("storage_error")
		}
	}
	if err = s.persistEventMembership(ctx, x); err != nil {
		return err
	}
	for _, e := range x.recalls {
		if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO item_recall VALUES(?,?,?)", r.ID, e.Seq, e.ID); err != nil {
			return failure("storage_error")
		}
	}
	for _, p := range r.Header.Links.Supersedes {
		if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO supersession VALUES(?,?,?,?,?)", x.owner, string(r.Header.Type), r.Header.LID, r.ID, p); err != nil {
			return failure("storage_error")
		}
	}
	return nil
}

// Persist the exact membership and its completeness proof together, before any
// body purge. Rebuild may learn these facts for an EXISTING session when a late
// chunk arrives, so insertion of the new record alone is insufficient.
func (s *Store) persistEventMembership(ctx context.Context, x *stored) error {
	for _, e := range x.events {
		if _, err := s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO item_event VALUES(?,?)", x.rec.ID, e); err != nil {
			return failure("storage_error")
		}
	}
	if x.membershipComplete {
		if _, err := s.conn.ExecContext(ctx, "INSERT INTO event_membership VALUES(?,?) ON CONFLICT(id) DO UPDATE SET event_count=excluded.event_count", x.rec.ID, len(x.events)); err != nil {
			return failure("storage_error")
		}
	}
	return nil
}
func (s *Store) effectDelta(ctx context.Context, d *databaseState) ([][3]string, error) {
	known := map[[2]string]bool{}
	count := map[string]int{}
	rows, err := s.conn.QueryContext(ctx, "SELECT control,target,author FROM erasure_effect")
	if err != nil {
		return nil, failure("storage_error")
	}
	for rows.Next() {
		var c, t, a string
		if rows.Scan(&c, &t, &a) != nil {
			rows.Close()
			return nil, failure("storage_error")
		}
		known[[2]string{c, t}] = true
		count[a]++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, failure("storage_error")
	}
	var delta [][3]string
	pairs := map[string]map[string]bool{}
	for id, causes := range d.eval.Causes {
		for _, c := range causes {
			if c.Kind == invalidate.Erased {
				if pairs[id] == nil {
					pairs[id] = map[string]bool{}
				}
				pairs[id][c.Cause] = true
			}
		}
	}
	for id, tokens := range d.eval.HoldCauses {
		for _, token := range tokens {
			parts := strings.Split(token, "/")
			if len(parts) != 2 {
				return nil, failure("corrupt_database")
			}
			c := d.byID[parts[1]]
			if c == nil {
				return nil, failure("corrupt_database")
			}
			if c.rec.Header.Type == record.KindErasure {
				if pairs[id] == nil {
					pairs[id] = map[string]bool{}
				}
				pairs[id][c.rec.ID] = true
			}
		}
	}
	for id, controls := range pairs {
		if d.byID[id] == nil || d.byID[id].rec.Header.Type.IsControl() {
			continue
		}
		for cid := range controls {
			if known[[2]string{cid, id}] {
				continue
			}
			control := d.byID[cid]
			if control == nil || control.rec.Header.Type != record.KindErasure {
				return nil, failure("corrupt_database")
			}
			owner := control.owner
			count[owner]++
			known[[2]string{cid, id}] = true
			delta = append(delta, [3]string{cid, id, owner})
		}
	}

	over := false
	for _, n := range count {
		if n > 1000 {
			over = true
		}
	}
	if over {
		cause := ""
		for _, p := range delta {
			x := d.byID[p[1]]
			c := d.byID[p[0]]
			if x != nil && x.persisted && x.previousLive && c != nil && c.persisted {
				cause = p[0]
				break
			}
		}
		return nil, &bulkLimit{cause: cause}
	}
	return delta, nil
}

func (s *Store) enrichBody(ctx context.Context, d *databaseState, x *stored, r *record.Record) (AdmissionResult, error) {
	if d.generation == math.MaxInt64 {
		return AdmissionResult{}, failure("ordinal_limit")
	}
	if err := s.verifyCandidate(d, r, x.sigs, x.seq); err != nil {
		return AdmissionResult{}, err
	}
	res := sig.VerifyRecord(r, x.sigs, d.keyState(), sig.Context{Route: record.RouteLocal, AdmittedSeq: x.seq})
	if res.Status != sig.StatusVerified || res.Owner != x.owner || !s.authorMachineAllowed(r, res) {
		return AdmissionResult{}, failure("unauthorized_record")
	}
	x.rec = r
	x.events = nil
	x.recalls = nil
	material(x)
	x.generation = d.generation + 1
	if err := d.rebuild(s.opts); err != nil {
		return AdmissionResult{}, s.refuseVerified(ctx, d, err)
	}
	delta, err := s.effectDelta(ctx, d)
	if err != nil {
		return AdmissionResult{}, s.refuseBulk(ctx, d, err)
	}
	if err = d.prepareRelations(); err != nil {
		return AdmissionResult{}, s.refuseVerified(ctx, d, err)
	}
	if x.state != "invalidated" {
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO record_body VALUES(?,?)", r.ID, r.BodyJCS); err != nil {
			return AdmissionResult{}, failure("storage_error")
		}
	}
	if err = s.insertMaterial(ctx, x); err != nil {
		return AdmissionResult{}, err
	}
	d.generation++
	if _, err = s.conn.ExecContext(ctx, "UPDATE meta SET generation=? WHERE singleton=1", d.generation); err != nil {
		return AdmissionResult{}, failure("storage_error")
	}
	for _, p := range delta {
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO erasure_effect VALUES(?,?,?)", p[0], p[1], p[2]); err != nil {
			return AdmissionResult{}, failure("storage_error")
		}
	}
	if err = s.persistState(ctx, d); err != nil {
		return AdmissionResult{}, err
	}
	return AdmissionResult{ID: r.ID, Sequence: x.seq, Generation: x.generation, State: x.state, Duplicate: true}, nil
}

// prepareNew and persistPrepared are the single admission path for Append and
// trusted producer batches. All candidate state is checked before candidate SQL.
func (s *Store) prepareNew(d *databaseState, r *record.Record, signatures []record.Signature) (*stored, error) {
	if d.nextSeq == math.MaxInt64 || d.generation == math.MaxInt64 {
		return nil, failure("ordinal_limit")
	}
	if d.byID[r.ID] != nil {
		return nil, failure("duplicate_record")
	}
	x := &stored{rec: r, sigs: signatures, owner: s.opts.PinnedGenesisID, seq: d.nextSeq, generation: d.generation + 1}
	if err := s.verifyCandidate(d, r, signatures, x.seq); err != nil {
		return nil, err
	}

	if r.Header.Type == record.KindKeyOp {
		d.authorityEpoch++
	}
	material(x)
	d.records = append(d.records, x)
	d.byID[r.ID] = x
	d.nextSeq++
	d.generation++
	if err := d.rebuild(s.opts); err != nil {
		return nil, s.refuseVerified(d.ctx, d, err)
	}
	// While the owner is blocked, a key operation whose parents are absent is
	// refused without a write, as guarded admission refuses it; the caller keeps
	// it pending outside durable authority until its parents arrive. The
	// evaluation-only block and the barrier row are one owner block. A held
	// operation admitted earlier, before any block, stays retained but outside
	// authority, and the parent that completes it remains admissible.
	if r.Header.Type == record.KindKeyOp && d.blocked && d.kr.State().Status[r.ID] == sig.OpHeldParents {
		return nil, failure("authority_evaluation_required")
	}
	return x, nil
}
func (s *Store) persistPrepared(ctx context.Context, d *databaseState, added []*stored) error {
	if err := d.prepareRelations(); err != nil {
		return s.refuseVerified(ctx, d, err)
	}
	effects, err := s.effectDelta(ctx, d)
	if err != nil {
		return s.refuseBulk(ctx, d, err)
	}
	for _, x := range added {
		if err = s.insertRecord(ctx, x); err != nil {
			return err
		}
	}
	if _, err = s.conn.ExecContext(ctx, "UPDATE meta SET next_seq=?,generation=?,authority_epoch=? WHERE singleton=1", d.nextSeq, d.generation, d.authorityEpoch); err != nil {
		return failure("storage_error")
	}
	for _, p := range effects {
		if _, err = s.conn.ExecContext(ctx, "INSERT INTO erasure_effect(control,target,author) VALUES(?,?,?)", p[0], p[1], p[2]); err != nil {
			return failure("storage_error")
		}
	}
	return s.persistState(ctx, d)
}

// verifyCandidate is shared by ordinary admission and producer verification,
// including a full candidate whose identity is already retained in SQL.
func (s *Store) verifyCandidate(d *databaseState, r *record.Record, signatures []record.Signature, sequence int64) error {
	if err := d.tenant.validateBody(r); err != nil {
		return err
	}
	if r.Header.Type == record.KindCall && r.Body != nil && record.ValidateCommitmentDependencies(r, knownCallRoots(d, r)) != nil {
		return failure("commitment_dependencies")
	}
	st := d.keyState()
	if r.Header.Type == record.KindKeyOp {
		if d.authorityEpoch == math.MaxInt64 {
			return failure("ordinal_limit")
		}
		body := r.Body.(*record.KeyOpBody)
		if body.Genesis != s.opts.PinnedGenesisID {
			return failure("unsupported_context")
		}
		op := &sig.KeyOp{Rec: r, Body: body, Sigs: signatures, AdmittedSeq: sequence}
		checked := sig.VerifyKeyOp(d.kr, op)
		if checked.Err != nil || checked.Status == sig.OpInvalid || checked.Status == sig.OpIgnored || checked.Status == sig.OpHeldGenesis {
			return failure("invalid_record")
		}
	} else {
		if s.verifyView != nil && r.Header.Type == record.KindErasure {
			st = s.verifyView
		}
		res := d.verifyWithReceipt(r, signatures, st, 0, nil)
		if res.Status != sig.StatusVerified || res.Owner != s.opts.PinnedGenesisID || !s.authorMachineAllowed(r, res) {
			return failure("unauthorized_record")
		}
		if r.Header.Type == record.KindErasure || r.Header.Type == record.KindRetraction {
			if res.Key == nil || res.Key.Status != sig.KeyActive {
				return failure("unauthorized_control")
			}
		}
	}
	if b, ok := r.Body.(*record.ErasureBody); ok {
		// Task, session, LID, source and event selectors have unbounded
		// future effect, even with zero current matches. Inside a bundle
		// import each such control applies only after the receiving owner's
		// local confirmation of that exact control; the issuer checks above
		// and the cumulative effect bound still apply to a confirmed one.
		// Elsewhere task, session, LID and source selectors are never
		// admitted, and event selectors are confirmed by the local erase
		// command and hosted browser re-authentication on their own routes.
		sel := b.Selectors
		bulk := len(sel.Tasks)+len(sel.Sessions)+len(sel.LIDs)+len(sel.Sources) > 0
		if s.controlConfirm != nil {
			if (bulk || len(sel.Events) > 0) && !s.controlConfirm[r.ID] {
				return failure("bulk_confirmation_required")
			}
		} else if bulk {
			return failure("bulk_confirmation_required")
		}
	}

	return nil
}

// authorMachineAllowed admits only this device's stream, except inside a
// verified bundle import, which may carry another device of the same pinned
// genesis whose key binds the author machine.
func (s *Store) authorMachineAllowed(r *record.Record, res sig.Result) bool {
	if r.Header.Author.MachineID == s.opts.LocalMachineID {
		return true
	}
	return s.bundleImport && res.Key != nil && res.Key.Role == record.RoleDevice && res.Key.Genesis == s.opts.PinnedGenesisID && res.Key.MachineID == r.Header.Author.MachineID
}
