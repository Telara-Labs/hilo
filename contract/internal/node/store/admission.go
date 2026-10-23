package store

import (
	"bytes"
	"context"
	"encoding/base64"

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
	if h.Pol != "" || h.Red.Profile != record.ProfileLocal || h.Prov == record.ProvGateway || h.Type == record.KindPolicy || h.Type == record.KindWithdrawal {
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
	var result AdmissionResult
	err = s.write(ctx, func() error {
		d, err := s.load(ctx)
		if err != nil {
			return err
		}
		if d.blocked && !r.Header.Type.IsControl() {
			return ownerBlocked()
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
		x := &stored{rec: r, sigs: signatures, owner: s.opts.PinnedGenesisID, seq: d.nextSeq, generation: d.generation + 1}
		st := d.kr.State()
		if r.Header.Type == record.KindKeyOp {
			body := r.Body.(*record.KeyOpBody)
			if body.Genesis != s.opts.PinnedGenesisID {
				return failure("unsupported_context")
			}
			op := &sig.KeyOp{Rec: r, Body: body, Sigs: signatures, AdmittedSeq: x.seq}
			checked := sig.VerifyKeyOp(d.kr, op)
			if checked.Err != nil || checked.Status == sig.OpInvalid || checked.Status == sig.OpIgnored || checked.Status == sig.OpHeldGenesis {
				return failure("invalid_record")
			}
		} else {
			res := sig.VerifyRecord(r, signatures, st, sig.Context{Route: record.RouteLocal})
			if res.Status != sig.StatusVerified || res.Owner != s.opts.PinnedGenesisID || r.Header.Author.MachineID != s.opts.LocalMachineID {
				return failure("unauthorized_record")
			}
			if r.Header.Type == record.KindErasure || r.Header.Type == record.KindRetraction {
				if res.Key == nil || res.Key.Status != sig.KeyActive {
					return failure("unauthorized_control")
				}
			}
		}
		if b, ok := r.Body.(*record.ErasureBody); ok {
			if len(b.Selectors.Tasks)+len(b.Selectors.Sessions)+len(b.Selectors.LIDs)+len(b.Selectors.Sources) > 0 {
				return failure("bulk_confirmation_required")
			}
		}
		material(x)
		d.records = append(d.records, x)
		d.byID[r.ID] = x
		if err = d.rebuild(s.opts); err != nil {
			return err
		}
		// All candidate closure and bulk accounting happen before any candidate SQL writes.
		effects, err := s.effectDelta(ctx, d)
		if err != nil {
			return s.refuseBulk(ctx, d, err)
		}
		if err = s.insertRecord(ctx, x); err != nil {
			return err
		}
		d.nextSeq++
		d.generation++
		if _, err = s.conn.ExecContext(ctx, "UPDATE meta SET next_seq=?,generation=?,authority_epoch=authority_epoch+? WHERE singleton=1", d.nextSeq, d.generation, boolInt(r.Header.Type == record.KindKeyOp)); err != nil {
			return failure("storage_error")
		}
		for _, p := range effects {
			if _, err = s.conn.ExecContext(ctx, "INSERT INTO erasure_effect(control,target,author) VALUES(?,?,?)", p[0], p[1], p[2]); err != nil {
				return failure("storage_error")
			}
		}
		if err = s.persistState(ctx, d); err != nil {
			return err
		}
		result = AdmissionResult{ID: r.ID, Sequence: x.seq, Generation: x.generation, State: x.state}
		return nil
	})
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
	for _, e := range x.events {
		if _, err = s.conn.ExecContext(ctx, "INSERT OR IGNORE INTO item_event VALUES(?,?)", r.ID, e); err != nil {
			return failure("storage_error")
		}
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
	for id, causes := range d.eval.Causes {
		if d.byID[id] == nil || d.byID[id].rec.Header.Type.IsControl() {
			continue
		}
		for _, cause := range causes {
			if cause.Kind != invalidate.Erased || known[[2]string{cause.Cause, id}] {
				continue
			}
			control := d.byID[cause.Cause]
			if control == nil {
				return nil, failure("corrupt_database")
			}
			owner := control.owner

			count[owner]++
			known[[2]string{cause.Cause, id}] = true
			delta = append(delta, [3]string{cause.Cause, id, owner})
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
	res := sig.VerifyRecord(r, x.sigs, d.kr.State(), sig.Context{Route: record.RouteLocal, AdmittedSeq: x.seq})
	if res.Status != sig.StatusVerified || res.Owner != x.owner || r.Header.Author.MachineID != s.opts.LocalMachineID {
		return AdmissionResult{}, failure("unauthorized_record")
	}
	x.rec = r
	x.events = nil
	x.recalls = nil
	material(x)
	x.generation = d.generation + 1
	if err := d.rebuild(s.opts); err != nil {
		return AdmissionResult{}, err
	}
	delta, err := s.effectDelta(ctx, d)
	if err != nil {
		return AdmissionResult{}, s.refuseBulk(ctx, d, err)
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
