package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/Telara-Labs/telara-memory/contract/internal/node/disclosuretext"
	"github.com/Telara-Labs/telara-memory/contract/internal/node/localpolicy"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
)

// Pools are prepared outside the SQLite writer, with bounded slots/retries.
type disclosureEntropy struct {
	ids           map[string][][]string
	slots         map[string]int
	calls, nonces []string
	secret        []byte
}

func newDisclosureEntropy() (p *disclosureEntropy, err error) {
	p = &disclosureEntropy{ids: map[string][][]string{}, slots: map[string]int{}}
	defer func() {
		if err != nil {
			p.clear()
		}
	}()
	for _, kind := range []string{"engine", "credential", "connection", "scope", "task", "attempt", "cursor", "selection", "snapshot", "exposure"} {
		n := 2
		if kind == "exposure" {
			n = 64
		}
		for i := 0; i < n; i++ {
			var slot []string
			for j := 0; j < 8; j++ {
				var b [16]byte
				if _, e := rand.Read(b[:]); e != nil {
					return p, failure("entropy_unavailable")
				}
				b[6] = (b[6] & 15) | 64
				b[8] = (b[8] & 63) | 128
				s := hex.EncodeToString(b[:])
				slot = append(slot, fmt.Sprintf("%s-%s-%s-%s-%s", s[:8], s[8:12], s[12:16], s[16:20], s[20:]))
				clear(b[:])
			}
			p.ids[kind] = append(p.ids[kind], slot)
		}
	}
	for i := 0; i < 8; i++ {
		var b [10]byte
		if _, e := rand.Read(b[:]); e != nil {
			return p, failure("entropy_unavailable")
		}
		p.nonces = append(p.nonces, hex.EncodeToString(b[:]))
		clear(b[:])
		ref, e := record.NewCallRef(rand.Reader)
		if e != nil {
			return p, failure("entropy_unavailable")
		}
		p.calls = append(p.calls, ref)
	}
	p.secret = make([]byte, 32)
	if _, e := rand.Read(p.secret); e != nil {
		return p, failure("entropy_unavailable")
	}
	return p, nil
}
func (p *disclosureEntropy) clear() {
	if p == nil {
		return
	}
	clear(p.secret)
	p.secret = nil
	clear(p.ids)
	clear(p.calls)
	clear(p.nonces)
}
func (p *disclosureEntropy) uuid(ctx context.Context, s *Store, kind, table, column string) (string, error) {
	n := p.slots[kind]
	if n >= len(p.ids[kind]) {
		return "", failure("entropy_collision")
	}
	p.slots[kind]++
	for _, id := range p.ids[kind][n] {
		if table == "" {
			return id, nil
		}
		var present int
		if s.conn.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+table+" WHERE "+column+"=?)", id).Scan(&present) != nil {
			return "", failure("storage_error")
		}
		if present == 0 {
			return id, nil
		}
	}
	return "", failure("entropy_collision")
}
func (s *Store) loadAuthority(ctx context.Context) (*databaseState, error) {
	d := &databaseState{byID: map[string]*stored{}, kr: sig.NewKeyring(s.opts.PinnedGenesisID)}
	if s.conn.QueryRowContext(ctx, "SELECT next_seq,generation,authority_epoch FROM meta WHERE singleton=1").Scan(&d.nextSeq, &d.generation, &d.authorityEpoch) != nil || d.nextSeq <= 0 || d.generation < 0 || d.authorityEpoch < 0 {
		return nil, failure("corrupt_database")
	}
	var count int
	var size sql.NullInt64
	if s.conn.QueryRowContext(ctx, "SELECT count(*),sum(length(r.header)+length(r.sigs)+coalesce(length(b.body),0)) FROM record r LEFT JOIN record_body b ON b.id=r.id WHERE json_extract(CAST(r.header AS TEXT),'$.type')='key_op'").Scan(&count, &size) != nil {
		return nil, failure("storage_error")
	}
	if int64(count) != d.authorityEpoch {
		return nil, failure("corrupt_database")
	}
	if count > 8192 || size.Int64 > 64<<20 {
		return nil, failure("authority_evaluation_required")
	}
	rows, e := s.conn.QueryContext(ctx, "SELECT r.id,r.header,r.sigs,r.owner,r.seq,r.generation,r.state,r.sig_status,b.body FROM record r LEFT JOIN record_body b ON b.id=r.id WHERE json_extract(CAST(r.header AS TEXT),'$.type')='key_op' ORDER BY r.seq")
	if e != nil {
		return nil, failure("storage_error")
	}
	defer rows.Close()
	for rows.Next() {
		var id, owner string
		var h, b, sg []byte
		var status string
		x := &stored{persisted: true, bodySeen: true}
		if rows.Scan(&id, &h, &sg, &owner, &x.seq, &x.generation, &x.state, &status, &b) != nil {
			return nil, failure("storage_error")
		}
		if len(b) == 0 {
			return nil, failure("authority_evaluation_required")
		}
		r, sigs, e := parse(SignedRecord{HeaderJCS: h, BodyJCS: b, Sigs: decodeSignatures(sg), AdvisoryID: id})
		if e != nil || r.Header.Type != record.KindKeyOp || owner != s.opts.PinnedGenesisID || x.seq <= 0 || x.seq >= d.nextSeq {
			return nil, failure("corrupt_database")
		}
		x.sigStatus = sig.SigStatus(status)
		x.rec = r
		x.sigs = sigs
		x.owner = owner
		op := &sig.KeyOp{Rec: r, Body: r.Body.(*record.KeyOpBody), Sigs: sigs, AdmittedSeq: x.seq}
		if d.kr.Add(op) != nil {
			return nil, failure("corrupt_database")
		}
		d.records = append(d.records, x)
		d.byID[id] = x
	}
	if rows.Err() != nil {
		return nil, failure("storage_error")
	}
	st := d.kr.State()
	for _, x := range d.records {
		switch st.Status[x.rec.ID] {
		case sig.OpInvalid:
			return nil, failure("corrupt_database")
		case sig.OpHeldParents, sig.OpHeldGenesis:
			return nil, failure("authority_evaluation_required")
		}
		expected := sig.StatusUnknownSigner
		if st.Status[x.rec.ID] == sig.OpAuthorized {
			expected = sig.StatusVerified
		}
		if x.sigStatus != expected {
			return nil, failure("corrupt_database")
		}
	}
	return d, nil
}
func decodeSignatures(b []byte) []record.Signature {
	var s []record.Signature
	if json.Unmarshal(b, &s) != nil {
		return nil
	}
	return s
}
func (e *DisclosureEngine) checkAuthority(ctx context.Context) error {
	if e.closed || !e.authority.valid {
		return failure("unauthorized")
	}
	if err := e.store.checkInstance(ctx); err != nil {
		return err
	}
	if e.instance != e.store.instanceID {
		return failure("outcome_unknown")
	}
	var held int
	if e.store.conn.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM privacy_barrier)+(SELECT count(*) FROM projection_hold)").Scan(&held) != nil {
		return failure("storage_error")
	}
	if held > 0 {
		return failure("owner_blocked")
	}
	d, err := e.store.loadAuthority(ctx)
	if err != nil {
		return err
	}
	k := d.kr.State().KeyFor(e.authority.keyID, record.RoleDevice, "")
	if k == nil || k.Status != sig.KeyActive || k.MachineID != e.config.MachineID {
		return failure("unauthorized")
	}
	return nil
}
func NewDisclosureEngine(ctx context.Context, st *Store, material PreloadedDisclosureAuthority, cfg DisclosureConfig) (*DisclosureEngine, error) {
	defer material.Clear()
	if st == nil || !material.valid || cfg.OwnerGenesis != st.opts.PinnedGenesisID || cfg.MachineID != st.opts.LocalMachineID {
		return nil, failure("invalid_config")
	}
	if cfg.MaxReplyBytes == 0 {
		cfg.MaxReplyBytes = 65536
	}
	if cfg.MaxReplyBytes < 2048 || cfg.MaxReplyBytes > 262144 {
		return nil, failure("invalid_config")
	}
	if err := disclosuretext.Capability(); err != nil {
		return nil, failure(disclosuretext.Code(err))
	}
	rules, err := localpolicy.Ruleset()
	if err != nil {
		return nil, failure("ruleset_unavailable")
	}
	pool, err := newDisclosureEntropy()
	if err != nil {
		return nil, err
	}
	defer pool.clear()
	e := &DisclosureEngine{store: st, config: cfg, authority: material, closedClients: map[string]bool{}, deadlines: map[string]time.Time{}, ruleset: rules}
	err = st.writeMode(ctx, true, func() error {
		e.instance = st.instanceID
		var err error
		e.id, err = pool.uuid(ctx, st, "engine", "", "")
		if err != nil {
			return err
		}
		return e.checkAuthority(ctx)
	})
	if err != nil {
		e.authority.Clear()
		return nil, err
	}
	return e, nil
}
func (s *Store) guarded(ctx context.Context) (bool, error) {
	var n int
	if s.conn.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM privacy_barrier)+(SELECT count(*) FROM projection_hold)").Scan(&n) != nil {
		return false, failure("storage_error")
	}
	return n > 0, nil
}
func (s *Store) appendGuardedKeyOp(ctx context.Context, r *record.Record, signatures []record.Signature) (AdmissionResult, error) {
	d, err := s.loadAuthority(ctx)
	if err != nil {
		return AdmissionResult{}, err
	}
	if old := d.byID[r.ID]; old != nil {
		if !sameSignatures(old.sigs, signatures) {
			return AdmissionResult{}, failure("invalid_record")
		}
		return AdmissionResult{ID: r.ID, Sequence: old.seq, Generation: old.generation, State: old.state, Duplicate: true}, nil
	}
	if len(d.records) >= 8192 || d.nextSeq == math.MaxInt64 || d.generation == math.MaxInt64 || d.authorityEpoch == math.MaxInt64 {
		return AdmissionResult{}, failure("authority_evaluation_required")
	}
	if err = s.verifyCandidate(d, r, signatures, d.nextSeq); err != nil {
		return AdmissionResult{}, err
	}
	op := &sig.KeyOp{Rec: r, Body: r.Body.(*record.KeyOpBody), Sigs: signatures, AdmittedSeq: d.nextSeq}
	if d.kr.Add(op) != nil {
		return AdmissionResult{}, failure("invalid_record")
	}
	st := d.kr.State()
	if st.Status[r.ID] != sig.OpAuthorized {
		return AdmissionResult{}, failure("authority_evaluation_required")
	}
	for _, old := range d.records {
		status := sig.StatusUnknownSigner
		if st.Status[old.rec.ID] == sig.OpAuthorized {
			status = sig.StatusVerified
		}
		if _, err := s.conn.ExecContext(ctx, "UPDATE record SET sig_status=?,state='authority-held' WHERE id=?", string(status), old.rec.ID); err != nil {
			return AdmissionResult{}, failure("storage_error")
		}
	}
	x := &stored{rec: r, sigs: signatures, owner: s.opts.PinnedGenesisID, seq: d.nextSeq, generation: d.generation + 1, state: "authority-held", sigStatus: sig.StatusVerified}
	material(x)
	if err = s.insertRecord(ctx, x); err != nil {
		return AdmissionResult{}, err
	}
	if _, err = s.conn.ExecContext(ctx, "UPDATE meta SET next_seq=?,generation=?,authority_epoch=? WHERE singleton=1", d.nextSeq+1, d.generation+1, d.authorityEpoch+1); err != nil {
		return AdmissionResult{}, failure("storage_error")
	}
	for _, q := range []string{"DELETE FROM projection_job", "DELETE FROM render_body"} {
		if _, err = s.conn.ExecContext(ctx, q); err != nil {
			return AdmissionResult{}, failure("storage_error")
		}
	}
	return AdmissionResult{ID: r.ID, Sequence: x.seq, Generation: x.generation, State: x.state}, nil
}
func sameSignatures(a, b []record.Signature) bool {
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(aa) == string(bb)
}
