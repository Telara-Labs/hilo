package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/invalidate"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/view"
)

type stored struct {
	membershipComplete      bool
	persisted, previousLive bool
	bodySeen                bool
	orderKnown              bool
	firstSeq, lastSeq       int64
	priorState              string
	rec                     *record.Record
	sigs                    []record.Signature
	owner                   string
	seq, generation         int64
	deps, events            []string
	recalls                 []invalidate.Recall
	sigStatus               sig.SigStatus
	state                   string
}
type databaseState struct {
	tenant                              *tenantState
	policyTenants                       map[string]string
	policyLogout                        map[string]bool
	groups                              *metadataGroups
	relationsReady                      bool
	plannedFacts                        map[string]view.EventFacts
	store                               *Store
	ctx                                 context.Context
	taintWitnesses                      map[taintWitness]bool
	trust                               map[string]view.EffectiveTrust
	directEvidence                      map[string][]string
	trustDeps                           map[string][]string
	nonceLookups                        int
	blocked                             bool
	projectionBlocked                   bool
	attrs                               map[string]attributionFact
	exposures                           []*exposureFact
	semantic                            map[string]map[string]bool
	retainedHolds                       map[string]map[string]bool
	taint                               map[string]map[string]bool
	completeness                        map[fieldKey]completenessFact
	nonces                              map[string]bool
	fields                              map[string][]projectionField
	retained                            map[string][]invalidate.Tomb
	bans                                map[occurrence]map[string]bool
	records                             []*stored
	byID                                map[string]*stored
	kr                                  *sig.Keyring
	model                               *invalidate.Model
	eval                                *invalidate.Eval
	facts                               map[string]view.EventFacts
	generation, nextSeq, authorityEpoch int64
}

func (s *Store) load(ctx context.Context) (*databaseState, error) {
	var projectionHeld int
	if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM projection_hold").Scan(&projectionHeld) != nil {
		return nil, failure("storage_error")
	}
	held := projectionHeld > 0
	var err error
	if held {
		d, e := s.loadAuthority(ctx)
		if e != nil {
			return nil, e
		}
		d.blocked = true
		d.projectionBlocked = true
		d.eval = invalidate.NewModel().Evaluate()
		return d, nil
	}
	d := &databaseState{store: s, ctx: ctx, byID: map[string]*stored{}, facts: map[string]view.EventFacts{}}
	if s.conn.QueryRowContext(ctx, "SELECT generation,next_seq,authority_epoch FROM meta WHERE singleton=1").Scan(&d.generation, &d.nextSeq, &d.authorityEpoch) != nil {
		return nil, failure("storage_error")
	}
	if d.generation < 0 || d.nextSeq <= 0 || d.authorityEpoch < 0 {
		return nil, failure("corrupt_database")
	}
	var count int
	var bodySize int64
	if s.conn.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(r.header)+length(r.sigs)+coalesce(length(b.body),0)),0) FROM record r LEFT JOIN record_body b ON b.id=r.id").Scan(&count, &bodySize) != nil {
		return nil, failure("storage_error")
	}
	if count > 8192 || bodySize > 64<<20 {
		return nil, s.commitProjectionHold(ctx)
	}
	// Count authoritative relations before allocating complete in-memory sets.
	// An over-bound retained history becomes a durable typed projection hold;
	// it is never silently truncated or discarded to make a read succeed.
	var sessionCount int
	if s.conn.QueryRowContext(ctx, "SELECT count(DISTINCT json_extract(CAST(header AS TEXT),'$.subj.session_key')) FROM record WHERE json_extract(CAST(header AS TEXT),'$.subj.session_key') IS NOT NULL").Scan(&sessionCount) != nil {
		return nil, failure("storage_error")
	}
	if sessionCount > 128 {
		return nil, s.commitProjectionHold(ctx)
	}
	for _, table := range []string{"dep", "item_event", "item_recall", "tomb", "event_ban", "presence", "presence_parent", "presence_taint", "witness", "supersession"} {
		var rows int
		if s.conn.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&rows) != nil {
			return nil, failure("storage_error")
		}
		if rows > 65536 {
			return nil, s.commitProjectionHold(ctx)
		}
	}
	rows, err := s.conn.QueryContext(ctx, "SELECT r.id,r.header,r.sigs,r.owner,r.seq,r.generation,r.state,EXISTS(SELECT 1 FROM body_seen z WHERE z.id=r.id),b.body FROM record r LEFT JOIN record_body b ON b.id=r.id ORDER BY r.seq")
	if err != nil {
		return nil, failure("storage_error")
	}
	for rows.Next() {
		var id string
		var header, sigs, body []byte
		x := &stored{persisted: true}
		if rows.Scan(&id, &header, &sigs, &x.owner, &x.seq, &x.generation, &x.priorState, &x.bodySeen, &body) != nil {
			rows.Close()
			return nil, failure("storage_error")
		}
		x.rec, err = record.Parse(header, body, id)
		if err != nil || json.Unmarshal(sigs, &x.sigs) != nil {
			rows.Close()
			return nil, failure("corrupt_database")
		}
		d.records = append(d.records, x)
		d.byID[id] = x
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, failure("storage_error")
	}
	for _, spec := range []struct {
		query string
		apply func(*stored, string, int64)
	}{
		{"SELECT id,parent,0 FROM dep", func(x *stored, v string, _ int64) { x.deps = append(x.deps, v) }},
		{"SELECT id,event_id,0 FROM item_event", func(x *stored, v string, _ int64) { x.events = append(x.events, v) }},
		{"SELECT id,recalled,event_seq FROM item_recall", func(x *stored, v string, n int64) { x.recalls = append(x.recalls, invalidate.Recall{Seq: n, ID: v}) }},
	} {
		rows, err = s.conn.QueryContext(ctx, spec.query)
		if err != nil {
			return nil, failure("storage_error")
		}
		for rows.Next() {
			var id, v string
			var n int64
			if rows.Scan(&id, &v, &n) != nil || d.byID[id] == nil {
				rows.Close()
				return nil, failure("corrupt_database")
			}
			spec.apply(d.byID[id], v, n)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, failure("storage_error")
		}
	}
	if err = s.loadFences(ctx, d); err != nil {
		return nil, err
	}
	// Reconstruct every signed edge before a call key or copied body can be
	// used. Missing local indexes never turn declared ancestry into empty [].
	for _, x := range d.records {
		m := &stored{rec: x.rec}
		material(m)
		for _, id := range m.deps {
			if !containsID(x.deps, id) {
				x.deps = append(x.deps, id)
			}
		}
		for _, id := range m.events {
			if !containsID(x.events, id) {
				x.events = append(x.events, id)
			}
		}
		if x.rec.Header.Type == record.KindChunk || x.rec.Header.Type == record.KindSession {
			var count int
			err := s.conn.QueryRowContext(ctx, "SELECT event_count FROM event_membership WHERE id=?", x.rec.ID).Scan(&count)
			x.membershipComplete = err == nil && count == len(x.events)
			if err != nil && err != sql.ErrNoRows {
				return nil, failure("storage_error")
			}
		}
	}
	d.tenant, err = s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	if err = s.loadPolicyProvenance(ctx, d); err != nil {
		return nil, err
	}
	if err = s.loadFacts(ctx, d); err != nil {
		return nil, err
	}
	if err = s.loadDisclosureFacts(ctx, d); err != nil {
		if _, ok := err.(*projectionLimit); ok {
			return nil, s.commitProjectionHold(ctx)
		}
		return nil, err
	}
	if err = d.rebuild(s.opts); err != nil {
		if _, ok := err.(*projectionLimit); ok {
			return nil, s.commitProjectionHold(ctx)
		}
		return nil, err
	}
	for _, x := range d.records {
		x.previousLive = (x.state == "live" || x.state == "privacy-hold") && x.sigStatus == sig.StatusVerified && x.rec.Body != nil
	}
	return d, nil
}
func (d *databaseState) rebuild(o Options) error {
	d.relationsReady = false
	d.groups = nil
	if c, err := d.reductions(); err != nil {
		return err
	} else {
		n := len(d.records) * 64
		for _, x := range d.records {
			n += len(x.rec.Header.Links.Supersedes) * 8
		}
		if err = c.charge(n); err != nil {
			return err
		}
	}
	d.kr = sig.NewKeyring(o.PinnedGenesisID)
	sort.Slice(d.records, func(i, j int) bool { return d.records[i].seq < d.records[j].seq })
	for _, x := range d.records {
		if x.rec.Header.Type != record.KindKeyOp {
			continue
		}
		b, ok := x.rec.Body.(*record.KeyOpBody)
		if !ok {
			return failure("corrupt_database")
		}
		op := &sig.KeyOp{Rec: x.rec, Body: b, Sigs: x.sigs, AdmittedSeq: x.seq}
		if err := d.kr.Add(op); err != nil {
			return failure("corrupt_database")
		}
	}
	d.model = invalidate.NewModel()
	for _, x := range d.records {
		if b, ok := x.rec.Body.(*record.ChunkBody); ok {
			x.membershipComplete = true
			_ = b
		}
	}
	for _, x := range d.records {
		if b, ok := x.rec.Body.(*record.SessionBody); ok {
			x.membershipComplete = true
			for _, id := range b.Chunks {
				child := d.byID[id]
				if child == nil || child.rec.Header.Type != record.KindChunk || child.owner != x.owner || child.rec.Header.Subj.SessionKey != x.rec.Header.Subj.SessionKey || !child.membershipComplete {
					x.membershipComplete = false
					continue
				}
				for _, ev := range child.events {
					if !containsID(x.events, ev) {
						x.events = append(x.events, ev)
					}
				}
			}
		}
	}
	st := d.kr.State()
	for _, x := range d.records {
		h := x.rec.Header
		if h.Type == record.KindKeyOp {
			if st.Status[x.rec.ID] == sig.OpAuthorized {
				x.sigStatus = sig.StatusVerified
			} else {
				x.sigStatus = sig.StatusUnknownSigner
			}
		} else {
			x.sigStatus = sig.VerifyRecord(x.rec, x.sigs, st, sig.Context{Route: record.RouteLocal, AdmittedSeq: x.seq}).Status
		}
		it := invalidate.Item{BodyAvailable: x.rec.Body != nil, EventMembershipComplete: x.membershipComplete, ID: x.rec.ID, LID: h.LID, Kind: h.Type, Prov: h.Prov, Owner: x.owner, TaskID: h.Subj.TaskID, SessionKey: h.Subj.SessionKey, Source: h.Subj.Source, Deps: x.deps, Events: x.events, Recalls: x.recalls, Origin: h.Links.Origin, Route: record.RouteLocal, OriginMachine: h.Author.MachineID, Explicit: h.Prov == record.ProvMCPExplicit, SessionSeq: x.lastSeq}
		if a, ok := d.attrs[x.rec.ID]; ok {
			if a.owner != x.owner || a.machine != h.Author.MachineID {
				return failure("corrupt_database")
			}
			it.Scope = a.scope
			it.OriginMachine = a.machine
		}
		d.model.Admit(it)
	}
	// Accepted destructive controls remain permanent facts, independently of later key state.
	for _, x := range d.records {
		c := invalidate.Control{ID: x.rec.ID, Kind: x.rec.Header.Type, Owner: x.owner}
		switch b := x.rec.Body.(type) {
		case *record.ErasureBody:
			c.Erasure = b
		case *record.RetractionBody:
			c.Retraction = b
		default:
			continue
		}
		if d.model.Apply(c) != nil {
			return failure("corrupt_database")
		}
	}
	if err := d.semanticFacts(o); err != nil {
		return err
	}
	d.eval = d.model.Evaluate()
	if d.eval.OwnerPending[o.PinnedGenesisID] {
		d.blocked = true
	}
	if err := d.enforceCallDependencies(); err != nil {
		return err
	}
	if err := d.enforceFences(); err != nil {
		return err
	}
	for _, x := range d.records {
		x.state = string(d.eval.StatusOf(x.rec.ID))
		if x.sigStatus != sig.StatusVerified && x.state != string(invalidate.Invalidated) {
			x.state = "unverified"
		}
	}
	// Current admission eligibility also follows present copied dependencies.
	c, err := d.reductions()
	if err != nil {
		return err
	}
	recalls := map[string][]invalidate.Recall{}
	for _, source := range d.records {
		if sk := source.rec.Header.Subj.SessionKey; sk != "" {
			if err = c.charge(len(source.recalls)); err != nil {
				return err
			}
			recalls[sk] = append(recalls[sk], source.recalls...)
		}
	}
	changed := true
	for changed {
		if err = c.charge(len(d.records)); err != nil {
			return err
		}
		changed = false
		for _, x := range d.records {
			if x.state != "live" {
				continue
			}
			if err = c.charge(len(x.deps) + len(d.semantic[x.rec.ID]) + len(recalls[x.rec.Header.Subj.SessionKey]) + 1); err != nil {
				return err
			}
			deps := append([]string(nil), x.deps...)
			for parent := range d.semantic[x.rec.ID] {
				deps = append(deps, parent)
			}
			if origin := x.rec.Header.Links.Origin; origin != "" && d.byID[origin] != nil {
				deps = append(deps, origin)
			}
			// A recalled source is a semantic dependency for potentially downstream
			// output, even without a copied-content edge. Unknown ordering is conservative.
			for _, r := range recalls[x.rec.Header.Subj.SessionKey] {
				if !x.orderKnown || x.lastSeq > r.Seq {
					deps = append(deps, r.ID)
				}
			}

			for _, id := range deps {
				if p := d.byID[id]; p == nil || (p.state == "unverified" || p.state == "ancestry-pending" || p.state == "lineage-hold") {
					x.state = "ancestry-pending"
					changed = true
					break
				}
			}
		}
	}
	if d.blocked {
		for _, x := range d.records {
			if !x.rec.Header.Type.IsControl() && x.state != "invalidated" {
				x.state = "privacy-hold"
			}
		}
	}
	if err := d.classifyFields(); err != nil {
		return err
	}
	if err := d.projectObservedTaint(); err != nil {
		return err
	}
	return nil
}
func material(x *stored) {
	if x.rec.Body != nil {
		x.bodySeen = true
	}
	h := x.rec.Header
	x.deps = append([]string(nil), h.Links.DerivedFrom...)
	switch b := x.rec.Body.(type) {
	case *record.SessionBody:
		x.deps = append(x.deps, b.Chunks...)
	case *record.RollupBody:
		x.deps = append(x.deps, b.Covers...)
	case *record.ChunkBody:
		if len(b.Events) > 0 {
			x.orderKnown = true
			x.firstSeq = b.Events[0].Seq
			x.lastSeq = b.Events[0].Seq
		}
		for _, e := range b.Events {
			if e.Seq < x.firstSeq {
				x.firstSeq = e.Seq
			}
			if e.Seq > x.lastSeq {
				x.lastSeq = e.Seq
			}
			x.events = append(x.events, e.ID)
			for _, r := range e.Recalled {
				if at := strings.LastIndexByte(r, '@'); at >= 0 {
					r = r[at+1:]
				}
				x.recalls = append(x.recalls, invalidate.Recall{Seq: e.Seq, ID: r})
			}
		}
	}
}
func (d *databaseState) observed() []view.Observed {
	out := make([]view.Observed, 0, len(d.records))
	for _, x := range d.records {
		admissible := x.sigStatus == sig.StatusVerified && x.state != string(invalidate.AncestryPending) && x.state != string(invalidate.LineageHold)
		out = append(out, view.Observed{Record: x.rec, Owner: x.owner, Live: x.state == string(invalidate.Live) && x.rec.Body != nil, Admissible: admissible, ObservedTaint: taintValues(d.taint[x.rec.ID])})
	}
	return out
}

func containsID(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
