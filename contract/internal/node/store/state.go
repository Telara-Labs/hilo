package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/Telara-Labs/telara-memory/contract/invalidate"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/view"
)

type stored struct {
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
	blocked             bool
	retained            map[string][]invalidate.Tomb
	bans                map[occurrence]map[string]bool
	records             []*stored
	byID                map[string]*stored
	kr                  *sig.Keyring
	model               *invalidate.Model
	eval                *invalidate.Eval
	facts               map[string]view.EventFacts
	generation, nextSeq int64
}

func (s *Store) load(ctx context.Context) (*databaseState, error) {
	d := &databaseState{byID: map[string]*stored{}, facts: map[string]view.EventFacts{}}
	if s.conn.QueryRowContext(ctx, "SELECT generation,next_seq FROM meta WHERE singleton=1").Scan(&d.generation, &d.nextSeq) != nil {
		return nil, failure("storage_error")
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
	if err = s.loadFacts(ctx, d); err != nil {
		return nil, err
	}
	if err = d.rebuild(s.opts); err != nil {
		return nil, err
	}
	for _, x := range d.records {
		x.previousLive = x.state == "live" && x.sigStatus == sig.StatusVerified && x.rec.Body != nil
	}
	return d, nil
}
func (d *databaseState) rebuild(o Options) error {
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
		it := invalidate.Item{ID: x.rec.ID, LID: h.LID, Kind: h.Type, Prov: h.Prov, Owner: x.owner, TaskID: h.Subj.TaskID, SessionKey: h.Subj.SessionKey, Source: h.Subj.Source, Deps: x.deps, Events: x.events, Recalls: x.recalls, Origin: h.Links.Origin, Route: record.RouteLocal, OriginMachine: h.Author.MachineID, Explicit: h.Prov == record.ProvMCPExplicit, SessionSeq: x.lastSeq}
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
	// Unknown session ordering must never be interpreted as sequence zero.
	for _, source := range d.records {
		for _, r := range source.recalls {
			var unknown []string
			for _, dest := range d.records {
				if dest.rec.Header.Subj.SessionKey != "" && dest.rec.Header.Subj.SessionKey == source.rec.Header.Subj.SessionKey && !dest.orderKnown {
					unknown = append(unknown, dest.rec.ID)
				}
			}
			if len(unknown) > 0 {
				d.model.Expose(invalidate.Exposure{ID: r.ID, AffectsIDs: unknown})
			}
		}
	}
	d.eval = d.model.Evaluate()
	d.enforceFences()
	for _, x := range d.records {
		x.state = string(d.eval.StatusOf(x.rec.ID))
		if x.sigStatus != sig.StatusVerified && x.state != string(invalidate.Invalidated) {
			x.state = "unverified"
		}
	}
	// Current admission eligibility also follows present copied dependencies.
	changed := true
	for changed {
		changed = false
		for _, x := range d.records {
			if x.state != "live" {
				continue
			}
			deps := append([]string(nil), x.deps...)
			if origin := x.rec.Header.Links.Origin; origin != "" && d.byID[origin] != nil {
				deps = append(deps, origin)
			}
			// A recalled source is a semantic dependency for potentially downstream
			// output, even without a copied-content edge. Unknown ordering is conservative.
			for _, source := range d.records {
				if source.rec.Header.Subj.SessionKey == "" || source.rec.Header.Subj.SessionKey != x.rec.Header.Subj.SessionKey {
					continue
				}
				for _, r := range source.recalls {
					if !x.orderKnown || x.lastSeq > r.Seq {
						deps = append(deps, r.ID)
					}
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
		out = append(out, view.Observed{Record: x.rec, Owner: x.owner, Live: x.state == string(invalidate.Live) && x.rec.Body != nil, Admissible: admissible})
	}
	return out
}
