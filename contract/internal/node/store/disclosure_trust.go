package store

import (
	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/sig"
	"github.com/Telara-Labs/hilo/contract/view"
	"sort"
)

type taintWitness struct{ id, tag, kind, evidence, source, boundary string }

func (d *databaseState) witness(w taintWitness) error {
	if d.taintWitnesses == nil {
		d.taintWitnesses = map[taintWitness]bool{}
	}
	if d.taintWitnesses[w] {
		return nil
	}
	if d.store != nil {
		var n int
		if err := d.store.conn.QueryRowContext(d.ctx, "SELECT count(*) FROM record_taint_evidence WHERE owner=? AND id=? AND tag=? AND kind=? AND evidence=? AND source=? AND boundary=?", d.store.opts.PinnedGenesisID, w.id, w.tag, w.kind, w.evidence, w.source, w.boundary).Scan(&n); err != nil {
			return failure("storage_error")
		}
		if n > 0 {
			return nil
		}
	}
	if len(d.taintWitnesses) >= 8192 {
		return failure("taint_projection_limit")
	}
	d.taintWitnesses[w] = true
	return nil
}
func (d *databaseState) currentBinding(ref, owner string) (view.Binding, string) {
	return d.binding(ref, owner)
}

// Trust uses actual reducer inputs. Neither signed coverage claims nor a local
// builder completeness fact supplies native session coverage or evidence.
func (d *databaseState) computeTrust(ids []string) error {
	d.trust = map[string]view.EffectiveTrust{}
	d.trustDeps = map[string][]string{}
	d.directEvidence = map[string][]string{}
	sessions := map[string]*view.Session{}
	sessionFor := func(sk string) (*view.Session, error) {
		if s, ok := sessions[sk]; ok {
			return s, nil
		}
		if len(sessions) >= 128 {
			return nil, &projectionLimit{}
		}
		s, err := d.reduceSession(sk)
		if err != nil {
			return nil, err
		}
		sessions[sk] = s
		return s, nil
	}
	callRefs := map[string]string{}
	for _, x := range d.records {
		if b, ok := x.rec.Body.(*record.CallBody); ok && available(x) {
			callRefs[x.rec.Header.Op] = b.CallRef
		}
	}
	visiting := map[string]bool{}
	work := 0
	var resolve func(string) (view.EffectiveTrust, error)
	resolve = func(id string) (view.EffectiveTrust, error) {
		if t, ok := d.trust[id]; ok {
			return t, nil
		}
		x := d.byID[id]
		fallback := view.EffectiveTrust{Observed: taintValues(d.taint[id]), Coverage: "incomplete", Uncertain: true}
		if x == nil || visiting[id] {
			return fallback, nil
		}
		visiting[id] = true
		defer delete(visiting, id)
		in := view.TrustInput{Header: record.Trust{Taint: taintValues(d.taint[id])}, Kind: x.rec.Header.Type, Provenance: x.rec.Header.Prov, Verified: x.sigStatus == sig.StatusVerified, AncestryResolved: available(x), Boundary: -1}
		deps := map[string]bool{}
		for _, p := range x.deps {
			deps[p] = true
		}
		if p := x.rec.Header.Links.Origin; p != "" {
			deps[p] = true
			in.OriginRequired = true
			in.OriginAvailable = available(d.byID[p])
		}
		for p := range d.semantic[id] {
			deps[p] = true
		}
		in.CopiedInputs = len(deps)
		for p := range deps {
			work++
			if work > 1048576 {
				return fallback, &projectionLimit{}
			}
			t, err := resolve(p)
			if err != nil {
				return fallback, err
			}
			in.Inputs = append(in.Inputs, t)
			d.trustDeps[id] = append(d.trustDeps[id], p)
		}
		sk := x.rec.Header.Subj.SessionKey
		bindingID := ""
		if ref := callRefs[x.rec.Header.Op]; ref != "" {
			b, bid := d.currentBinding(ref, x.owner)
			if b.Target != nil {
				sk = b.Target.SessionKey
				in.BindingConfidence = b.Confidence
				bindingID = bid
				d.trustDeps[id] = append(d.trustDeps[id], bid)
				d.directEvidence[id] = append(d.directEvidence[id], bid)
			}
		}
		if sk != "" {
			s, err := sessionFor(sk)
			if err != nil {
				return fallback, err
			}
			in.Session = s
			switch body := x.rec.Body.(type) {
			case *record.ChunkBody:
				for _, ev := range body.Events {
					in.EventSequences = append(in.EventSequences, ev.Seq)
					in.Boundary = max(in.Boundary, ev.Seq)
				}
			case *record.SessionBody:
				in.Boundary = body.SettledThrough
			default:
				if bid := d.byID[bindingID]; bid != nil {
					bb := bid.rec.Body.(*record.BindingBody)
					if bb.Evidence != nil {
						for _, ev := range s.Events {
							for _, eid := range bb.Evidence.SightingEventIDs {
								if eid == ev.ID {
									in.Boundary = max(in.Boundary, ev.Seq)
								}
							}
						}
					}
				}
			}
			members := currentSessionSources(d, sk)
			for _, source := range d.records {
				if !members[source.rec.ID] || source.rec.Header.Subj.SessionKey != sk || !available(source) {
					continue
				}
				if source.rec.Header.Type == record.KindSession || source.rec.Header.Type == record.KindChunk {
					d.trustDeps[id] = append(d.trustDeps[id], source.rec.ID)
					evidence := source.rec.Header.Type == record.KindSession
					if cb, ok := source.rec.Body.(*record.ChunkBody); ok {
						for _, ev := range cb.Events {
							if ev.Seq == in.Boundary {
								evidence = true
							}
						}
					}
					if evidence {
						d.directEvidence[id] = append(d.directEvidence[id], source.rec.ID)
					}
				}
			}
		}
		t := view.Trust(in)
		d.trust[id] = t
		sort.Strings(d.trustDeps[id])
		return t, nil
	}
	for _, id := range ids {
		if _, err := resolve(id); err != nil {
			return err
		}
	}
	return nil
}
func (d *databaseState) projectObservedTaint() error {
	if d.taint == nil {
		d.taint = map[string]map[string]bool{}
	}
	add := func(id, tag string) bool {
		if !observedTag(tag) {
			return false
		}
		if d.taint[id] == nil {
			d.taint[id] = map[string]bool{}
		}
		if d.taint[id][tag] {
			return false
		}
		d.taint[id][tag] = true
		return true
	}
	for _, x := range d.records {
		if x.sigStatus != sig.StatusVerified {
			continue
		}
		for _, tag := range x.rec.Header.Trust.Taint {
			if observedTag(tag) {
				add(x.rec.ID, tag)
				if err := d.witness(taintWitness{x.rec.ID, tag, "header_claim", x.rec.ID, x.rec.ID, ""}); err != nil {
					return err
				}
			}
		}
		for _, f := range d.fields[x.rec.ID] {
			if f.class == "injected_source" || f.class == "possible_memory_frame" {
				add(x.rec.ID, "recalled-memory")
				if err := d.witness(taintWitness{x.rec.ID, "recalled-memory", "possible_recall_field", x.rec.ID, x.rec.ID, f.event}); err != nil {
					return err
				}
			}
		}
	}
	// One complete-or-refuse work budget covers binding observations and the
	// dependency fixed point; historical presence never becomes a prefix.
	work := 0
	c, err := d.reductions()
	if err != nil {
		return err
	}
	charge := func(n int) error {
		if n < 0 || n > 1048576-work {
			return &projectionLimit{}
		}
		if err := c.charge(n); err != nil {
			return err
		}
		work += n
		return nil
	}
	// Compute the current accepted binding before any correction can replace it.
	// Witnesses collected by load remain staged across the subsequent rebuild.
	callRefs := map[string]string{}
	for _, x := range d.records {
		if b, ok := x.rec.Body.(*record.CallBody); ok && available(x) {
			callRefs[x.rec.Header.Op] = b.CallRef
		}
	}
	for _, x := range d.records {
		ref := callRefs[x.rec.Header.Op]
		if ref == "" || !available(x) {
			continue
		}
		b, bid := d.currentBinding(ref, x.owner)
		if b.Target == nil {
			continue
		}
		s, err := d.reduceSession(b.Target.SessionKey)
		if err != nil {
			return err
		}
		boundary := int64(-1)
		bb := d.byID[bid].rec.Body.(*record.BindingBody)
		if bb.Evidence != nil {
			if n := len(bb.Evidence.SightingEventIDs); n > 0 {
				if len(s.Events) > (1048576-work)/n {
					return &projectionLimit{}
				}
				if err := charge(len(s.Events) * n); err != nil {
					return err
				}
			}
			for _, ev := range s.Events {
				for _, eid := range bb.Evidence.SightingEventIDs {
					if eid == ev.ID {
						boundary = max(boundary, ev.Seq)
					}
				}
			}
		}
		if err := charge(len(s.Facts.Presence)); err != nil {
			return err
		}
		for _, presence := range s.Facts.Presence {
			if presence.Owner != x.owner || presence.SessionKey != b.Target.SessionKey || presence.Seq > boundary {
				continue
			}
			source := d.byID[presence.RecordID]
			if source == nil || source.owner != x.owner || source.rec.Header.Type != record.KindChunk || source.rec.Header.Subj.SessionKey != b.Target.SessionKey {
				return failure("corrupt_database")
			}
			// These are the reducer's historical observations, not current
			// manifest membership or body availability. A later correction,
			// revocation or erasure cannot retract an observation already made.
			for _, tag := range presence.ObservedTaint {
				if !observedTag(tag) {
					continue
				}
				add(x.rec.ID, tag)
				if err := d.witness(taintWitness{x.rec.ID, tag, "binding_projection", bid, presence.RecordID, presence.EventID}); err != nil {
					return err
				}
			}
		}
	}
	changed := true
	for changed {
		if err := charge(len(d.records)); err != nil {
			return err
		}
		changed = false
		for _, x := range d.records {
			if x.sigStatus != sig.StatusVerified {
				continue
			}
			if err := charge(len(x.deps) + len(d.semantic[x.rec.ID]) + 1); err != nil {
				return err
			}
			deps := append([]string(nil), x.deps...)
			if p := x.rec.Header.Links.Origin; p != "" {
				deps = append(deps, p)
			}
			for p := range d.semantic[x.rec.ID] {
				deps = append(deps, p)
			}
			for _, p := range deps {
				if err := charge(1 + len(d.taint[p])); err != nil {
					return err
				}
				for tag := range d.taint[p] {
					if add(x.rec.ID, tag) {
						changed = true
					}
					if err := d.witness(taintWitness{x.rec.ID, tag, "dependency", p, p, ""}); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func currentSessionSources(d *databaseState, sk string) map[string]bool {
	out := map[string]bool{}
	head := currentHeads(d)
	for _, x := range d.records {
		if x.rec.Header.Type != record.KindSession || x.rec.Header.Subj.SessionKey != sk || !head[x.rec.ID] {
			continue
		}
		b, ok := x.rec.Body.(*record.SessionBody)
		if !ok {
			continue
		}
		out[x.rec.ID] = true
		for _, id := range b.Chunks {
			out[id] = true
		}
	}
	return out
}
