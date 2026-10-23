package store

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/Telara-Labs/telara-memory/contract/heads"
	"github.com/Telara-Labs/telara-memory/contract/invalidate"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"github.com/Telara-Labs/telara-memory/contract/sig"
	"github.com/Telara-Labs/telara-memory/contract/view"
)

// These concrete structs contain only JSON-safe bounded values. Cloning is
// transient; serialized views are never written to the database.
func detached[T any](in T) T {
	b, _ := json.Marshal(in)
	var out T
	_ = json.Unmarshal(b, &out)
	return out
}
func (t *CaptureTxn) check() error {
	if t == nil || !t.valid.Load() {
		return failure("capture_txn_expired")
	}
	return nil
}
func (t *CaptureTxn) Context() (CaptureContext, error) {
	if e := t.check(); e != nil {
		return CaptureContext{}, e
	}
	return t.context, nil
}
func (t *CaptureTxn) Progress() (CaptureProgress, error) {
	if e := t.check(); e != nil {
		return CaptureProgress{}, e
	}
	return detached(t.progress), nil
}
func (t *CaptureTxn) PriorSource() ([]CaptureRecord, error) {
	if e := t.check(); e != nil {
		return nil, e
	}
	return detached(t.prior), nil
}
func (t *CaptureTxn) SessionPages() ([]CapturePage, error) {
	if e := t.check(); e != nil {
		return nil, e
	}
	return detached(t.pages), nil
}
func (t *CaptureTxn) Events(ids []string) (map[string]CaptureEventHistory, error) {
	if e := t.check(); e != nil {
		return nil, e
	}
	if len(ids) > 4096 {
		return nil, failure("history_limit")
	}
	out := map[string]CaptureEventHistory{}
	for _, id := range ids {
		h, ok := t.events[id]
		if !ok {
			return nil, failure("event_not_requested")
		}
		v := detached(h)
		v.Facts.CurrentSources = map[string]bool{}
		for k, b := range h.Facts.CurrentSources {
			v.Facts.CurrentSources[k] = b
		}
		out[id] = v
	}
	return out, nil
}

func available(x *stored) bool {
	return x != nil && x.state == "live" && x.sigStatus == sig.StatusVerified && x.rec.Body != nil
}
func availability(x *stored) string {
	if x == nil {
		return "missing"
	}
	if available(x) {
		return "available"
	}
	if x.state == "invalidated" {
		return "invalidated"
	}
	if x.rec.Body == nil {
		return "bodyless"
	}
	return x.state
}
func captureRecord(x *stored) CaptureRecord {
	r := CaptureRecord{RecordRef: RecordRef{x.rec.ID, x.seq}, Availability: availability(x)}
	r.HeaderJCS = append([]byte(nil), x.rec.HeaderJCS...)
	r.Sigs = append([]record.Signature(nil), x.sigs...)
	r.AdvisoryID = x.rec.ID
	if available(x) {
		r.BodyJCS = append([]byte(nil), x.rec.BodyJCS...)
	}
	return r
}
func suppression(d *databaseState, q SourceOccurrence) Suppression {
	out := Suppression{Suppressed: d.blocked, OwnerBlocked: d.blocked}
	for _, x := range d.records {
		if x.owner != q.Owner {
			continue
		}
		if q.Source != "" && x.rec.Header.Subj.Source == q.Source || q.SessionKey != "" && x.rec.Header.Subj.SessionKey == q.SessionKey {
			for _, c := range d.eval.Causes[x.rec.ID] {
				if c.Kind == invalidate.Erased {
					out.Suppressed = true
				}
			}
		}
	}
	for k := range d.bans {
		if k.owner == q.Owner && k.session == q.SessionKey {
			out.Suppressed = true
		}
	}
	return out
}
func (s *Store) makeCaptureTxn(ctx context.Context, d *databaseState, q CaptureRequest, p CaptureProgress) (*CaptureTxn, error) {
	t := &CaptureTxn{progress: p, events: map[string]CaptureEventHistory{}}
	var epoch int64
	if s.conn.QueryRowContext(ctx, "SELECT authority_epoch FROM meta WHERE singleton=1").Scan(&epoch) != nil {
		return nil, failure("storage_error")
	}
	t.context = CaptureContext{s.opts.PinnedGenesisID, s.opts.LocalMachineID, q.AuthorKeyID, epoch, d.generation, p.Version}
	total := 0
	addBytes := func(x *stored) bool {
		total += len(x.rec.HeaderJCS)
		if available(x) {
			total += len(x.rec.BodyJCS)
		}
		return total <= 64<<20
	}
	refs := p.LastSourceRecords
	if p.Version == 0 {
		for _, x := range d.records {
			if x.owner == q.Occurrence.Owner && x.rec.Header.Subj.Source == q.Occurrence.Source && x.rec.Header.Subj.SessionKey == q.Occurrence.SessionKey && x.rec.Header.Type == record.KindChunk {
				refs = append(refs, RecordRef{x.rec.ID, x.seq})
			}
		}
	}
	if len(refs) > 64 {
		return nil, failure("history_limit")
	}
	for _, r := range refs {
		x := d.byID[r.ID]
		if x == nil || x.seq != r.Sequence {
			return nil, failure("corrupt_database")
		}
		if !addBytes(x) {
			return nil, failure("history_limit")
		}
		t.prior = append(t.prior, captureRecord(x))
	}
	// Treat an unavailable latest page as unavailable, never fall back to an older
	// live page. All retained headers participate in permanent supersession.
	groups := map[int64][]*stored{}
	for _, x := range d.records {
		h := x.rec.Header
		if x.owner != q.Occurrence.Owner || h.Subj.SessionKey != q.Occurrence.SessionKey || h.Type != record.KindSession || h.Author.MachineID != s.opts.LocalMachineID {
			continue
		}
		// LID identity is session/machine/page, not source. Cross-source page
		// transfer is deliberately unsupported, including disjoint new events.
		if h.Subj.Source != q.Occurrence.Source {
			return nil, failure("ambiguous_source_baseline")
		}
		page := int64(-1)
		if b, ok := x.rec.Body.(*record.SessionBody); ok {
			page = b.Page
		} else {
			for i := int64(0); i < 16; i++ {
				if h.LID == record.SessionLID(q.Occurrence.SessionKey, s.opts.LocalMachineID, i) {
					page = i
					break
				}
			}
		}
		if page < 0 || page >= 16 {
			return nil, failure("history_limit")
		}
		groups[page] = append(groups[page], x)
	}
	for i := int64(0); i < int64(len(groups)); i++ {
		xs, ok := groups[i]
		if !ok {
			return nil, failure("ambiguous_page_history")
		}
		var versions []heads.Version
		for _, x := range xs {
			versions = append(versions, heads.FromHeader(x.rec.ID, &x.rec.Header, x.owner, true))
		}
		hs := heads.Heads(versions, nil, record.SessionLID(q.Occurrence.SessionKey, s.opts.LocalMachineID, i), record.KindSession)
		if len(hs) != 1 {
			return nil, failure("ambiguous_page_history")
		}
		x := d.byID[hs[0].ID]
		if !addBytes(x) {
			return nil, failure("history_limit")
		}
		if prev := x.rec.Header.Links.Prev; prev != "" {
			old := d.byID[prev]
			if old == nil || old.owner != x.owner || old.rec.Header.LID != x.rec.Header.LID {
				return nil, failure("ambiguous_page_history")
			}
		}
		r := captureRecord(x)
		t.pages = append(t.pages, CapturePage{PageRef: PageRef{i, x.rec.ID}, Prev: x.rec.Header.Links.Prev, Availability: r.Availability, SignedRecord: r.SignedRecord})
	}
	if len(t.pages) > 16 {
		return nil, failure("history_limit")
	}
	ids := map[string]bool{}
	for _, id := range q.EventIDs {
		ids[id] = true
	}
	facts := view.EventFacts{V: record.Version, CurrentSources: map[string]bool{}}
	historical := d.facts[q.Occurrence.SessionKey]
	count := 0
	for _, p := range historical.Presence {
		if p.Owner == q.Occurrence.Owner && ids[p.EventID] {
			facts.Presence = append(facts.Presence, p)
			count++
		}
	}
	for _, w := range historical.Witnesses {
		if w.Owner == q.Occurrence.Owner && ids[w.EventID] {
			facts.Witnesses = append(facts.Witnesses, w)
		}
	}
	if count > 8192 || len(facts.Witnesses) > 8192 {
		return nil, failure("history_limit")
	}
	var copies []view.EventVersion
	for _, x := range d.records {
		facts.CurrentSources[x.rec.ID] = x.sigStatus == sig.StatusVerified && x.state != "ancestry-pending" && x.state != "lineage-hold" && x.state != "privacy-hold"
		if x.owner != q.Occurrence.Owner || x.rec.Header.Subj.SessionKey != q.Occurrence.SessionKey {
			continue
		}
		b, ok := x.rec.Body.(*record.ChunkBody)
		if !ok {
			continue
		}
		used := false
		for _, e := range b.Events {
			if ids[e.ID] {
				count++
				if count > 8192 {
					return nil, failure("history_limit")
				}
				copies = append(copies, view.EventVersion{Event: e, Live: available(x), Admissible: facts.CurrentSources[x.rec.ID], ObservedTaint: x.rec.Header.Trust.Taint, RecordID: x.rec.ID, Owner: x.owner, SessionKey: q.Occurrence.SessionKey})
				used = true
			}
		}
		if used && !addBytes(x) {
			return nil, failure("history_limit")
		}
	}
	// Bound potential newly generated equality witnesses before the reducer's
	// pairwise comparison. This conservative work bound never returns a partial
	// witness set as authoritative history.
	revisions := map[string]map[string]int{}
	for _, v := range copies {
		if !v.Live || !v.Admissible {
			continue
		}
		if revisions[v.Event.ID] == nil {
			revisions[v.Event.ID] = map[string]int{}
		}
		revisions[v.Event.ID][v.Event.Revision]++
	}
	work := len(facts.Witnesses)
	for _, counts := range revisions {
		seen := 0
		for _, n := range counts {
			work += seen * n
			seen += n
			if work > 8192 {
				return nil, failure("history_limit")
			}
		}
	}
	choices, err := view.EventHeads(copies, nil, facts)
	if err != nil {
		return nil, failure("invalid_causal_state")
	}
	witnessCount := 0
	for id := range ids {
		c := choices[id]
		witnessCount += len(c.Facts.Witnesses)
		if witnessCount > 8192 {
			return nil, failure("history_limit")
		}
		h := CaptureEventHistory{ID: id, Pending: c.Pending, Conflict: c.Conflict, Facts: c.Facts}
		h.Facts.V = record.Version
		h.Facts.CurrentSources = map[string]bool{}
		for _, p := range h.Facts.Presence {
			h.Facts.CurrentSources[p.RecordID] = facts.CurrentSources[p.RecordID]
		}
		for _, w := range h.Facts.Witnesses {
			h.Facts.CurrentSources[w.RecordA] = facts.CurrentSources[w.RecordA]
			h.Facts.CurrentSources[w.RecordB] = facts.CurrentSources[w.RecordB]
		}
		h.Banned = len(d.bans[occurrence{q.Occurrence.Owner, q.Occurrence.SessionKey, id}]) > 0
		h.KnownPresence = len(c.Facts.Presence) > 0
		for _, v := range copies {
			if v.Event.ID == id && v.Live && v.Admissible {
				h.Copies = append(h.Copies, v)
			}
		}
		authorized := map[string]view.RevisionPresence{}
		suppressed := map[string]bool{}
		full := map[string]bool{}
		for _, v := range h.Copies {
			full[v.Event.Revision] = true
		}
		for _, p := range h.Facts.Presence {
			if facts.CurrentSources[p.RecordID] {
				authorized[p.Revision] = p
				for _, r := range p.Replaces {
					suppressed[r] = true
				}
			}
		}
		for rev, p := range authorized {
			for _, parent := range p.Replaces {
				if _, ok := authorized[parent]; !ok {
					h.Pending = true
				}
			}
			if !suppressed[rev] && !full[rev] {
				h.Pending = true
			}
		}
		for _, e := range c.Heads {
			h.MaximalRevisionIDs = append(h.MaximalRevisionIDs, e.Revision)
		}
		sort.Strings(h.MaximalRevisionIDs)
		if h.KnownPresence && len(h.MaximalRevisionIDs) == 0 {
			h.Pending = true
		}
		h.CompleteFrontier = !h.Pending && !h.Banned
		t.events[id] = h
	}
	// Count all retained facts and detached metadata as well as copied bodies.
	b, _ := json.Marshal(struct {
		Prior  []CaptureRecord
		Pages  []CapturePage
		Events map[string]CaptureEventHistory
	}{t.prior, t.pages, t.events})
	if len(b) > 64<<20 {
		return nil, failure("history_limit")
	}
	t.valid.Store(true)
	return t, nil
}
