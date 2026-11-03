package store

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/Telara-Labs/hilo/contract/record"
	"github.com/Telara-Labs/hilo/contract/view"
)

const reductionWorkLimit = 1048576

type cachedSession struct {
	key     string
	value   *view.Session
	history view.EventFacts
	sources map[string]bool
}
type reductionContext struct {
	work, encoded int
	sessions      map[string]cachedSession
	plan          *relationPlan
}

func newReductionContext() *reductionContext {
	return &reductionContext{sessions: map[string]cachedSession{}}
}
func (c *reductionContext) charge(n int) error {
	if n < 0 || n > reductionWorkLimit-c.work {
		return &projectionLimit{}
	}
	c.work += n
	return nil
}
func (c *reductionContext) product(a, b int) error {
	if a < 0 || b < 0 || a != 0 && b > (reductionWorkLimit-c.work)/a {
		return &projectionLimit{}
	}
	return c.charge(a * b)
}
func (c *reductionContext) encode(n, m int) error {
	if n < 0 || m < 0 || n != 0 && m > ((64<<20)-c.encoded)/n {
		return &projectionLimit{}
	}
	c.encoded += n * m
	return nil
}
func (d *databaseState) reductions() (*reductionContext, error) {
	if d.store == nil || d.store.reductions == nil {
		return nil, failure("unavailable")
	}
	return d.store.reductions, nil
}

// The cache contains only immutable, verified state within one acquired writer.
// A body/status/taint/fact/membership change changes the exact input key. An
// unrelated task is not made a session/event input merely to charge it again.
func (d *databaseState) reduceSession(sk string) (*view.Session, error) {
	c, err := d.reductions()
	if err != nil {
		return nil, err
	}
	f := d.facts[sk]
	if f.V == 0 {
		f.V = record.Version
	}
	sourceIDs := map[string]bool{}
	old, hit := c.sessions[sk]
	historySame := hit && sameFactBacking(old.history, f)
	if historySame {
		sourceIDs = old.sources
	} else {
		if err = c.charge(len(f.Presence) + 2*len(f.Witnesses)); err != nil {
			return nil, err
		}
		for _, p := range f.Presence {
			if p.Owner != d.store.opts.PinnedGenesisID || p.SessionKey != sk {
				return nil, failure("corrupt_database")
			}
			sourceIDs[p.RecordID] = true
		}
		for _, w := range f.Witnesses {
			if w.Owner != d.store.opts.PinnedGenesisID || w.SessionKey != sk {
				return nil, failure("corrupt_database")
			}
			sourceIDs[w.RecordA] = true
			sourceIDs[w.RecordB] = true
		}
	}
	// Cache lookups still validate retained source provenance and scan current
	// metadata. Charge that work before those scans or detached allocations.
	if err = c.charge(len(sourceIDs) + 2*len(d.records)); err != nil {
		return nil, err
	}
	for id := range sourceIDs {
		source := d.byID[id]
		if source == nil || source.owner != d.store.opts.PinnedGenesisID || source.rec.Header.Subj.SessionKey != sk || source.rec.Header.Type != record.KindChunk {
			return nil, failure("corrupt_database")
		}
	}
	var observed []view.Observed
	type identity struct {
		ID, Owner              string
		Body, Live, Admissible bool
		Taint                  []string
	}
	var identities []identity
	for _, o := range d.observed() {
		if o.Record.Header.Subj.SessionKey != sk && !sourceIDs[o.Record.ID] {
			continue
		}
		observed = append(observed, o)
		identities = append(identities, identity{o.Record.ID, o.Owner, o.Record.Body != nil, o.Live, o.Admissible, o.ObservedTaint})
	}
	keyBytes := 0
	for _, v := range identities {
		keyBytes += 256 + len(v.ID) + len(v.Owner)
		for _, tag := range v.Taint {
			keyBytes += 6*len(tag) + 4
		}
	}
	if err = c.encode(keyBytes, 1); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(identities)
	if err != nil {
		return nil, failure("invalid_causal_state")
	}
	sum := sha256.Sum256(raw)
	clear(raw)
	key := fmt.Sprintf("%x", sum)
	if historySame && old.key == key {
		return old.value, nil
	}
	// Account for page head selection, membership and coverage before the pure
	// session wrapper constructs those maps. All records here belong to sk.
	if err = c.charge(len(observed) * 4); err != nil {
		return nil, err
	}
	versions, lids, links, refs := 0, map[string]bool{}, 0, 0
	for _, o := range observed {
		if o.Record.Header.Type == record.KindSession {
			versions++
			lids[o.Record.Header.LID] = true
			links += len(o.Record.Header.Links.Supersedes)
			if b, ok := o.Record.Body.(*record.SessionBody); ok {
				refs += len(b.Chunks)
			}
		}
	}
	if err = c.product(len(lids), versions+links); err != nil {
		return nil, err
	}
	if err = c.charge(refs * 258); err != nil {
		return nil, err
	}
	members := currentSessionSources(d, sk)
	copyCount := 0
	for _, o := range observed {
		if b, ok := o.Record.Body.(*record.ChunkBody); ok {
			if err = c.charge(len(b.Events)); err != nil {
				return nil, err
			}
			copyCount += len(b.Events)
		}
	}
	// Each contiguous page can rescan the complete seen sequence prefix.
	// All page versions are a conservative upper bound on selected pages.
	if err = c.product(versions, copyCount); err != nil {
		return nil, err
	}
	var copies = make([]view.EventVersion, 0, copyCount)
	for _, o := range observed {
		if b, ok := o.Record.Body.(*record.ChunkBody); ok {
			for _, ev := range b.Events {
				copies = append(copies, view.EventVersion{Event: ev, RecordID: o.Record.ID, Owner: o.Owner, SessionKey: sk, Live: o.Live && members[o.Record.ID], Admissible: o.Admissible, ObservedTaint: append(append([]string(nil), o.ObservedTaint...), o.Record.Header.Trust.Taint...)})
			}
		}
	}
	if err = c.preflightEvents(d, copies, nil, f); err != nil {
		return nil, err
	}
	result, err := view.SessionView(observed, nil, nil, sk, f)
	if err != nil {
		return nil, failure("invalid_causal_state")
	}
	if err = c.stageFacts(d, result.Facts); err != nil {
		return nil, err
	}
	c.sessions[sk] = cachedSession{key, result, f, sourceIDs}
	return result, nil
}
func (d *databaseState) reduceEvents(copies []view.EventVersion, index []view.EventPair, facts view.EventFacts) (map[string]view.EventChoice, error) {
	c, err := d.reductions()
	if err != nil {
		return nil, err
	}
	if err = c.preflightEvents(d, copies, index, facts); err != nil {
		return nil, err
	}
	result, err := view.EventHeads(copies, index, facts)
	if err != nil {
		return nil, failure("invalid_causal_state")
	}
	return result, nil
}

type eventCost struct {
	revisions map[string]bool
	live      []view.EventVersion
	witnesses map[relationKey]bool
	parents   int
	empty     bool
}

func (c *reductionContext) preflightEvents(d *databaseState, copies []view.EventVersion, index []view.EventPair, f view.EventFacts) error {
	p := len(f.Presence) + len(copies)
	w := len(f.Witnesses)
	if err := c.charge(p + len(copies) + w + len(index)); err != nil {
		return err
	}
	groups := map[string]*eventCost{}
	group := func(id string) *eventCost {
		g := groups[id]
		if g == nil {
			g = &eventCost{revisions: map[string]bool{}, witnesses: map[relationKey]bool{}, empty: true}
			groups[id] = g
		}
		return g
	}
	for _, x := range f.Presence {
		g := group(x.EventID)
		g.revisions[x.Revision] = true
		g.parents += len(x.Replaces)
		g.empty = g.empty && len(x.Replaces) == 0
	}
	for _, x := range f.Witnesses {
		if err := c.reserveWitnessEncoding(x); err != nil {
			return err
		}
		group(x.EventID).witnesses[pureWitnessKey(x)] = true
	}
	for _, x := range index {
		group(x.EventID)
	}
	lengths := map[string]int{}
	for _, x := range copies {
		g := group(x.Event.ID)
		g.revisions[x.Event.Revision] = true
		g.parents += len(x.Event.Replaces)
		g.empty = g.empty && len(x.Event.Replaces) == 0
		n, err := c.eventEncodingSize(x.Event)
		if err != nil {
			return err
		}
		lengths[x.RecordID+"/"+x.Event.Revision] = n
		// Reserve the complete revision validation/hash helper chain.
		if err = c.reserveRevisionEncoding(x.Event, n); err != nil {
			return err
		}
		if x.Live && x.Admissible {
			g.live = append(g.live, x)
		}
	}
	// EventHeads scans each complete presence/copy/witness/index array once per
	// event. This is a global product, not a sum of per-event group sizes.
	if err := c.product(len(groups), p+len(copies)+w+len(index)); err != nil {
		return err
	}
	plan, err := c.relations(d)
	if err != nil {
		return err
	}
	potential := map[relationKey]bool{}
	for _, g := range groups {
		n := len(g.live)
		if n > 1 {
			// The pure loop visits current[i+1:], once per unordered pair.
			// Divide first so the checked product cannot overflow beforehand.
			a, b := n, n-1
			if a%2 == 0 {
				a /= 2
			} else {
				b /= 2
			}
			if err = c.product(a, b); err != nil {
				return err
			}
		} // includes all pair loop iterations conservatively; outer 6n covers
		// its payload and a possible final-head comparison, three encodings each.
		for i, a := range g.live {
			if err = c.reservePayloadEncoding(lengths[a.RecordID+"/"+a.Event.Revision], 2); err != nil {
				return err
			}
			for _, b := range g.live[i+1:] {
				if a.Event.Revision == b.Event.Revision {
					continue
				}
				if err = c.reservePayloadEncoding(lengths[b.RecordID+"/"+b.Event.Revision], 1); err != nil {
					return err
				}
				witness := view.EqualityWitness{EventID: a.Event.ID, A: a.Event.Revision, B: b.Event.Revision, RecordA: a.RecordID, RecordB: b.RecordID, Owner: a.Owner, SessionKey: a.SessionKey, Admissible: true}
				if err = c.reserveWitnessEncoding(witness); err != nil {
					return err
				}
				row := witnessRow(witness)
				k := relationKeyOf(row)
				if !plan.has("witness", k) {
					potential[k] = true
					if plan.count("witness")+len(potential) > 65536 {
						return &projectionLimit{}
					}
				}
				g.witnesses[pureWitnessKey(witness)] = true
			}
		}
		r := len(g.revisions)
		rounds := r
		if g.empty && rounds > 2 {
			rounds = 2
		}
		if rounds < 1 {
			rounds = 1
		}
		// At most R-1 successful unions; empty frontiers all match in the first
		// pass and need only one stable pass. Parent/frontier work stays explicit.
		frontier := 1
		if !g.empty {
			frontier = 17
		}
		if err = c.product(rounds, len(g.witnesses)); err != nil {
			return err
		}
		if err = c.product(rounds*frontier, len(g.witnesses)); err != nil {
			return err
		}
		if err = c.charge(r + g.parents); err != nil {
			return err
		}
		if !g.empty {
			if err = c.product(r, r+g.parents); err != nil {
				return err
			}
		} else {
			if err = c.charge(r); err != nil {
				return err
			}
		}
	}
	return nil
}
func pureWitnessKey(w view.EqualityWitness) relationKey {
	if w.A > w.B {
		w.A, w.B = w.B, w.A
		w.RecordA, w.RecordB = w.RecordB, w.RecordA
	}
	return relationKeyOf(witnessRow(w))
}
func witnessRow(w view.EqualityWitness) []any {
	return []any{w.Owner, w.SessionKey, w.EventID, w.A, w.B, w.RecordA, w.RecordB}
}

// Merge by the actual SQL keys, never by pure alias equivalence or a live-only
// suffix. The merged metadata is also the authoritative post-purge history.
func mergedFacts(a, b view.EventFacts) view.EventFacts {
	out := view.EventFacts{V: record.Version}
	presence := map[relationKey]view.RevisionPresence{}
	witness := map[relationKey]view.EqualityWitness{}
	for _, f := range []view.EventFacts{a, b} {
		for _, p := range f.Presence {
			k := relationKeyOf([]any{p.Owner, p.SessionKey, p.EventID, p.Revision, p.RecordID})
			if prior, ok := presence[k]; ok {
				tags := map[string]bool{}
				parents := map[string]bool{}
				for _, v := range append(prior.ObservedTaint, p.ObservedTaint...) {
					tags[v] = true
				}
				for _, v := range append(prior.Replaces, p.Replaces...) {
					parents[v] = true
				}
				p.ObservedTaint = nil
				p.Replaces = nil
				for v := range tags {
					p.ObservedTaint = append(p.ObservedTaint, v)
				}
				for v := range parents {
					p.Replaces = append(p.Replaces, v)
				}
				sort.Strings(p.ObservedTaint)
				sort.Strings(p.Replaces)
			}
			presence[k] = p
		}
		for _, w := range f.Witnesses {
			witness[relationKeyOf(witnessRow(w))] = w
		}
	}
	keys := make([]relationKey, 0, len(presence))
	for k := range presence {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
	for _, k := range keys {
		out.Presence = append(out.Presence, presence[k])
	}
	keys = keys[:0]
	for k := range witness {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
	for _, k := range keys {
		out.Witnesses = append(out.Witnesses, witness[k])
	}
	return out
}
func integerKey(v int64) string { return strconv.FormatInt(v, 10) }

// Store-owned history slices are immutable after load; new fact unions allocate
// fresh backing. Retaining the old backing prevents pointer reuse in this lease.
func sameFactBacking(a, b view.EventFacts) bool {
	if a.V != b.V || len(a.Presence) != len(b.Presence) || len(a.Witnesses) != len(b.Witnesses) || len(a.CurrentSources) != 0 || len(b.CurrentSources) != 0 {
		return false
	}
	return (len(a.Presence) == 0 || &a.Presence[0] == &b.Presence[0]) && (len(a.Witnesses) == 0 || &a.Witnesses[0] == &b.Witnesses[0])
}
