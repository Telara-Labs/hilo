package view

import (
	"bytes"
	"fmt"
	"github.com/Telara-Labs/telara-memory/contract/record"
	"sort"
)

// Inputs are verified admission facts, never assertions decoded from transport.
// Admissible is recomputed from retained signer/admission provenance; body erasure
// alone does not revoke a previously verified presence/equality witness.
type EventVersion struct {
	Admissible                  bool
	ObservedTaint               []string
	Event                       record.Event
	Live                        bool
	RecordID, Owner, SessionKey string
}
type EventPair struct{ EventID, From, To, RecordID, Owner, SessionKey string }
type RevisionPresence struct {
	Seq                                            int64
	ObservedTaint                                  []string
	EventID, Revision, RecordID, Owner, SessionKey string
	Replaces                                       []string
	Admissible                                     bool
}
type EqualityWitness struct {
	EventID, A, B, RecordA, RecordB, Owner, SessionKey string
	Admissible                                         bool
}
type EventFacts struct {
	CurrentSources map[string]bool `json:"-"` // runtime authoritative source status, independent of body availability
	V              int
	Presence       []RevisionPresence
	Witnesses      []EqualityWitness
}
type EventChoice struct {
	ObservedTaint     []string
	Heads             []record.Event
	Pending, Conflict bool
	Facts             EventFacts
}

func witnessKey(w EqualityWitness) string {
	a, b, ra, rb := w.A, w.B, w.RecordA, w.RecordB
	if a > b {
		a, b, ra, rb = b, a, rb, ra
	}
	return record.H("event-equality", w.Owner, w.SessionKey, w.EventID, a, b, ra, rb)
}

// EventHeads reconstructs active aliases from identity at every evaluation.
// A retained payload witness activates only with admissible source records and
// equal current parent-class frontiers, so parent trust loss removes dependents.
func EventHeads(copies []EventVersion, index []EventPair, history ...EventFacts) (map[string]EventChoice, error) {
	owner, session := "", ""
	events := map[string]bool{}
	facts := EventFacts{V: record.Version}
	for _, h := range history {
		if h.V != record.Version {
			return nil, fmt.Errorf("event: legacy revision facts refused")
		}
		facts.Presence = append(facts.Presence, h.Presence...)
		facts.Witnesses = append(facts.Witnesses, h.Witnesses...)
	}
	currentStatus := map[string]bool{}
	for _, h := range history {
		for id, status := range h.CurrentSources {
			if old, ok := currentStatus[id]; ok {
				currentStatus[id] = old && status
			} else {
				currentStatus[id] = status
			}
		}
	}
	for _, v := range copies {
		if old, ok := currentStatus[v.RecordID]; !ok {
			currentStatus[v.RecordID] = v.Admissible
		} else {
			currentStatus[v.RecordID] = old && v.Admissible
		}
	}
	scope := func(o, s string) bool {
		if o == "" || s == "" {
			return false
		}
		if owner == "" {
			owner, session = o, s
		}
		return o == owner && s == session
	}
	for _, v := range copies {
		if !scope(v.Owner, v.SessionKey) || v.RecordID == "" {
			return nil, fmt.Errorf("event: verified namespace/source required")
		}
		rev, err := record.EventRevision(v.Event)
		if err != nil || rev != v.Event.Revision {
			return nil, fmt.Errorf("event: protected revision mismatch")
		}
		events[v.Event.ID] = true
		facts.Presence = append(facts.Presence, RevisionPresence{EventID: v.Event.ID, Revision: rev, RecordID: v.RecordID, Owner: v.Owner, SessionKey: v.SessionKey, Replaces: append([]string(nil), v.Event.Replaces...), Seq: v.Event.Seq, ObservedTaint: observedTags(v.ObservedTaint, v.Admissible), Admissible: v.Admissible})
	}
	for _, p := range facts.Presence {
		if !scope(p.Owner, p.SessionKey) || p.RecordID == "" || !record.IsHex64(p.Revision) || len(p.Replaces) > 8 {
			return nil, fmt.Errorf("event: malformed presence namespace")
		}
		events[p.EventID] = true
	}
	for _, w := range facts.Witnesses {
		if !scope(w.Owner, w.SessionKey) || w.RecordA == "" || w.RecordB == "" {
			return nil, fmt.Errorf("event: malformed equality witness")
		}
		events[w.EventID] = true
	}
	for _, p := range index {
		if !scope(p.Owner, p.SessionKey) || p.RecordID == "" {
			return nil, fmt.Errorf("event: legacy/unscoped causal index refused")
		}
		events[p.EventID] = true
	}
	out := map[string]EventChoice{}
	for eventID := range events {
		seen := map[string]RevisionPresence{}
		sources := map[string]map[string]bool{}
		allSeen := []RevisionPresence{}
		for _, p := range facts.Presence {
			if p.EventID != eventID {
				continue
			}
			if status, ok := currentStatus[p.RecordID]; ok {
				p.Admissible = status
			}
			p.ObservedTaint = observedTags(p.ObservedTaint, true)
			p.Replaces = append([]string(nil), p.Replaces...)
			sort.Strings(p.Replaces)
			allSeen = append(allSeen, p)
			if !p.Admissible {
				continue
			}
			if prior, ok := seen[p.Revision]; ok && !sameStrings(prior.Replaces, p.Replaces) {
				return nil, fmt.Errorf("event: inconsistent causal presence")
			}
			seen[p.Revision] = p
			if sources[p.Revision] == nil {
				sources[p.Revision] = map[string]bool{}
			}
			sources[p.Revision][p.RecordID] = true
		}
		body := map[string]EventVersion{}
		live := map[string]bool{}
		var current []EventVersion
		for _, v := range copies {
			if v.Event.ID != eventID {
				continue
			}
			v.Admissible = currentStatus[v.RecordID]
			if prior, ok := body[v.Event.Revision]; !ok || !(prior.Live && prior.Admissible) {
				body[v.Event.Revision] = v
			}
			live[v.Event.Revision] = live[v.Event.Revision] || v.Live && v.Admissible
			if v.Live && v.Admissible {
				current = append(current, v)
			}
		}
		witnesses := map[string]EqualityWitness{}
		for _, w := range facts.Witnesses {
			if w.EventID == eventID {
				witnesses[witnessKey(w)] = w
			}
		}
		// Full eligible bodies establish only payload equality. Causal equivalence is
		// derived below and never cached as an unconditional union.
		for i, a := range current {
			ap, err := record.EventPayload(a.Event)
			if err != nil {
				continue
			}
			for _, b := range current[i+1:] {
				if a.Event.Revision == b.Event.Revision {
					continue
				}
				bp, err := record.EventPayload(b.Event)
				if err != nil {
					continue
				}
				if bytes.Equal(ap, bp) {
					w := EqualityWitness{EventID: eventID, A: a.Event.Revision, B: b.Event.Revision, RecordA: a.RecordID, RecordB: b.RecordID, Owner: owner, SessionKey: session, Admissible: true}
					witnesses[witnessKey(w)] = w
				}
			}
			clear(ap)
		}
		parent := map[string]string{}
		var find func(string) string
		find = func(x string) string {
			if parent[x] == "" {
				parent[x] = x
			}
			if parent[x] != x {
				parent[x] = find(parent[x])
			}
			return parent[x]
		}
		union := func(a, b string) bool {
			a, b = find(a), find(b)
			if a == b {
				return false
			}
			if a > b {
				a, b = b, a
			}
			parent[b] = a
			return true
		}
		frontier := func(rev string) ([]string, bool) {
			p, ok := seen[rev]
			if !ok {
				return nil, false
			}
			set := map[string]bool{}
			for _, r := range p.Replaces {
				if _, known := seen[r]; !known {
					return nil, false
				}
				set[find(r)] = true
			}
			xs := []string{}
			for r := range set {
				xs = append(xs, r)
			}
			sort.Strings(xs)
			return xs, true
		}
		keys := []string{}
		for k := range witnesses {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		changed := true
		for changed {
			changed = false
			for _, k := range keys {
				w := witnesses[k]
				if !w.Admissible || !sources[w.A][w.RecordA] || !sources[w.B][w.RecordB] {
					continue
				}
				a, oka := frontier(w.A)
				b, okb := frontier(w.B)
				if oka && okb && sameStrings(a, b) && union(w.A, w.B) {
					changed = true
				}
			}
		}
		edges := map[string]map[string]bool{}
		suppressed := map[string]bool{}
		unknown := map[string]bool{}
		pending := false
		for rev, p := range seen {
			from := find(rev)
			if edges[from] == nil {
				edges[from] = map[string]bool{}
			}
			for _, r := range p.Replaces {
				to := find(r)
				edges[from][to] = true
				suppressed[to] = true
				if _, known := seen[r]; !known {
					unknown[to] = true
				}
			}
		}
		for _, p := range index {
			if p.EventID != eventID {
				continue
			}
			source, known := seen[p.From]
			if !known || source.RecordID != p.RecordID && !sources[p.From][p.RecordID] {
				pending = true
				continue
			}
			if !containsRevision(source.Replaces, p.To) {
				return nil, fmt.Errorf("event: causal index differs from admitted predecessor set")
			}
		}
		// Cycles hold the event deterministically; no hash/arrival tie-break resolves it.
		color := map[string]int{}
		var cycle func(string) bool
		cycle = func(x string) bool {
			if color[x] == 1 {
				return true
			}
			if color[x] == 2 {
				return false
			}
			color[x] = 1
			for p := range edges[x] {
				if cycle(p) {
					return true
				}
			}
			color[x] = 2
			return false
		}
		for rev := range seen {
			if cycle(find(rev)) {
				pending = true
			}
		}
		choice := EventChoice{Pending: pending, Facts: EventFacts{V: record.Version, Presence: allSeen}}
		for _, k := range keys {
			choice.Facts.Witnesses = append(choice.Facts.Witnesses, witnesses[k])
		}
		reachUnknown := func(start string) bool {
			visited := map[string]bool{}
			todo := []string{start}
			for len(todo) > 0 {
				x := todo[len(todo)-1]
				todo = todo[:len(todo)-1]
				if visited[x] {
					continue
				}
				visited[x] = true
				if unknown[x] {
					return true
				}
				for p := range edges[x] {
					todo = append(todo, p)
				}
			}
			return false
		}
		for rev, v := range body {
			if live[rev] && !suppressed[find(rev)] {
				choice.Heads = append(choice.Heads, v.Event)
				if reachUnknown(find(rev)) {
					choice.Pending = true
				}
			}
		}
		sort.Slice(choice.Heads, func(i, j int) bool { return choice.Heads[i].Revision < choice.Heads[j].Revision })
		if len(choice.Heads) > 8 {
			choice.Pending = true
		}
		if len(choice.Heads) > 1 {
			first, firstErr := record.EventPayload(choice.Heads[0])
			for _, e := range choice.Heads[1:] {
				payload, payloadErr := record.EventPayload(e)
				if firstErr != nil || payloadErr != nil || !bytes.Equal(first, payload) {
					choice.Conflict = true
				}
				clear(payload)
			}
			clear(first)
		}
		tags := map[string]bool{}
		for _, p := range allSeen {
			for _, tag := range p.ObservedTaint {
				if tag != "taint-unknown" {
					tags[tag] = true
				}
			}
		}
		for tag := range tags {
			choice.ObservedTaint = append(choice.ObservedTaint, tag)
		}
		sort.Strings(choice.ObservedTaint)
		out[eventID] = choice
	}
	return out, nil
}
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func containsRevision(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// EventErasureRecords is the conservative source-occurrence closure. Persist
// the owner/session/event tomb before any recapture seal and erase every copy.
func EventErasureRecords(facts EventFacts, owner, session, eventID string) ([]string, error) {
	if facts.V != record.Version {
		return nil, fmt.Errorf("event: legacy revision facts refused")
	}
	set := map[string]bool{}
	for _, p := range facts.Presence {
		if p.Owner == owner && p.SessionKey == session && p.EventID == eventID {
			set[p.RecordID] = true
		}
	}
	out := []string{}
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

func observedTags(tags []string, admissible bool) []string {
	if !admissible {
		return nil
	}
	seen := map[string]bool{}
	for _, tag := range tags {
		if tag != "taint-unknown" {
			for _, allowed := range record.TaintValues {
				if tag == allowed {
					seen[tag] = true
				}
			}
		}
	}
	out := []string{}
	for tag := range seen {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}
